# SPDX-License-Identifier: Apache-2.0
"""Embedding：OpenAI 兼容接口（#21 后唯一通道）。

本地哈希向量通道已随 SQLite 降级链路一并移除——它无语义维度，金融检索拿它
当依据等于输出"看似正常、实则无依据"的答案，比明确失败更危险。现在无
EMBED_API_KEY 即拒绝启动（方案 B，见 require_embedding_key）；配了 Key 但
远端不可用时明确抛 503，绝不再静默降级写垃圾向量。离线测试/回归基线由
测试侧注入替身 embedder（见 tests/conftest.py 的 fake embedder）。
"""
import re
import sys

import httpx
from sqlalchemy import text

from .config import (
    EMBED_API_KEY, EMBED_BASE_URL, EMBED_DIM, EMBED_MODEL,
    EMBED_REQUIRE_API_KEY, HTTP_TIMEOUT,
)
from .errors import ServiceUnavailable, dependency_timeout

_LABEL = "向量嵌入"


class Embedder:
    def __init__(self):
        # api_mode 保留给阈值切换消费方（retrieve.is_reliable / intent 锚句）：
        # 未配 Key 时它们是 False，走关键词证据为准的保守口径。
        self.api_mode = bool(EMBED_API_KEY)
        self.mode = "api" if self.api_mode else "unconfigured"
        self.dim = EMBED_DIM
        self._remote_dim: int | None = None

    def _fit(self, vec: list[float], dim: int) -> list[float]:
        if len(vec) == dim:
            return vec
        if len(vec) > dim:
            return vec[:dim]
        return vec + [0.0] * (dim - len(vec))

    def _remote(self, texts: list[str]) -> list[list[float]] | None:
        url = EMBED_BASE_URL.rstrip("/") + "/embeddings"
        headers = {
            "Authorization": f"Bearer {EMBED_API_KEY}",
            "Content-Type": "application/json",
        }
        try:
            r = httpx.post(
                url, headers=headers,
                json={"model": EMBED_MODEL, "input": texts},
                timeout=HTTP_TIMEOUT,
            )
            r.raise_for_status()
            data = r.json().get("data") or []
            if len(data) != len(texts):
                return None
            vecs = [d.get("embedding") or [] for d in data]
            if any(not v for v in vecs):
                return None
            if self._remote_dim is None:
                self._remote_dim = len(vecs[0])
            return [self._fit(v, self.dim) for v in vecs]
        except httpx.TimeoutException as e:
            # 配了远端却超时：不静默降级。降级会把无语义的垃圾向量写进库，
            # 之后每次检索都拿它当依据——用户看到的是"看似正常、实则无依据"
            # 的答案，比明确失败更危险。明确抛 503（带 Retry-After）退避重试。
            raise dependency_timeout("embedding", _LABEL, HTTP_TIMEOUT) from e
        except Exception as e:
            # #21 前这里返回 None 让调用方降级到本地哈希向量；本地通道已移除，
            # 不可用就是不可用——统一 503，重试可能好，静默写垃圾向量不会好。
            raise ServiceUnavailable(
                f"{_LABEL}服务不可用（{type(e).__name__}），请稍后重试",
                dependency="embedding",
            ) from e

    def embed(self, texts: list[str]) -> list[list[float]]:
        texts = [t if t.strip() else " " for t in texts]
        got = self._remote(texts)
        if got is None:
            raise ServiceUnavailable(
                f"{_LABEL}服务返回了无法解析的结果，请稍后重试", dependency="embedding"
            )
        return got

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


embedder = Embedder()


# ---------------------------------------------------------------------------
# 启动期就绪校验（方案 B + 维度一致性）
# ---------------------------------------------------------------------------

_COLUMN_TYPE_RE = re.compile(r"vector\((\d+)\)")


def require_embedding_key() -> None:
    """无 EMBED_API_KEY 时的启动决策（方案 B：默认拒绝，且是唯一路径）。

    #21 移除了本地哈希向量通道，无 Key 即无可用向量通道。仅离线测试/回归
    基线可设 EMBED_REQUIRE_API_KEY=false 显式放行——放行后由测试侧注入
    替身 embedder（tests/conftest.py），不代表生产可无 Key 运行。

    刻意不做导入期校验：import app.main 不该因缺配置而失败
    （见 CI 的 import 冒烟步骤注释）。
    """
    if not EMBED_API_KEY and EMBED_REQUIRE_API_KEY:
        raise RuntimeError(
            "拒绝启动：未配置 EMBED_API_KEY。自 #21 起本地哈希向量通道已移除"
            "（无语义维度，不能作为生产检索依据），请注入真实的 embedding "
            "服务密钥；仅离线测试可设 EMBED_REQUIRE_API_KEY=false 显式放行。"
        )


def _column_vector_dim(db) -> int | None:
    """读 PG 侧 chunks.embedding 列的实际维度；列不存在返回 None。

    format_type 对 pgvector 列返回 'vector(1024)' 这类字面量，比解析
    atttypmod 原值（pgvector 自有编码）稳。
    """
    row = db.execute(text(
        # PG 签名是 format_type(oid, integer)——即 (atttypid, atttypmod)。
        # 顺序写反会 UndefinedFunction，被下面的 except 吞成"校验跳过"，
        # 维度闸从此空转（曾发生，回归测试见 test_dimension_check_against_real_pg）。
        "SELECT format_type(a.atttypid, a.atttypmod) "
        "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
        "WHERE c.relname = 'chunks' AND a.attname = 'embedding' "
        "AND a.attnum > 0 AND NOT a.attisdropped"
    )).scalar()
    if not row:
        return None
    m = _COLUMN_TYPE_RE.search(str(row))
    return int(m.group(1)) if m else None


def check_dimension_consistency(db) -> None:
    """启动期维度一致性校验（唯一存储为 PG，故不再有方言早退）。

    改了 EMBED_DIM 却不重建表，会在首次写入时撞 pgvector dimension
    mismatch——那时报错点离配置现场已经很远，极难诊断。启动期对照
    "当前配置的维度"与"库内列的实际维度"，不一致直接拒绝启动并给出改法。

    库内还没有该列（全新库）时跳过：create_all 随后按当前维度建表，天然一致。
    introspection 本身失败只告警不拦启动——查都不让查是可用性灾难，
    而维度确定不符才是正确性灾难，两者要分开。
    """
    try:
        col_dim = _column_vector_dim(db)
    except Exception as e:  # noqa: BLE001   introspection 失败降级为告警
        print(f"[embed] WARNING: 向量列维度校验跳过（{e}）", file=sys.stderr)
        return
    if col_dim is None or col_dim == embedder.dim:
        return
    raise RuntimeError(
        f"拒绝启动：chunks.embedding 列维度为 {col_dim}，当前配置的 EMBED_DIM "
        f"为 {embedder.dim}。同一库不能混用两种维度——请恢复原 EMBED_DIM 配置，"
        f"或备份后清空 chunks 表按当前维度重建。"
    )
