# SPDX-License-Identifier: AGPL-3.0-only
"""原件对象存储（MinIO / S3 兼容）：仅供人工审查与可选合规留存。

为什么默认关闭（ORIGINAL_STORE_ENABLED=false）
----------------------------------------------
现行口径是"解析完即删原文，库内只留切片文本"：泄露面最小。开启原件留存
等于在对象存储里再放一份与切片同等级的敏感数据——审查能对账，代价是
备份、权限、审计范围都要同步扩大。因此这是一个显式开关，而不是默认行为。

三条硬约束
----------
1. **键不可猜**：`originals/<doc_id>/v<version>/original.<ext>`，doc_id 是 UUID；
   桶只给本服务账号读写，不对外开匿名访问。
2. **可校验**：每次写入都把 sha256 放进对象元数据，台账（document_versions）
   也存一份；取回时重算比对，原件被替换/截断立刻检出，不把脏字节交给审查端。
3. **缺库不静默**：`minio` SDK 延迟导入；未开启时不影响启动，开启却缺库则
   在调用点抛明确错误（由安全姿态自检在启动期提前报 FAIL）。
"""
import hashlib
import io

from . import config as cfg

try:  # pragma: no cover - 仅用于类型检查/文档提示，运行期走延迟导入
    from minio import Minio  # noqa: F401
except Exception:  # 未安装时保持模块可导入（未开启原件留存时不需要它）
    Minio = None  # type: ignore[assignment]


class OriginalStoreError(RuntimeError):
    """对象存储不可用/写入失败。调用方决定是拒绝入库还是宽容放行。"""


class OriginalIntegrityError(RuntimeError):
    """取回的原件与台账哈希不一致：原件被替换或损坏，禁止下发。"""


def key_for(doc_id: str, version: int, ext: str = "") -> str:
    """对象键：originals/<doc_id>/v<version>/original.<ext>。

    只由服务端生成的 doc_id/版本号/白名单后缀拼出，不含用户提供的原始文件名
    ——原文件名可能带路径穿越、超长、非 ASCII，直接拼键会把对象存储变成
    第二个"文件名注入点"（键空间被占、审计里出现伪造路径）。
    """
    safe_ext = "".join(ch for ch in (ext or "") if ch.isalnum()).lower()[:8] or "bin"
    prefix = (cfg.ORIGINAL_STORE_PREFIX or "originals").strip("/")
    return f"{prefix}/{doc_id}/v{int(version)}/original.{safe_ext}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


class S3OriginalStore:
    """MinIO / S3 兼容后端。构造一次复用连接池；配置在实例化时固化。"""

    def __init__(self) -> None:
        if not cfg.ORIGINAL_STORE_ENDPOINT:
            raise OriginalStoreError("ORIGINAL_STORE_ENDPOINT 未配置")
        if not cfg.ORIGINAL_STORE_ACCESS_KEY or not cfg.ORIGINAL_STORE_SECRET_KEY:
            raise OriginalStoreError("原件存储凭据未配置（ACCESS_KEY / SECRET_KEY）")
        try:
            from minio import Minio as _Minio
        except Exception as e:  # pragma: no cover - 依赖缺失路径
            raise OriginalStoreError(
                "原件留存已开启，但缺少 minio 客户端（pip install minio）") from e
        self.bucket = cfg.ORIGINAL_STORE_BUCKET
        self._cli = _Minio(
            cfg.ORIGINAL_STORE_ENDPOINT,
            access_key=cfg.ORIGINAL_STORE_ACCESS_KEY,
            secret_key=cfg.ORIGINAL_STORE_SECRET_KEY,
            secure=bool(cfg.ORIGINAL_STORE_SECURE),
            region=cfg.ORIGINAL_STORE_REGION or "us-east-1",
        )
        self._bucket_ready = False

    # ---------- 桶 ----------
    def ensure_bucket(self) -> None:
        """桶不存在则创建；存在则直接复用。不设匿名策略（默认私有）。"""
        if self._bucket_ready:
            return
        try:
            if not self._cli.bucket_exists(self.bucket):
                self._cli.make_bucket(self.bucket)
        except Exception as e:
            raise OriginalStoreError(f"对象存储不可用（桶 {self.bucket}）：{e}") from e
        self._bucket_ready = True

    # ---------- 写 ----------
    def put(self, key: str, data: bytes, digest: str = "") -> dict:
        self.ensure_bucket()
        body = data or b""
        digest = digest or sha256_bytes(body)
        try:
            self._cli.put_object(
                self.bucket, key, io.BytesIO(body), len(body),
                content_type="application/octet-stream",
                # 元数据自带指纹：即使台账被改，对象侧仍留有写入时的哈希
                metadata={"sha256": digest, "upload-sha256": digest},
            )
            st = self._cli.stat_object(self.bucket, key)
        except Exception as e:
            raise OriginalStoreError(f"原件写入失败（{key}）：{e}") from e
        return {
            "key": key,
            "size": int(getattr(st, "size", len(body)) or len(body)),
            "etag": str(getattr(st, "etag", "") or ""),
            "sha256": digest,
        }

    # ---------- 读 ----------
    def get_bytes(self, key: str, max_bytes: int | None = None) -> bytes:
        self.ensure_bucket()
        try:
            resp = self._cli.get_object(self.bucket, key)
            try:
                # 多读 1 字节：正好超限时也能判定"超过上限"，而不是读完才发现
                limit = int(max_bytes) if max_bytes else None
                data = resp.read(limit + 1) if limit else resp.read()
            finally:
                resp.close()
                resp.release_conn()
        except Exception as e:
            raise OriginalStoreError(f"原件读取失败（{key}）：{e}") from e
        if max_bytes and len(data) > max_bytes:
            raise OriginalStoreError(
                f"原件超过单次取回上限 {max_bytes // (1024 * 1024)}MB（{key}）")
        return data

    def stat(self, key: str) -> dict:
        self.ensure_bucket()
        try:
            st = self._cli.stat_object(self.bucket, key)
        except Exception as e:
            raise OriginalStoreError(f"原件元数据读取失败（{key}）：{e}") from e
        meta = {k.lower(): v for k, v in (getattr(st, "metadata", None) or {}).items()}
        return {
            "key": key,
            "size": int(getattr(st, "size", 0) or 0),
            "etag": str(getattr(st, "etag", "") or ""),
            "sha256": meta.get("sha256", "") or meta.get("x-amz-meta-sha256", ""),
        }

    def remove(self, key: str) -> None:
        self.ensure_bucket()
        try:
            self._cli.remove_object(self.bucket, key)
        except Exception as e:
            raise OriginalStoreError(f"原件删除失败（{key}）：{e}") from e


_store: S3OriginalStore | None = None


def get_store() -> S3OriginalStore | None:
    """按配置取后端实例；未开启返回 None（调用方据此走"不留原件"的老路径）。

    每次调用都读 cfg.ORIGINAL_STORE_ENABLED：开关是运行期可测的配置，
    不能只在导入期判断一次（测试与运维脚本都会 monkeypatch 它）。
    """
    global _store
    if not cfg.ORIGINAL_STORE_ENABLED:
        return None
    if _store is None:
        _store = S3OriginalStore()
    return _store


def reset_store() -> None:
    """丢弃缓存实例（测试改配置后调用；生产无调用点）。"""
    global _store
    _store = None
