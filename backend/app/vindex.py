# SPDX-License-Identifier: Apache-2.0
"""pgvector 向量索引保障（P1-6）。

为什么需要它：pgvector 没索引时走全表精确扫描，切片量上万后延迟不可接受。
HNSW 相比 IVFFlat 的取舍——查询更快、不需要预聚类训练数据，代价是建索引更慢、
内存占用更高，且 pgvector 的 HNSW **不支持 CREATE INDEX CONCURRENTLY**
（建索引期间对 chunks 写锁表），所以只能低峰执行或行数不多时启动时建。

#21：SQLite 链路移除后本模块不再有方言早退分支——存储只有 PG 一条路。
"""
import sys

from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import HNSW_AUTO_BUILD_MAX

INDEX_NAME = "ix_chunks_embedding_hnsw"

# 与 config.HNSW_EF_SEARCH 解耦：DDL 常量独立于运行时参数，便于单测直接断言
_M = 16
_EF_CONSTRUCTION = 64


def _hnsw_ddl() -> str:
    """建索引语句（抽成函数供单测直接断言，无需真连 PG）。"""
    return (
        f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON chunks "
        f"USING hnsw (embedding vector_cosine_ops) "
        f"WITH (m={_M}, ef_construction={_EF_CONSTRUCTION})"
    )


def _warn(msg: str) -> None:
    print(f"[vindex] WARNING: {msg}", file=sys.stderr)


def _version_tuple(v: str) -> tuple:
    """'0.7.4' → (0, 7, 4)；解析失败返回空 tuple（按未知版本处理）。"""
    try:
        return tuple(int(p) for p in str(v).split(".")[:3])
    except Exception:
        return ()


def ensure_vector_index(db: Session) -> dict:
    """确保 PG 侧有可用的向量索引。

    返回 {"skipped": reason} 或 {"created": bool, "rows": n, "version": str}。
    任何失败都只告警不抛——索引缺失降级为慢，不该让服务起不来。
    """
    try:
        db.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        db.commit()
    except Exception as e:
        db.rollback()
        _warn(f"vector 扩展不可用（{type(e).__name__}），向量检索将退化为全表扫描；"
              f"生产环境请由 DBA 预装 pgvector")
        return {"skipped": "extension_unavailable"}

    version = ""
    try:
        version = str(db.execute(
            text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
        ).scalar() or "")
    except Exception:
        pass
    # <0.5.0 的 HNSW 带过滤条件时召回受限（无 iterative scan），仅告警不阻断
    vt = _version_tuple(version)
    if vt and vt < (0, 5, 0):
        _warn(f"pgvector {version} 低于 0.5.0，HNSW 带权限过滤时可能漏召回；"
              f"建议升级到 0.5+（iterative scan）或改两阶段检索")

    try:
        rows = int(db.execute(text("SELECT count(*) FROM chunks")).scalar() or 0)
    except Exception as e:
        _warn(f"统计 chunks 行数失败（{type(e).__name__}），跳过建索引")
        return {"skipped": "count_failed"}

    if rows > HNSW_AUTO_BUILD_MAX:
        _warn(f"chunks 有 {rows} 行（超过 HNSW_AUTO_BUILD_MAX={HNSW_AUTO_BUILD_MAX}），"
              f"不在启动时建索引；请在低峰执行：python run.py build-index")
        return {"skipped": "too_many_rows", "rows": rows, "version": version}

    created = False
    try:
        db.execute(text(_hnsw_ddl()))
        db.commit()
        created = True
    except Exception as e:
        db.rollback()
        _warn(f"建 HNSW 索引失败（{type(e).__name__}），向量检索退化为全表扫描")
    return {"created": created, "rows": rows, "version": version, "skipped": ""}
