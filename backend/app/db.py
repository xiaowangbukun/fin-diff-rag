# SPDX-License-Identifier: AGPL-3.0-only
"""数据库引擎与会话。#21 起只支持 PostgreSQL + pgvector（SQLite 链路已移除）。"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import DATABASE_URL, require_database_url  # noqa: F401  启动期校验入口

# DATABASE_URL 缺失时用一个连不上的占位串建引擎：create_engine 本身不连接，
# 不会因为占位串失败——真正的拒绝在启动期 require_database_url()。
# 这样 import app.main（CI import 冒烟）在未配置环境下依然成功。
_EFFECTIVE_URL = DATABASE_URL or "postgresql+psycopg://finrag:__unset__@127.0.0.1:1/finrag"

engine = create_engine(_EFFECTIVE_URL, pool_pre_ping=True, future=True)


class Base(DeclarativeBase):
    pass


SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """建表 + 扩展。重复调用安全。"""
    from . import models  # noqa: F401  确保模型注册

    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        # 关键词检索用的中文/英文通用全文索引函数（PG 侧不做分词，靠 ILIKE 兜底）
    Base.metadata.create_all(engine)
    _ensure_indexes()


def _ensure_indexes():
    """pgvector 需要显式建近似索引。"""
    with engine.begin() as conn:
        try:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_chunks_embedding "
                    "ON chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists=100)"
                )
            )
        except Exception:
            # 数据量不足时 ivfflat 建索引会失败，退化为暴力扫描，功能不受影响
            pass
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_chunks_doc ON chunks(doc_id)")
        )
        conn.execute(
            text("CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit_logs(ts)")
        )
