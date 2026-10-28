# SPDX-License-Identifier: AGPL-3.0-only
"""migrate.py —— SCHEMA_PATCHES 的旧库升级与幂等（pytest 侧此前零覆盖）。

#21 后存储只剩 PG，启动期补列走的全是 PG 分支。此前这条路径只有 smoke
脚本验过（smoke.py:901「先删列模拟旧库，ensure_schema 应幂等补回」），
pytest 侧一个用例都没有——意味着 CI 可以在"旧库升级必崩"的状态下全绿。

事故形态：
  · 补列 SQL 写错（PG 语法/表名）→ 老库启动即崩，服务起不来；
  · 补列不幂等 → 每次启动重复执行 ALTER，或第二次跑报"列已存在"；
  · 依赖新列的索引（ix_audit_row_hash）建不出来 → 审计哈希链校验退化成
    全表扫描，链校验慢到没人跑，等于防篡改形同虚设。
"""
import pytest
from sqlalchemy import inspect, text

from app.db import engine
from app.migrate import SCHEMA_PATCHES, ensure_schema


def _columns(conn, table):
    return {c["name"] for c in inspect(conn).get_columns(table)}


# ------------------------------------------------------------------ 干净库


def test_clean_schema_needs_no_patch(db):
    """防：干净库每次启动都报一堆"补列"，升级日志里全是噪音，掩盖真问题。"""
    applied = ensure_schema()
    assert applied == [], f"全新库不应有任何迁移项，实际：{applied}"


def test_audit_row_hash_index_exists_on_clean_schema(db):
    """防：哈希链校验索引缺失——链校验退化成全表扫描，防篡改形同虚设。"""
    with engine.begin() as conn:
        names = {i["name"] for i in inspect(conn).get_indexes("audit_logs")}
    assert "ix_audit_row_hash" in names


# ------------------------------------------------------------------ 旧库升级


@pytest.mark.parametrize("table,column", [
    ("audit_logs", "prev_hash"),
    ("audit_logs", "row_hash"),
    ("audit_logs", "seq"),
    ("documents", "parse_quality"),
    ("documents", "inject_risk"),
    ("documents", "version"),
    ("users", "risk_score"),
    ("users", "last_risk_ts"),
    ("users", "must_change_password"),
    ("users", "token_version"),
    ("users", "totp_secret"),
    ("users", "totp_confirmed_at"),
    ("users", "totp_last_step"),
    ("users", "recovery_codes"),
    ("users", "oidc_subject"),
    ("approval_requests", "payload"),
    ("document_versions", "original_key"),
    ("document_versions", "original_sha256"),
    ("document_versions", "original_size"),
    ("document_versions", "original_stored_at"),
])
def test_missing_column_is_backfilled(db, table, column):
    """防：老库升级时补列失败 → 启动崩溃或字段永久缺失（审计链直接断）。"""
    with engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
        assert column not in _columns(conn, table)

    applied = ensure_schema()

    assert f"{table}.{column}" in applied, "缺失列必须被补回"
    with engine.begin() as conn:
        assert column in _columns(conn, table)


def test_patch_is_idempotent(db):
    """防：补列不幂等——第二次启动重复 ALTER，或直接报"列已存在"起不来。"""
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DROP COLUMN prev_hash"))
        conn.execute(text("ALTER TABLE audit_logs DROP COLUMN row_hash"))

    first = ensure_schema()
    second = ensure_schema()

    assert first, "首次应当补齐缺失列"
    assert second == [], f"二次调用必须幂等，实际又补了：{second}"


def test_row_hash_index_is_rebuilt_after_backfill(db):
    """防：补列后索引没跟上——row_hash 列建了但索引没有，链校验依旧慢。"""
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DROP COLUMN row_hash"))
        conn.execute(text("DROP INDEX IF EXISTS ix_audit_row_hash"))

    ensure_schema()

    with engine.begin() as conn:
        names = {i["name"] for i in inspect(conn).get_indexes("audit_logs")}
    assert "ix_audit_row_hash" in names


# ------------------------------------------------------------------ DDL 口径


def test_pg_ddl_is_idempotent_by_construction():
    """防：PG DDL 丢掉 IF NOT EXISTS —— 老库升级第二次启动就撞「列已存在」。

    #21 后 SQLite 分支已移除，这套 DDL 是唯一执行路径，必须自带幂等。
    """
    for table, column, ddl in SCHEMA_PATCHES:
        assert ddl.startswith(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column}"), (
            f"{table}.{column} 的 DDL 口径不符：{ddl}")


def test_every_patch_column_exists_in_model():
    """防：白名单里登记了模型里不存在的列——DDL 能跑通但字段永远用不上。"""
    from app.models import (
        ApprovalRequest, AuditLog, Document, DocumentVersion, User,
    )

    models = {
        "audit_logs": AuditLog, "documents": Document, "users": User,
        "approval_requests": ApprovalRequest, "document_versions": DocumentVersion,
    }
    for table, column, _ddl in SCHEMA_PATCHES:
        assert column in models[table].__table__.columns, (
            f"{table}.{column} 不在模型定义里")
