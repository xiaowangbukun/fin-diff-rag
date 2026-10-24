# SPDX-License-Identifier: Apache-2.0
"""增量 schema 管理：create_all 之后的白名单补列。

SQLAlchemy 的 create_all 只建新表，不给已有表加列。本项目不用 Alembic
（单库、无多环境迁移史），改为显式白名单在启动时补齐：缺列才 ALTER，
重复调用安全。新表由 models.py 定义直接带默认值建出，走不到这里。

新增列必须在本文件登记（与 models.py 一一对应），否则旧库升级时报
unknown column。

#21：SQLite 降级链路移除后只保留 PG 一套 DDL（原双方言双列在这里收口成
单列，DDL 一律带 IF NOT EXISTS——PG 原生支持，重复执行安全）。
"""
from sqlalchemy import inspect, text

from .db import engine

# (表名, 列名, PG DDL)
SCHEMA_PATCHES: list[tuple[str, str, str]] = [
    # P0-2 审计哈希链
    ("audit_logs", "prev_hash",
     "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT DEFAULT ''"),
    ("audit_logs", "row_hash",
     "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS row_hash TEXT DEFAULT ''"),
    ("audit_logs", "seq",
     "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS seq INTEGER DEFAULT 0"),
    # P1 PDF 解析质量标记（documents.parse_quality，无索引依赖）
    ("documents", "parse_quality",
     "ALTER TABLE documents ADD COLUMN IF NOT EXISTS parse_quality TEXT DEFAULT 'ok'"),
    # P1-4 提示注入风险标记（documents.inject_risk，无索引依赖）
    ("documents", "inject_risk",
     "ALTER TABLE documents ADD COLUMN IF NOT EXISTS inject_risk INTEGER DEFAULT 0"),
    # P1-7 用户风险分（用户长周期异常访问模式，无索引依赖）
    ("users", "risk_score",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0"),
    ("users", "last_risk_ts",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_risk_ts TIMESTAMP"),
    # P2-10 文档版本号（内容每次变更 +1，无索引依赖）
    ("documents", "version",
     "ALTER TABLE documents ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1"),
    # 上线闭环：access-control 变更审批（acl / acl_grant 的结构化载荷）。
    # 归属部门 UUID / 授权对象塞不进 from_value/to_value 的 32 字符，
    # 截断后审批通过也无法还原，必须独立存。
    ("approval_requests", "payload",
     "ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS payload TEXT DEFAULT ''"),
    # 闭环项 3：首次登录强制改密 + 会话代次（旧库升级必须补，否则 500）。
    # must_change_password 对既有账号默认 false：演示种子账号不被锁在改密页；
    # 只有管理员新建/重置的账号才置 true（见 routers/admin.py）。
    ("users", "must_change_password",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false"),
    ("users", "token_version",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0"),
    # 闭环项 3 · S3：TOTP 第二因子 + OIDC subject（旧库升级必须补，否则 500）
    ("users", "totp_secret",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''"),
    ("users", "totp_confirmed_at",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_confirmed_at TIMESTAMP"),
    ("users", "totp_last_step",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step INTEGER DEFAULT 0"),
    ("users", "recovery_codes",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_codes TEXT DEFAULT ''"),
    ("users", "oidc_subject",
     "ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject VARCHAR(255) DEFAULT ''"),
]

# P2-10 版本唯一约束的收口：历史库（无约束时期写入）可能已有同
# (doc_id, version) 多行，直接建唯一索引会失败。策略：每个组合保留
# **最早**的一条（created_at 最早，同时刻按 id 字典序取定，保证结果
# 确定、可复现），删掉其余，再建唯一索引。窗口函数 PostgreSQL 9.6+
# 支持；派生表带别名（PG 强制要求）。
_DEDUP_VERSIONS_SQL = """
DELETE FROM document_versions
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
            PARTITION BY doc_id, version ORDER BY created_at, id
        ) AS rn
        FROM document_versions
    ) AS ranked
    WHERE rn = 1
)
"""

_UQ_VERSIONS_INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_document_versions "
    "ON document_versions(doc_id, version)"
)


def ensure_schema() -> list[str]:
    """补齐白名单列，返回本次实际执行的迁移项（空 = 无需迁移）。"""
    applied: list[str] = []
    with engine.begin() as conn:
        insp = inspect(conn)
        tables = set(insp.get_table_names())
        for table, column, ddl in SCHEMA_PATCHES:
            if table not in tables:
                continue  # 表尚未创建：create_all 会按模型定义带默认值建出
            cols = {c["name"] for c in insp.get_columns(table)}
            if column in cols:
                continue
            conn.execute(text(ddl))
            applied.append(f"{table}.{column}")
        # 列宽收紧后的放宽：审批展示列原为 VARCHAR(32)，而 acl_grant 的
        # "user:<36 位 UUID>" 有 41 字符 —— 旧库会在写入时 500
        # （StringDataRightTruncation）。这里只放宽、不收紧，重复执行安全。
        if "approval_requests" in tables:
            insp = inspect(conn)
            cols = {c["name"]: c for c in insp.get_columns("approval_requests")}
            for col in ("from_value", "to_value"):
                c = cols.get(col)
                if c is not None and (getattr(c["type"], "length", None) or 0) < 160:
                    conn.execute(text(
                        f"ALTER TABLE approval_requests "
                        f"ALTER COLUMN {col} TYPE VARCHAR(160)"))
                    applied.append(f"approval_requests.{col}:widen")
        # OIDC subject 唯一性（部分索引：空串=未绑定，不参与唯一约束）。
        # 干净库由 models.py 的 __table_args__ 带出；旧库在此补建。
        if "users" in tables:
            insp = inspect(conn)
            if any(c["name"] == "oidc_subject" for c in insp.get_columns("users")):
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_oidc_subject "
                    "ON users(oidc_subject) WHERE oidc_subject <> ''"
                ))
        # 依赖新列的索引必须放在补列之后（旧库升级路径上列还不存在，
        # 提前建会报 no such column；干净库由 create_all 按模型定义带出）
        if "audit_logs" in tables:
            insp = inspect(conn)  # 重新 inspection，避开补列后的缓存
            cols = {c["name"] for c in insp.get_columns("audit_logs")}
            if "row_hash" in cols:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_audit_row_hash ON audit_logs(row_hash)"
                ))
        # P2-10 版本唯一约束：干净库由 models.py 的 UniqueConstraint 带出
        # （已存在则整段跳过）；旧库无索引时才去重 + 建索引。
        if "document_versions" in tables:
            insp = inspect(conn)  # 重新 inspection，避开上一步的缓存
            # 判定口径是「语义」而非索引名：SQLite 的 get_indexes 默认排除
            # 约束 autoindex（sqlite_autoindex_* 前缀），干净库里
            # UniqueConstraint 建出的索引名字对不上 uq_document_versions，
            # 按名匹配会把干净库误判成缺索引——每次 ensure_schema 都重复
            # 建一个同名索引（IF NOT EXISTS 按名去重，挡不住这个），还把
            # 迁移报告误报成"补了约束"。include_auto_indexes=True 后按
            # 「唯一 且 列集合 == (doc_id, version)」判定，PG/SQLite 同口径
            # （PG 的约束索引本就按名可见，不受默认过滤影响）。
            # DDL 的 IF NOT EXISTS 保留：兜 PG 路径与并发时序。
            has_uq = any(
                i.get("unique")
                and set(i.get("column_names") or ()) == {"doc_id", "version"}
                for i in insp.get_indexes("document_versions",
                                          include_auto_indexes=True)
            )
            if not has_uq:
                conn.execute(text(_DEDUP_VERSIONS_SQL))
                conn.execute(text(_UQ_VERSIONS_INDEX_SQL))
                applied.append("document_versions.uq(doc_id,version)")
    return applied
