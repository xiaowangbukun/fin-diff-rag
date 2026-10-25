# SPDX-License-Identifier: Apache-2.0
"""0001 基线：把"当前模型 + 历史补列"一次性收口成可版本化的起点。

Revision ID: 0001_baseline
Revises: -
Create Date: 2026-10-25

这个基线刻意**不冻结成一份手写 DDL 快照**，而是复用应用自身的
create_all + ensure_schema：
  · 已有环境（先于 Alembic 上线）：表都在，create_all 是空操作，
    ensure_schema 只补缺列，执行后仅新增 alembic_version 一行——
    "给存量库打版本号"不需要停服重建；
  · 全新环境：等价于服务首次启动做的事，结果与 create_all 完全一致。
代价是：本文件会随 `app/models.py` 变化而语义漂移。因此约定——
**结构变更一律新增 revision 文件，不得修改本文件**；本文件只在"新装环境
的起点"这个意义上被使用一次。

未来若需要严格的"基线冻结"，做法是把本文件替换为一次性导出的显式 DDL
（`alembic revision --autogenerate` 在空库上生成），并保留旧基线副本。
"""
from alembic import op  # noqa: F401

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app import models  # noqa: F401  确保全部表注册进 metadata
    from app.db import Base, engine
    from app.migrate import ensure_schema

    Base.metadata.create_all(bind=engine)   # 幂等：已有表不重建
    ensure_schema()                          # 补历史缺列 + 审计只追加触发器


def downgrade() -> None:
    # 基线的"回滚"等于删库：审计日志（合规要求留存 ≥6 个月）、文档与切片、
    # 用户与权限全部丢失。不提供自动 downgrade 是**有意的安全设计**——
    # 回退请按 docs/BACKUP-RESTORE.md 用备份恢复到新实例，再切流量。
    raise RuntimeError(
        "0001_baseline 不支持 downgrade：回滚请用备份恢复到新实例（见 "
        "docs/BACKUP-RESTORE.md），不要在生产库上执行删表回滚。"
    )
