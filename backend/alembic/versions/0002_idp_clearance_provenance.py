# SPDX-License-Identifier: AGPL-3.0-only
"""0002：IdP 密级同步溯源（authoritative 撤权所需）。

Revision ID: 0002_idp_clearance_provenance
Revises: 0001_baseline
Create Date: 2026-10-25

OIDC_CLAIM_SYNC_MODE=authoritative 要回答的问题是"这个人现在的密级里，
哪一截是 IdP 抬上去的"——没有溯源就只能二选一：要么永远不降（旧的
只升不降，IdP 侧离岗收权失效），要么无条件覆盖（把本地管理员授予的
更高密级一起抹掉）。两列把答案写下来：

  · idp_clearance_synced：上次 claim 同步写入的密级（0=从未同步）；
  · idp_clearance_base：同步前的本地基线（-1=未记录）。

旧库默认值让行为与升级前完全一致（union 模式根本不读这两列）。
"""
from alembic import op

revision = "0002_idp_clearance_provenance"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_clearance_synced INTEGER DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS idp_clearance_base INTEGER DEFAULT -1"
    )


def downgrade() -> None:
    # 溯源列可以安全删除：删掉只退回"只升不降"的旧行为，不丢任何权限事实。
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS idp_clearance_base")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS idp_clearance_synced")
