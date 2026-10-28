# SPDX-License-Identifier: AGPL-3.0-only
"""0003：原件留存台账（ORIGINAL_STORE_ENABLED）。

Revision ID: 0003_original_store_ledger
Revises: 0002_idp_clearance_provenance
Create Date: 2026-10-25

原件开启后，原始字节放对象存储（MinIO/S3），库内只留台账：
对象键、sha256、体积、写入时间。四列空值即"该版本没有原件"，与开关
关闭时的语义严格一致（所以旧库升级不需要回填）。

downgrade 仅删列，不动对象存储里的对象——迁移不该替运维删备份数据，
清理动作由运维在确认后单独执行。
"""
from alembic import op

revision = "0003_original_store_ledger"
down_revision = "0002_idp_clearance_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE document_versions "
        "ADD COLUMN IF NOT EXISTS original_key VARCHAR(512) DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE document_versions "
        "ADD COLUMN IF NOT EXISTS original_sha256 VARCHAR(64) DEFAULT ''"
    )
    op.execute(
        "ALTER TABLE document_versions "
        "ADD COLUMN IF NOT EXISTS original_size INTEGER DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE document_versions "
        "ADD COLUMN IF NOT EXISTS original_stored_at TIMESTAMP"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE document_versions DROP COLUMN IF EXISTS original_stored_at")
    op.execute("ALTER TABLE document_versions DROP COLUMN IF EXISTS original_size")
    op.execute("ALTER TABLE document_versions DROP COLUMN IF EXISTS original_sha256")
    op.execute("ALTER TABLE document_versions DROP COLUMN IF EXISTS original_key")
