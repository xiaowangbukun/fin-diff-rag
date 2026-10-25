# SPDX-License-Identifier: Apache-2.0
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

变更约定（P0-6，写在这里是为了让 `alembic revision` 生成的每个新脚本
自带模板，不依赖人的记忆）：
  · upgrade() 必须幂等：老库可能已是目标结构（create_all/ensure_schema 先
    跑过），DDL 一律带 IF NOT EXISTS / IF EXISTS；
  · 新增非空列必须带 server_default，否则大表加列会锁表且老行违反非空；
  · downgrade() 只做"可安全回退"的变更。删列/删表的回滚会一并删掉审计证据
    与业务数据，这类变更请显式 raise，要求走备份恢复（见 docs/BACKUP-RESTORE.md）；
  · 一条 revision 只做一件事，命名用动词短语（add_xxx / widen_xxx）。
"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
