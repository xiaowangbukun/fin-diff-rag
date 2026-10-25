# SPDX-License-Identifier: Apache-2.0
"""Alembic 环境：连接串、模型元数据全部取自应用代码。

为什么不用 alembic.ini 里的 sqlalchemy.url：
  · 两份配置必然分叉（有人改了 .env 忘了改 ini，迁移打到旧库）；
  · 应用侧连接串可能来自密钥托管（SECRETS_PROVIDER），迁移必须走同一入口
    才能复用同一套取值逻辑。
这里直接复用 `app.db.engine`（含连接池与 pgvector 扩展所在的默认
search_path），迁移与应用看到的是**同一个库、同一套可见性**。
"""
import sys
from pathlib import Path

from alembic import context

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import models  # noqa: E402,F401  注册全部表到 Base.metadata
from app.config import DATABASE_URL  # noqa: E402
from app.db import Base, engine  # noqa: E402

config = context.config
# `%` 在 ini 里是转义符，密码含 % 时必须双写
if DATABASE_URL:
    config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """离线模式：只生成 SQL（`alembic upgrade head --sql` 交给 DBA 复核）。"""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
