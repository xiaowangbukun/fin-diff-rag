# SPDX-License-Identifier: AGPL-3.0-only
"""migrate.py —— document_versions 唯一约束的旧库升级路径（B3 验收）。

覆盖三层：
  1. **旧库升级**：无唯一索引的历史库（含重复 (doc_id, version) 行）跑
     ensure_schema → 去重保留最早行 + 建唯一索引 + 二次调用幂等；
  2. **迁移后防线**：唯一索引建成后，重复插入被 IntegrityError 拦截；
  3. **PG 语法形状**：去重 SQL 的派生表别名 / 窗口函数 / 排序键是
     PostgreSQL 合法性的充要条件，用静态断言钉住，防止后人"简化"
     成 PG 不接受或结果不确定的形状。

为什么要去重保留**最早**：版本号的意义是"一个版本号对应且仅对应一次
内容状态"。重试路径写重时，最早一行才是首次落库的真实快照；按
(created_at, id) 排序保证同刻多行也能确定性地取同一条，结果可复现。
"""
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.db import Base, engine
from app.migrate import (
    _DEDUP_VERSIONS_SQL,
    _UQ_VERSIONS_INDEX_SQL,
    ensure_schema,
)
from app.models import DocumentVersion

UQ_INDEX = "uq_document_versions"

# 旧库形态：无唯一约束的 document_versions（约束是 P2-10 之后才补的）。
# 逐列对齐 models.DocumentVersion，只差 UNIQUE(doc_id, version)。
# #21：created_at 用 TIMESTAMP——DATETIME 是 SQLite 方言，PG 不认。
_LEGACY_DDL = """
CREATE TABLE document_versions (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    doc_id VARCHAR(36) NOT NULL,
    version INTEGER DEFAULT 1,
    content_hash VARCHAR(64) DEFAULT '',
    chunk_count INTEGER DEFAULT 0,
    clearance INTEGER DEFAULT 1,
    created_by VARCHAR(64) DEFAULT '',
    created_at TIMESTAMP
)
"""


@pytest.fixture
def legacy_versions_table(db):
    """把当前库的 document_versions 换成旧库形态（无唯一约束）。

    db 夹具已 create_all 出带约束的新表；这里先按元数据 drop 掉，
    再用原始 DDL 建旧表。teardown 再 drop 一次，把 schema 控制权还给
    后续用例的 drop_all/create_all。
    """
    Base.metadata.drop_all(engine, tables=[DocumentVersion.__table__])
    with engine.begin() as conn:
        conn.execute(text(_LEGACY_DDL))
    try:
        yield
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS document_versions"))


def _insert_version(conn, *, id, doc_id, version, created_at):
    conn.execute(
        text(
            "INSERT INTO document_versions "
            "(id, doc_id, version, content_hash, chunk_count, clearance, "
            " created_by, created_at) VALUES "
            "(:i, :d, :v, '', 0, 1, '', :t)"
        ),
        {"i": id, "d": doc_id, "v": version, "t": created_at},
    )


def _rows(conn):
    return conn.execute(
        text("SELECT id, doc_id, version, created_at FROM document_versions "
             "ORDER BY doc_id, version")
    ).all()


def _index_names(conn):
    return {i["name"] for i in inspect(conn).get_indexes("document_versions")}


# ------------------------------------------------------------------ 旧库升级


class TestLegacyUpgrade:
    """旧库（重复行 + 无索引）→ 去重保最早 + 建索引 + 幂等。"""

    def test_dedup_keeps_earliest_and_builds_unique_index(
            self, legacy_versions_table):
        from datetime import datetime

        with engine.begin() as conn:
            # 同 (doc A, v1) 三行：保留 created_at 最早的
            _insert_version(conn, id="zzz-late", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 10, 0))
            _insert_version(conn, id="aaa-early", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 9, 0))
            _insert_version(conn, id="mmm-mid", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 11, 0))
            # 不同版本号不受影响
            _insert_version(conn, id="bbb-v2", doc_id="A", version=2,
                            created_at=datetime(2026, 3, 1, 9, 30))
            # 同刻两行：按 id 字典序取定（确定性）
            _insert_version(conn, id="b1-tie", doc_id="B", version=1,
                            created_at=datetime(2026, 3, 2, 12, 0))
            _insert_version(conn, id="b0-tie", doc_id="B", version=1,
                            created_at=datetime(2026, 3, 2, 12, 0))

        applied = ensure_schema()
        assert "document_versions.uq(doc_id,version)" in applied

        with engine.begin() as conn:
            kept = {(r[0], r[1], r[2]) for r in _rows(conn)}
            assert kept == {
                ("aaa-early", "A", 1),   # 最早 created_at
                ("bbb-v2", "A", 2),      # 版本号不同，原样保留
                ("b0-tie", "B", 1),      # 同刻取 id 字典序最小
            }
            assert UQ_INDEX in _index_names(conn)

    def test_second_run_is_idempotent(self, legacy_versions_table):
        from datetime import datetime

        with engine.begin() as conn:
            _insert_version(conn, id="dup-1", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 9, 0))
            _insert_version(conn, id="dup-2", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 10, 0))
        first = ensure_schema()
        second = ensure_schema()
        assert "document_versions.uq(doc_id,version)" in first
        assert second == []  # 索引已存在：整段跳过，不重复去重

    def test_unique_index_blocks_duplicate_after_migration(
            self, legacy_versions_table):
        from datetime import datetime

        with engine.begin() as conn:
            _insert_version(conn, id="keep-me", doc_id="A", version=1,
                            created_at=datetime(2026, 3, 1, 9, 0))
        ensure_schema()
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                _insert_version(conn, id="clash", doc_id="A", version=1,
                                created_at=datetime(2026, 3, 1, 10, 0))


# ------------------------------------------------------------------ 干净库


def test_clean_db_ensure_schema_skips_versions_unique_index(db):
    """干净库（models 的 UniqueConstraint 已带出约束）不应再报迁移项。

    回归背景：修复前 SQLite 下 get_indexes 默认排除约束 autoindex
    （sqlite_autoindex_*），干净库被误判成缺索引 → 每次 ensure_schema
    都重复建一个同名唯一索引并误报 applied。migrate.py 已改为
    include_auto_indexes=True + 「unique 且列集合=={doc_id, version}」
    语义判定；本条同时钉住"索引集合不增长"，双重防回归。

    #21 起跑在 PG schema 隔离上（每用例独立 schema），旧叙述里"池化
    SQLite 连接跨用例状态残留导致偶发 before=[]"已无土壤；保留用例内
    重建表 + dispose 的口径：确保 ensure_schema 与两次快照都落在全新
    连接上，断言不依赖执行顺序。
    """
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS document_versions")
    DocumentVersion.__table__.create(engine, checkfirst=False)
    engine.dispose()  # 丢弃池化连接，排除跨用例连接级状态残留

    with engine.begin() as conn:
        seen = inspect(conn).get_indexes(
            "document_versions", include_auto_indexes=True)
        before = sorted(i["name"] for i in seen)
        # 钉住修复的核心判据：Inspector 必须能反射出唯一约束，
        # 否则 ensure_schema 的 has_uq 判定失去依据
        uq = [i for i in seen
              if i["unique"]
              and set(i["column_names"] or ()) == {"doc_id", "version"}]
        assert uq, "干净库应能反射出 (doc_id, version) 唯一约束"
    applied = ensure_schema()
    assert "document_versions.uq(doc_id,version)" not in applied
    with engine.begin() as conn:
        after = sorted(
            i["name"] for i in inspect(conn).get_indexes(
                "document_versions", include_auto_indexes=True))
    assert after == before  # 不新增任何索引（含同名重复索引）


# ------------------------------------------------------------------ PG 语法形状


class TestDedupSqlShape:
    """去重 SQL 的 PG 合法性靠形状保证，静态钉住防"简化"。"""

    def test_window_function_and_derived_table_alias(self):
        # PG 强制 FROM 子查询带别名；窗口函数 PG 9.6+ / SQLite 3.25+ 均支持
        assert "ROW_NUMBER() OVER (" in _DEDUP_VERSIONS_SQL
        assert ") AS ranked" in _DEDUP_VERSIONS_SQL
        assert "PARTITION BY doc_id, version" in _DEDUP_VERSIONS_SQL

    def test_deterministic_tiebreak(self):
        """同 created_at 多行必须按 id 字典序取定，否则去重结果不可复现。"""
        assert "ORDER BY created_at, id" in _DEDUP_VERSIONS_SQL

    def test_unique_index_is_if_not_exists(self):
        assert "IF NOT EXISTS" in _UQ_VERSIONS_INDEX_SQL
        assert UQ_INDEX in _UQ_VERSIONS_INDEX_SQL
