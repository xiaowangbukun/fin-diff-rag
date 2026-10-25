# SPDX-License-Identifier: AGPL-3.0-only
"""审计只追加 + 全量外送（P0-3）：把"证据"从"约定"变成"数据库拒绝 + 独立副本"。

两个缺口各自的补法：
  1. **应用从不改审计**只是代码约定，DBA 一条 UPDATE 就能抹掉证据 →
     PG 触发器拒绝 UPDATE/DELETE/TRUNCATE（演练用会话级破窗）；
  2. **锚点只证明尾行**：改中间行 + 重算其后哈希 + 保留正确尾哈希，锚点仍对
     得上 → 每批新增行（seq + row_hash + 摘要）外送到独立 sink，sink 侧可
     重建时间线；库里少一行/换一行，副本立刻对不上。
"""
import json
from datetime import datetime

import pytest
from sqlalchemy import text

from app import anchors, audit, config
from app.models import AuditLog


@pytest.fixture
def sink_file(tmp_path, monkeypatch):
    path = tmp_path / "worm" / "audit_stream.jsonl"
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", str(path))
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(config, "AUDIT_SHIP_ROWS", True)
    anchors.reset_state()
    yield path
    anchors.reset_state()


def _disabled_sink(monkeypatch):
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "")
    anchors.reset_state()


# ---------------------------------------------------------------- 行副本内容


def test_write_log_ships_row_copy(db, sink_file, user_factory):
    """同步路径（启动告警/背压回落）也要外送：这类行最不能在副本里缺。"""
    who = user_factory("alice")
    log = audit.write_log(db, user=who, action="search",
                          target_label="年报.pdf", ip="10.0.0.1",
                          query="敏感问句正文", decision="allow", sync=True)
    assert log.seq >= 1

    records = anchors.read_external()
    rows = [r for r in records if r.get("kind") == "audit_rows"]
    assert rows, "审计行必须外送"
    batch = rows[-1]
    assert batch["count"] == 1
    assert batch["sig_ok"] is True
    row = batch["rows"][0]
    assert row["seq"] == log.seq and row["row_hash"] == log.row_hash
    assert row["action"] == "search" and row["username"] == "alice"
    assert row["ip"] == "10.0.0.1"
    # 外送目标是日志基础设施，不是数据仓库：不含 query 正文
    assert "敏感问句正文" not in json.dumps(batch, ensure_ascii=False)
    assert "query" not in row


def test_ship_rows_keeps_anchor_stream_kind_separate(sink_file):
    anchors.emit("H" * 64, 5, force=True)
    anchors.ship_rows([{"seq": 5, "row_hash": "H" * 64, "prev_hash": "G" * 64,
                        "ts": datetime.utcnow().isoformat(), "action": "search",
                        "decision": "allow", "username": "bob",
                        "target_label": "x", "ip": "1.1.1.1"}])
    kinds = [r.get("kind") for r in anchors.read_external()]
    assert kinds == ["audit_anchor", "audit_rows"]

    status = anchors.check("H" * 64, 5)
    assert status["ok"] is True
    assert status["shipped_batches"] == 1


def test_ship_rows_disabled_by_flag(sink_file, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_SHIP_ROWS", False)
    assert anchors.ship_rows([{"seq": 1, "row_hash": "H"}]) is None
    assert anchors.read_external() == []


def test_ship_rows_truncates_oversized_fields(sink_file):
    """外送字段截断：避免恶意超长 target_label 把日志网关撑爆。"""
    rec = anchors.ship_rows([{
        "seq": 1, "row_hash": "H" * 64, "prev_hash": "",
        "ts": "2026-01-01T00:00:00", "action": "a" * 100,
        "decision": "x" * 40, "username": "u" * 200,
        "target_label": "t" * 500, "ip": "i" * 200,
    }])
    row = rec["rows"][0]
    assert len(row["action"]) == 32 and len(row["decision"]) == 8
    assert len(row["username"]) == 64 and len(row["target_label"]) == 128
    assert len(row["ip"]) == 64


def test_ship_rows_failure_never_breaks_audit(db, monkeypatch):
    """防：日志网关挂掉导致审计写不进去（合规底线不能被外部依赖拖垮）。"""
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "http://127.0.0.1:1/rows")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_TIMEOUT", 1)
    anchors.reset_state()

    log = audit.write_log(db, action="search", reason="sink down", sync=True)
    assert log.seq >= 1


def test_async_batch_ships_all_rows(db, sink_file, monkeypatch):
    """异步批：一批的行要一次性送出去（不是逐行一次 HTTP）。"""
    audit.flush_audit()
    before = sum(int(r.get("count") or 0) for r in anchors.read_external()
                 if r.get("kind") == "audit_rows")
    for i in range(3):
        audit.write_log(db, action="search", reason=f"async {i}")
    audit.flush_audit()

    batches = [r for r in anchors.read_external() if r.get("kind") == "audit_rows"]
    after = sum(int(r.get("count") or 0) for r in batches)
    assert after - before >= 3
    # 每批的 seq 单调递增，且行内 seq/prev 链路自洽（sink 侧可重建链）
    flat = [row for b in batches for row in b["rows"]]
    seqs = [r["seq"] for r in flat]
    assert seqs == sorted(seqs)
    for prev, cur in zip(flat, flat[1:]):
        assert cur["prev_hash"] == prev["row_hash"]


# ---------------------------------------------------------------- DB 层只追加


@pytest.fixture
def append_only(db):
    """装只追加触发器（等价于服务启动时 ensure_schema 做的事）。

    测试 schema 由 create_all 建表，触发器属于 ensure_schema 的副作用，
    所以这里显式跑一次——顺带覆盖"幂等"：第二次调用不该重建。
    """
    from app import migrate
    migrate.ensure_schema()
    yield
    # 清掉函数/触发器由 schema DROP CASCADE 兜底，无需手工还原


def test_ensure_schema_installs_triggers_idempotently(db, append_only):
    from sqlalchemy import text as _text
    names = {r[0] for r in db.execute(_text(
        "SELECT tgname FROM pg_trigger "
        "WHERE tgrelid = 'audit_logs'::regclass AND NOT tgisinternal")).all()}
    assert {"trg_audit_append_only", "trg_audit_no_truncate"} <= names

    from app import migrate
    assert migrate.ensure_schema() == []          # 已补过，不再报迁移项
    assert migrate._ensure_audit_append_only(db.connection()) is False


@pytest.mark.parametrize("sql", [
    "UPDATE audit_logs SET reason = '抹掉证据'",
    "DELETE FROM audit_logs",
    "TRUNCATE audit_logs",
])
def test_append_only_trigger_rejects_mutation(db, append_only, sql):
    audit.write_log(db, action="search", reason="orig", sync=True)
    db.commit()

    with pytest.raises(Exception) as exc:
        db.execute(text(sql))
        db.commit()
    db.rollback()
    assert "只追加" in str(exc.value)

    # 内容必须没被动过
    rows = db.query(AuditLog).all()
    assert any(r.reason == "orig" for r in rows)


def test_append_only_break_glass_is_transaction_local(db, append_only):
    """演练破窗：SET LOCAL 只在本事务内有效，提交后约束自动恢复。"""
    audit.write_log(db, action="search", reason="orig", sync=True)
    db.commit()

    db.execute(text("SET LOCAL finrag.audit_append_only = 'off'"))
    db.execute(text("UPDATE audit_logs SET reason = 'drill'"))
    db.commit()

    db.expire_all()
    assert any(r.reason == "drill" for r in db.query(AuditLog).all())
    # 新事务里开关已失效：再次尝试修改必须被拒
    with pytest.raises(Exception) as exc:
        db.execute(text("UPDATE audit_logs SET reason = 'again'"))
        db.commit()
    db.rollback()
    assert "只追加" in str(exc.value)
