# SPDX-License-Identifier: Apache-2.0
"""audit.py —— 审计哈希链单元测试（防篡改三层 + 异步写入）。

链的定义：row_hash = sha256(prev_hash + "|" + canonical(业务字段))。
三种攻击对应三种检出：
  改内容 → row_hash 不符（broken_rows）
  删中间 → 邻链断裂（broken_links）+ 序号断档（seq_gaps）
  删尾行 → 库内链**防不住**（ deliberately ），由启动锚点 resume_chain 兜底
"""
import json
import time

import pytest
from sqlalchemy import delete as sa_delete, func, select

from app import audit
from app.models import AuditLog


@pytest.fixture
def chain():
    """每条用例重置进程内链尾状态与磁盘锚点，保证 seq 从 1 开始、可预测。"""
    audit._last_hash = "GENESIS"
    audit._last_seq = 0
    audit.ANCHOR_FILE.unlink(missing_ok=True)
    yield
    audit.shutdown_audit(timeout=2.0)


def _write(db, action="search", n=1, **kwargs):
    """连续写 n 条同步审计。相邻两条之间留 1ms —— verify_chain 按 (ts, id)
    排序邻链，ts 撞到同一微秒时排序可能与链序不一致（另见报告中的备注）。"""
    logs = []
    for i in range(n):
        if i:
            time.sleep(0.001)
        logs.append(audit.write_log(db, action=f"{action}-{i}", sync=True, **kwargs))
    return logs


def _all(db):
    return list(db.execute(select(AuditLog).order_by(AuditLog.seq)).scalars().all())


# ------------------------------------------------------------------ 链构造


def test_sync_write_assigns_contiguous_seq(db, chain):
    _write(db, "chat", n=3)
    rows = _all(db)
    assert [r.seq for r in rows] == [1, 2, 3]
    assert rows[0].prev_hash == "GENESIS"
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash
    assert all(r.row_hash for r in rows)
    assert rows[0].row_hash != rows[1].row_hash


def test_verify_chain_ok_on_fresh_chain(db, chain):
    _write(db, "search", n=5)
    res = audit.verify_chain(db)
    assert res["ok"] is True
    assert res["checked"] == 5
    assert res["broken_rows"] == 0
    assert res["broken_links"] == 0
    assert res["seq_gaps"] == 0


def test_row_hash_matches_recomputation(db, chain):
    _write(db, "view", n=2)
    rows = _all(db)
    for r in rows:
        expected = audit._chain_hash(r.prev_hash, audit._canonical(r))
        assert r.row_hash == expected


def test_verify_chain_ok_on_empty_table(db, chain):
    res = audit.verify_chain(db)
    assert res["ok"] is True
    assert res["checked"] == 0


def test_write_log_truncates_long_fields(db, chain):
    log = audit.write_log(
        db, action="search", query="问" * 3000, reason="原" * 2000,
        target_id="i" * 100, target_label="l" * 400, ip="p" * 100,
        detail="d" * 9000, sync=True,
    )
    assert len(log.query) == 2000
    assert len(log.reason) == 1000
    assert len(log.target_id) == 36
    assert len(log.target_label) == 255
    assert len(log.ip) == 64
    assert len(log.detail) == 4000


def test_write_log_binds_user_identity(db, chain, user_factory):
    user = user_factory("alice", clearance=2)
    log = audit.write_log(db, user=user, action="login", sync=True)
    assert log.user_id == user.id
    assert log.username == "alice"


def test_write_log_anonymous_default(db, chain):
    log = audit.write_log(db, action="system", sync=True)
    assert log.user_id == ""
    assert log.username == "anonymous"


# ------------------------------------------------------------------ 篡改检出


def test_tampering_content_is_detected(db, chain):
    _write(db, "search", n=3)
    target = _all(db)[1]

    db.execute(
        AuditLog.__table__.update().where(AuditLog.id == target.id).values(
            decision="allow" if target.decision != "allow" else "deny"
        )
    )
    db.commit()
    # Core UPDATE 不走 ORM：用例 Session 的 identity map 里仍是旧值，
    # 必须 expire 让下一次查询真正回到磁盘读被改后的行。
    db.expire_all()

    res = audit.verify_chain(db)
    assert res["ok"] is False
    assert res["broken_rows"] == 1
    assert res["first_broken_id"] == target.id


def test_tampering_reason_is_detected(db, chain):
    """把「越权被拒」改成「已放行」这种最典型的抹痕，必须检出。"""
    audit.write_log(db, action="chat", decision="deny", reason="密级不足",
                    sync=True)
    target = _all(db)[0]
    db.execute(
        AuditLog.__table__.update().where(AuditLog.id == target.id).values(
            decision="allow", reason="合规审查通过"
        )
    )
    db.commit()
    db.expire_all()

    res = audit.verify_chain(db)
    assert res["ok"] is False
    assert res["broken_rows"] >= 1


def test_deleting_middle_row_is_detected(db, chain):
    rows = _write(db, "search", n=4)
    db.execute(sa_delete(AuditLog).where(AuditLog.id == rows[1].id))
    db.commit()
    db.expire_all()

    res = audit.verify_chain(db)
    assert res["ok"] is False
    assert res["broken_links"] == 1
    assert res["seq_gaps"] == 1
    assert res["checked"] == 3


def test_deleting_tail_row_is_invisible_in_db_chain(db, chain):
    """删尾行（截断攻击）库内链看不出来 —— 这正是启动锚点存在的理由。
    这里把「看不出来」钉住，避免有人误以为链已经覆盖了截断场景。"""
    rows = _write(db, "search", n=3)
    db.execute(sa_delete(AuditLog).where(AuditLog.id == rows[-1].id))
    db.commit()
    db.expire_all()

    res = audit.verify_chain(db)
    assert res["ok"] is True
    assert res["checked"] == 2


# ------------------------------------------------------------------ 启动锚点


def test_resume_chain_restores_tail(db, chain):
    _write(db, "search", n=3)
    tail = _all(db)[-1]

    state = audit.resume_chain(db)
    assert state["tail_hash"] == tail.row_hash
    assert state["seq"] == tail.seq == 3


def test_resume_chain_writes_anchor_file(db, chain, tmp_data_dir):
    _write(db, "search", n=2)
    audit.resume_chain(db)
    anchor = tmp_data_dir / "audit_anchor.json"
    assert anchor.is_file()
    data = json.loads(anchor.read_text(encoding="utf-8"))
    assert set(data) == {"tail_hash", "seq", "ts"}


def test_resume_chain_chain_continues_after_restart(db, chain):
    _write(db, "search", n=2)
    audit.resume_chain(db)

    audit.write_log(db, action="chat", sync=True)
    rows = _all(db)
    assert [r.seq for r in rows] == [1, 2, 3]
    assert rows[2].prev_hash == rows[1].row_hash


def test_resume_chain_no_alert_on_clean_restart(db, chain):
    _write(db, "search", n=3)
    audit.resume_chain(db)
    before = db.execute(select(func.count()).select_from(AuditLog)).scalar()

    audit.resume_chain(db)
    after = db.execute(select(func.count()).select_from(AuditLog)).scalar()
    assert after == before


def test_resume_chain_detects_truncated_tail(db, chain):
    rows = _write(db, "search", n=3)
    tail = rows[-1]
    audit._write_anchor(tail.row_hash, tail.seq + 2)   # 锚点比库尾新 → 尾行被删

    before = db.execute(select(func.count()).select_from(AuditLog)).scalar()
    audit.resume_chain(db)
    after = db.execute(select(func.count()).select_from(AuditLog)).scalar()

    assert after == before + 1
    alert = _all(db)[-1]
    assert alert.action == "system"
    assert alert.decision == "deny"
    assert "被截断删除" in alert.reason


def test_resume_chain_detects_tail_tampering(db, chain):
    rows = _write(db, "search", n=3)
    tail = rows[-1]
    audit._write_anchor("f" * 64, tail.seq)     # 同序号、不同哈希 → 尾行被改

    before = db.execute(select(func.count()).select_from(AuditLog)).scalar()
    audit.resume_chain(db)
    after = db.execute(select(func.count()).select_from(AuditLog)).scalar()

    assert after == before + 1
    assert "篡改" in _all(db)[-1].reason


def test_resume_chain_on_empty_db_starts_from_genesis(db, chain):
    state = audit.resume_chain(db)
    assert state == {"tail_hash": "GENESIS", "seq": 0}


# ------------------------------------------------------------------ 异步写入


def test_async_write_lands_after_flush(db, chain):
    log = audit.write_log(db, action="search", detail="异步写入测试", sync=False)
    assert log.id          # 调用方拿到 id 不必等落库
    assert log.seq in (None, 0)

    assert audit.flush_audit(timeout=5.0) is True

    row = db.get(AuditLog, log.id)
    assert row is not None
    assert row.seq == 1
    assert row.row_hash
    assert row.detail == "异步写入测试"


def test_async_batch_keeps_chain_order(db, chain):
    ids = [
        audit.write_log(db, action=f"q-{i}", sync=False).id
        for i in range(5)
    ]
    assert audit.flush_audit(timeout=5.0) is True
    db.commit()

    rows = db.execute(
        select(AuditLog).where(AuditLog.id.in_(ids))
    ).scalars().all()
    seqs = sorted(r.seq for r in rows)
    assert seqs == [1, 2, 3, 4, 5]

    res = audit.verify_chain(db)
    assert res["ok"] is True
    assert res["checked"] == 5


def test_flush_audit_is_idempotent(db, chain):
    audit.write_log(db, action="search", sync=False)
    assert audit.flush_audit(timeout=5.0) is True
    assert audit.flush_audit(timeout=5.0) is True


def test_queue_full_falls_back_to_sync(db, chain, monkeypatch):
    """背压：队列投不进去时自动回落同步直写，审计一行都不能丢。"""
    monkeypatch.setattr(audit, "_audit_q", _FullQueue())
    log = audit.write_log(db, action="search", detail="背压回落", sync=False)
    assert log.seq == 1
    db.commit()
    row = db.get(AuditLog, log.id)
    assert row is not None and row.detail == "背压回落"


class _FullQueue:
    """永远投不进的队列替身，用于验证背压回落同步直写路径。

    `put`（带 timeout/block）也必须抛 Full：shutdown_audit 的关机路径用
    的是 put 而非 put_nowait，替身不完整会让审计收尾在背压用例的 teardown
    里炸 AttributeError——那与"背压回落"本身要验的行为无关。
    """

    def put(self, item, timeout=None, block=True):
        raise __import__("queue").Full

    def put_nowait(self, item):
        raise __import__("queue").Full

    @property
    def unfinished_tasks(self):
        return 0
