# SPDX-License-Identifier: AGPL-3.0-only
"""跨账号合谋拼图「检出」（app/jigsaw.py coalition_alerts）。

背景：单账号账本按定义挡不住 N 个低权限账号各取一块、线下合并——每个人
单独看都没越权、覆盖率都不高，并集却逼近全文。本模块只做**检出**并交给
人工复核，不自动封禁（热点文档被同事正常阅读时并集天然很高，自动处置
会把正常业务打死）。这里要钉死的口径：

  · 参与账号数不足阈值 → 不报；
  · 并集覆盖率低于阈值 → 不报；
  · 明细被 SEEN_DETAIL_CAP 截断 → 只能给上界，必须标 approx=True，
    绝不把"上界"冒充成"精确并集覆盖率"；
  · 总开关关闭 → 一律空列表（不偷偷算）。
"""
import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app import jigsaw
from app.main import app as real_app
from app.models import Chunk, Document, ExposureLedger, User, new_id
from app.security import hash_password

API = "/api/v1"


@pytest.fixture
def client():
    return TestClient(real_app)


@pytest.fixture
def ccfg(monkeypatch):
    """阈值收敛到小整数，并固定窗口口径。"""
    vals = {
        "JIGSAW_COALITION_ENABLED": True,
        "JIGSAW_COALITION_MIN_USERS": 3,
        "JIGSAW_COALITION_COVER": 0.85,
        "JIGSAW_LONG_WINDOW_DAYS": 7,
        "JIGSAW_WINDOW_HOURS": 24,
    }
    for k, v in vals.items():
        monkeypatch.setattr(jigsaw, k, v, raising=False)
    return vals


def _doc(db, n_chunks=10, title="合谋样本"):
    d = Document(id=new_id(), title=title, clearance=1, acl_mode="open",
                 status="ready")
    db.add(d)
    db.flush()
    ids = []
    for i in range(n_chunks):
        c = Chunk(id=new_id(), doc_id=d.id, seq=i, content=f"第{i}段正文",
                  content_len=5)
        db.add(c)
        ids.append(c.id)
    db.flush()
    return d, ids


def _user(db, name, clearance=1):
    u = User(id=new_id(), username=name, display_name=name,
             clearance=clearance, roles=json.dumps(["research"]),
             pwd_hash="x", salt="y", status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.flush()
    return u


def _ledger(db, user, doc, seen_ids, *, seen_count=None, chars=100,
            window_key=None):
    row = ExposureLedger(
        user_id=user.id, doc_id=doc.id,
        window_key=window_key or jigsaw.current_window_key(),
        seen_chunks=json.dumps(sorted(seen_ids)),
        seen_count=len(seen_ids) if seen_count is None else seen_count,
        char_total=chars, query_count=1, last_ts=datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def test_single_user_high_coverage_is_not_a_coalition(db, ccfg):
    """防：一个人读满 90% 被当成"合谋"——那是单账号风险榜的事，不是本模块。"""
    d, ids = _doc(db, 10)
    u = _user(db, "solo")
    _ledger(db, u, d, ids[:9])
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_three_users_union_high_triggers_alert(db, ccfg):
    """三人各取 4 段、互不重叠 → 并集 12/12 覆盖，必须报出来。"""
    d, ids = _doc(db, 12)
    users = [_user(db, f"u{i}") for i in range(3)]
    for i, u in enumerate(users):
        _ledger(db, u, d, ids[i * 4:(i + 1) * 4])
    db.commit()

    alerts = jigsaw.coalition_alerts(db)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["doc_id"] == d.id and a["users"] == 3
    assert a["union_seen"] == 12 and a["total"] == 12
    assert a["coverage"] == 1.0 and a["approx"] is False
    assert {m["username"] for m in a["members"]} == {"u0", "u1", "u2"}


def test_below_min_users_is_ignored(db, ccfg):
    """两人拼满全文也不报：阈值默认 3，两人并集更可能是正常协作。"""
    d, ids = _doc(db, 10)
    for i in range(2):
        _ledger(db, _user(db, f"u{i}"), d, ids[i * 5:(i + 1) * 5])
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_low_union_coverage_is_ignored(db, ccfg):
    """三人各取 2 段（并集 6/12=0.5 < 0.85）→ 不报，避免噪声淹没真信号。"""
    d, ids = _doc(db, 12)
    for i in range(3):
        _ledger(db, _user(db, f"u{i}"), d, ids[i * 2:(i + 1) * 2])
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_truncated_detail_is_marked_approx(db, ccfg, monkeypatch):
    """防：明细被截断（seen_chunks 为空但 seen_count>0）时把上界当精确覆盖率。

    这里刻意把阈值放低，确保报出来的那条必须带 approx=True——运维据此知道
    "这一条是上界估算，复核前别当成确凿证据"。
    """
    monkeypatch.setattr(jigsaw, "JIGSAW_COALITION_COVER", 0.5)
    d, ids = _doc(db, 10)
    for i in range(3):
        u = _user(db, f"t{i}")
        # 明细为空串（模拟 SEEN_DETAIL_CAP 截断后只留计数）
        _ledger(db, u, d, [], seen_count=3)
    db.commit()

    alerts = jigsaw.coalition_alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["approx"] is True
    assert alerts[0]["union_seen"] == 0        # 精确并集无从得知
    assert alerts[0]["coverage"] == 0.9        # 9/10 上界（各账号条数之和）


def test_switch_off_returns_nothing(db, ccfg, monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_COALITION_ENABLED", False)
    d, ids = _doc(db, 10)
    for i in range(3):
        _ledger(db, _user(db, f"x{i}"), d, ids[i * 3:(i + 1) * 3 + 1])
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_old_window_rows_are_excluded(db, ccfg):
    """窗口外的账本不参与：上周的分散阅读不该和本周的拼起来报警。"""
    d, ids = _doc(db, 10)
    for i in range(3):
        _ledger(db, _user(db, f"w{i}"), d, ids[i * 4:(i + 1) * 4],
                window_key="w0")   # 早于长窗口范围的旧桶
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_doc_without_chunks_is_skipped(db, ccfg):
    """防：除零。切片表为空时不能拿 0 当分母算出 inf/NaN。"""
    d = Document(id=new_id(), title="空文档", clearance=1, acl_mode="open",
                 status="ready")
    db.add(d)
    db.flush()
    for i in range(3):
        _ledger(db, _user(db, f"z{i}"), d, [], seen_count=2)
    db.commit()
    assert jigsaw.coalition_alerts(db) == []


def test_deleted_user_or_doc_does_not_crash(db, ccfg):
    """账本行指向已删除主体时只降级显示，不能 500。"""
    d, ids = _doc(db, 6)
    for i in range(3):
        _ledger(db, _user(db, f"d{i}"), d, ids[i * 2:(i + 1) * 2])
    db.commit()
    # 直接删 doc（cascade 会删切片，账本无外键约束，故意留悬空行）
    db.delete(d)
    db.commit()
    assert jigsaw.coalition_alerts(db) == []   # 无切片可算 → 跳过


def test_members_sorted_by_exposure(db, ccfg):
    """成员按披露量降序：复核时先问那个拿得最多的人。"""
    d, ids = _doc(db, 12)
    counts = [6, 4, 2]
    for i, n in enumerate(counts):
        start = sum(counts[:i])
        _ledger(db, _user(db, f"m{i}"), d, ids[start:start + n])
    db.commit()
    a = jigsaw.coalition_alerts(db)[0]
    assert [m["seen"] for m in a["members"]] == counts


def test_admin_endpoint_lists_alerts(client, db, ccfg):
    """管理端可查（HTTP 契约）：未登录 401。"""
    d, ids = _doc(db, 12)
    for i in range(3):
        _ledger(db, _user(db, f"e{i}"), d, ids[i * 4:(i + 1) * 4])
    db.commit()

    pwd, salt = hash_password("Coalition-Adm1n!2026")
    db.add(User(id=new_id(), username="coalition_admin",
                display_name="coalition_admin", clearance=3,
                roles=json.dumps(["admin"]), pwd_hash=pwd, salt=salt,
                status=True, must_change_password=False, token_version=0))
    db.commit()
    r = client.post(f"{API}/auth/login",
                    json={"username": "coalition_admin",
                          "password": "Coalition-Adm1n!2026"})
    assert r.status_code == 200, r.text
    hdr = {"Authorization": f"Bearer {r.json()['token']}"}

    r = client.get(f"{API}/admin/jigsaw/coalition", headers=hdr)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1 and body[0]["doc_title"] == "合谋样本"
    assert body[0]["users"] == 3

    assert client.get(f"{API}/admin/jigsaw/coalition").status_code == 401
