# SPDX-License-Identifier: AGPL-3.0-only
"""approval.py —— 密级变更审批流单元测试（P2-9）。

降密 = 把原本受限的内容开放出去，是**不可逆**的信息外流，必须走：
  申请人发起 → 他人复核 → 复核人密级 ≥ 目标密级 → 生效 → 全程留痕
反向的升密（变严格）不产生外流，默认直接生效。

这里逐条钉住：谁需要审批、谁能批、拒绝为什么必须写理由。
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app import approval
from app.models import ApprovalRequest


# ---------------------------------------------------------------- level_name


@pytest.mark.parametrize(
    "value,expected",
    [(0, "公开"), (1, "内部"), (2, "机密"), (3, "绝密")],
)
def test_level_name_maps_known_levels(value, expected):
    assert approval.level_name(value) == expected


@pytest.mark.parametrize("value", [99, -1, None, "x"])
def test_level_name_falls_back_to_str(value):
    assert isinstance(approval.level_name(value), str)


# ---------------------------------------------------------------- 发起：是否需要审批


def test_downgrade_creates_pending_request(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=1)
    doc = doc_factory(clearance=3)

    req, msg = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    assert req is not None
    assert req.status == "pending"
    assert req.kind == "clearance"
    assert req.from_value == "3"
    assert req.to_value == "1"
    assert req.requester_id == user.id
    # 未经批准，文档密级必须纹丝不动
    assert doc.clearance == 3
    assert "已提交审批" in msg


def test_upgrade_applies_immediately(db, user_factory, doc_factory):
    """升密不产生外流，默认直接生效（卡审批只会逼人绕过流程）。"""
    user = user_factory("analyst", clearance=3)
    doc = doc_factory(clearance=1)

    req, msg = approval.request_clearance_change(db, user, doc, 3)

    assert req is None
    assert doc.clearance == 3
    assert "立即生效" in msg or "变严" in msg


def test_upgrade_can_be_required_by_policy(db, user_factory, doc_factory, monkeypatch):
    monkeypatch.setattr(approval, "APPROVAL_UPGRADE_REQUIRED", True, raising=False)
    user = user_factory("analyst", clearance=3)
    doc = doc_factory(clearance=1)

    req, msg = approval.request_clearance_change(db, user, doc, 3)
    db.flush()

    assert req is not None
    assert req.status == "pending"
    assert doc.clearance == 1
    assert "已提交审批" in msg


def test_same_level_is_noop(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=2)
    doc = doc_factory(clearance=2)

    req, msg = approval.request_clearance_change(db, user, doc, 2)

    assert req is None
    assert msg == "密级未变化"
    assert doc.clearance == 2


def test_emergency_bypass_applies_downgrade(db, user_factory, doc_factory,
                                            monkeypatch):
    monkeypatch.setattr(approval, "APPROVAL_EMERGENCY_BYPASS", True, raising=False)
    user = user_factory("analyst", clearance=1)
    doc = doc_factory(clearance=3)

    req, msg = approval.request_clearance_change(db, user, doc, 0)

    assert req is None
    assert doc.clearance == 0
    assert "紧急旁路" in msg


def test_duplicate_pending_request_is_not_created(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=1)
    doc = doc_factory(clearance=3)

    first, _ = approval.request_clearance_change(db, user, doc, 2)
    db.flush()
    second, msg = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    assert second is first
    assert msg == "该文档已有待审批的密级变更单"
    count = db.execute(
        select(func.count()).select_from(ApprovalRequest)
    ).scalar()
    assert count == 1


def test_new_request_allowed_after_previous_decided(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    approver = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)

    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()
    approval.decide(db, approver, req.id, approve=False, reason="暂不降密")
    db.flush()

    new_req, msg = approval.request_clearance_change(db, user, doc, 2)
    db.flush()
    assert new_req is not req
    assert new_req.status == "pending"
    assert "已提交审批" in msg


# ---------------------------------------------------------------- 审批：谁能批


def test_requester_cannot_approve_self(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, user, req.id, approve=True)
    assert exc.value.status_code == 403
    assert "不能审批自己" in exc.value.detail


def test_approver_clearance_below_target_is_rejected(db, user_factory, doc_factory):
    """密级 1 的人不该有能力批准把绝密文档开放到机密（目标密级 2）。"""
    user = user_factory("analyst", clearance=3)
    weak = user_factory("weak", clearance=1)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 2)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, weak, req.id, approve=True)
    assert exc.value.status_code == 403
    assert "低于目标密级" in exc.value.detail
    assert doc.clearance == 3
    assert req.status == "pending"


def test_approver_with_sufficient_clearance_approves(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    decided = approval.decide(db, boss, req.id, approve=True, reason="已在内网脱敏")

    assert decided.status == "approved"
    assert decided.approver_id == boss.id
    assert decided.decided_at is not None
    assert decided.decided_reason == "已在内网脱敏"
    assert doc.clearance == 1


def test_approval_at_exact_clearance_boundary(db, user_factory, doc_factory):
    """复核人密级 == 目标密级即可（`>=` 而非 `>`）。"""
    user = user_factory("analyst", clearance=3)
    peer = user_factory("peer", clearance=2)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 2)
    db.flush()

    decided = approval.decide(db, peer, req.id, approve=True)
    assert decided.status == "approved"
    assert doc.clearance == 2


def test_low_clearance_approver_can_still_reject(db, user_factory, doc_factory):
    """拒绝不产生外流，密级要求只约束「批准」这一侧。"""
    user = user_factory("analyst", clearance=3)
    weak = user_factory("weak", clearance=0)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 2)
    db.flush()

    decided = approval.decide(db, weak, req.id, approve=False, reason="不同意")
    assert decided.status == "rejected"
    assert doc.clearance == 3


# ---------------------------------------------------------------- 审批：拒绝必须写理由


def test_reject_without_reason_is_rejected(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    for empty in ("", "   ", None):
        with pytest.raises(HTTPException) as exc:
            approval.decide(db, boss, req.id, approve=False, reason=empty)
        assert exc.value.status_code == 400
        assert "拒绝必须填写理由" in exc.value.detail


def test_reject_with_reason_records_decision(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    decided = approval.decide(db, boss, req.id, approve=False,
                              reason="  尚未完成脱敏复核  ")

    assert decided.status == "rejected"
    assert decided.decided_reason == "尚未完成脱敏复核"   # 已 strip
    assert decided.approver_id == boss.id
    assert doc.clearance == 3


def test_decided_reason_is_truncated(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    decided = approval.decide(db, boss, req.id, approve=True, reason="啰" * 1000)
    assert len(decided.decided_reason) <= 500


# ---------------------------------------------------------------- 异常与状态机


def test_decide_unknown_request_is_404(db, user_factory):
    boss = user_factory("boss", clearance=3)
    with pytest.raises(HTTPException) as exc:
        approval.decide(db, boss, "no-such-id", approve=True)
    assert exc.value.status_code == 404


def test_decide_twice_is_409(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()

    approval.decide(db, boss, req.id, approve=True)
    with pytest.raises(HTTPException) as exc:
        approval.decide(db, boss, req.id, approve=True)
    assert exc.value.status_code == 409


def test_decide_missing_document_auto_rejects(db, user_factory, doc_factory):
    """文档在审批期间被删除：不能留一张永远悬着的 pending 单。"""
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    doc = doc_factory(clearance=3)
    req, _ = approval.request_clearance_change(db, user, doc, 1)
    db.flush()
    db.delete(doc)
    db.flush()

    decided = approval.decide(db, boss, req.id, approve=True)
    assert decided.status == "rejected"
    assert decided.decided_reason == "原文档已不存在"


# ---------------------------------------------------------------- 待审批查询


def test_pending_doc_ids_marks_only_pending_clearance(db, user_factory, doc_factory):
    user = user_factory("analyst", clearance=3)
    boss = user_factory("boss", clearance=3)
    p1 = doc_factory("待审批1", clearance=3)
    p2 = doc_factory("待审批2", clearance=3)
    done = doc_factory("已办结", clearance=3)

    r1, _ = approval.request_clearance_change(db, user, p1, 1)
    r2, _ = approval.request_clearance_change(db, user, p2, 1)
    r3, _ = approval.request_clearance_change(db, user, done, 1)
    db.flush()
    approval.decide(db, boss, r3.id, approve=True)
    db.flush()

    ids = approval.pending_doc_ids(db)
    assert ids == {p1.id, p2.id}


def test_pending_doc_ids_empty_when_none(db):
    assert approval.pending_doc_ids(db) == set()
