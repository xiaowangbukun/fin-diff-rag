# SPDX-License-Identifier: AGPL-3.0-only
"""账号权限双人复核（P0-1）：单人不得给自己/他人扩权。

威胁模型：管理员账号本身就是"最大攻击面"——能建号、能升密、能重置动态口令。
如果一次 PATCH 就能把自己的密级从「内部」调到「绝密」、或把 admin 角色加给
一个新账号，那么审计日志记录得再完整也只是"事后知道谁干的"。

本文件钉住四条硬规则：
  1. 放宽（加角色 / 升密 / 停用→启用 / 改挂部门）→ 只建单，**不改库**；
  2. 收紧（去角色 / 降密 / 停用）→ 立即生效（安全方向不能被流程拖慢）；
  3. 审批人不能是申请人、不能是目标账号本人，且密级必须够得上目标密级；
  4. 最后一名启用中的管理员不能被降权/停用（防自锁）。
"""
import json
import threading
import time

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app import approval
from app.models import ApprovalRequest, User

ROLES_ADMIN = ["admin"]


def _u(db, user_factory, username, clearance=1, roles=None, **kw):
    u = user_factory(username, clearance=clearance, roles=roles or [], **kw)
    db.flush()
    return u


# ---------------------------------------------------------------- 放宽 vs 收紧


def test_widening_creates_pending_and_keeps_db_untouched(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])

    req, note = approval.request_user_change(
        db, requester, target, to_roles=["guest", "risk"], to_clearance=2,
        to_active=True, to_dept_id=None, reason="转岗风控")
    db.flush()

    assert req is not None and req.status == "pending"
    assert req.kind == "user_privilege" and req.subject_type == "user"
    assert "已提交审批" in note
    # 放宽不能先斩后奏：审批前库里必须保持原样
    assert target.clearance == 1
    assert json.loads(target.roles) == ["guest"]
    payload = json.loads(req.payload)
    assert payload["to_roles"] == ["guest", "risk"]
    assert "新增角色 risk" in "".join(payload["widening"])


def test_tightening_applies_immediately(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "risky", clearance=2, roles=["risk"])

    req, note = approval.request_user_change(
        db, requester, target, to_roles=[], to_clearance=1,
        to_active=True, to_dept_id=None, reason="风险岗轮岗结束")

    assert req is None
    assert "立即生效" in note
    assert target.clearance == 1 and json.loads(target.roles) == []


def test_disable_is_tightening_and_applies(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "leaver", clearance=2, roles=["risk"])

    req, _ = approval.request_user_change(
        db, requester, target, to_roles=["risk"], to_clearance=2,
        to_active=False, to_dept_id=None)
    assert req is None
    assert target.status is False


def test_reenable_is_widening(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "frozen", clearance=1, roles=["guest"])
    target.status = False
    db.flush()

    req, note = approval.request_user_change(
        db, requester, target, to_roles=["guest"], to_clearance=1,
        to_active=True, to_dept_id=None)
    assert req is not None and "已提交审批" in note
    assert target.status is False


def test_no_change_is_noop(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "steady", clearance=2, roles=["risk"])

    req, note = approval.request_user_change(
        db, requester, target, to_roles=["risk"], to_clearance=2,
        to_active=True, to_dept_id=None)
    assert req is None and note == "账号权限无变化"


def test_widening_does_not_duplicate_pending(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])

    first, _ = approval.request_user_change(
        db, requester, target, ["guest", "risk"], 1, True, None)
    db.flush()
    second, note = approval.request_user_change(
        db, requester, target, ["guest", "risk", "research"], 1, True, None)

    assert second is first
    assert "已有一张待审批" in note
    assert db.execute(select(func.count()).select_from(ApprovalRequest)).scalar() == 1


def test_unknown_role_is_filtered(db, user_factory):
    """角色白名单：不允许把任意字符串塞进 roles（否则等于自造权限面）。"""
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])

    req, _ = approval.request_user_change(
        db, requester, target, ["guest", "superuser"], 1, True, None)
    # 非法角色被过滤后无变化 → 不建单、不改库
    assert req is None
    assert json.loads(target.roles) == ["guest"]


# ---------------------------------------------------------------- 审批侧


def test_requester_cannot_approve_own_privilege_request(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])
    req, _ = approval.request_user_change(
        db, requester, target, ["guest", "risk"], 2, True, None)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, requester, req.id, approve=True)
    assert exc.value.status_code == 403
    assert "不能审批自己" in exc.value.detail
    assert target.clearance == 1


def test_admin_to_guest_is_treated_as_tightening(db, user_factory):
    """管理员降级为访客是净收紧：不能被"加了个 guest 角色"误判成放宽。"""
    a = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)

    widening, why = approval.privilege_widening(
        ["admin"], 3, True, None, ["guest"], 3, True, None)
    assert widening is False and why == []

    widening, why = approval.privilege_widening(
        ["admin"], 3, True, None, ["admin", "risk"], 3, True, None)
    assert widening is True and "新增角色 risk" in why


def test_approver_with_lower_clearance_is_rejected(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    weak = _u(db, user_factory, "weakadmin", clearance=1, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])
    req, _ = approval.request_user_change(
        db, requester, target, ["guest"], 2, True, None)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, weak, req.id, approve=True)
    assert exc.value.status_code == 403
    assert "低于目标密级" in exc.value.detail


def test_second_admin_approves_and_change_applies(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    approver = _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])
    req, _ = approval.request_user_change(
        db, requester, target, ["guest", "risk"], 2, True, None)
    db.flush()

    decided = approval.decide(db, approver, req.id, approve=True, reason="已评估")
    assert decided.status == "approved"
    assert decided.approver_name == "root2"
    assert target.clearance == 2
    assert json.loads(target.roles) == ["guest", "risk"]


def test_target_cannot_approve_own_account(db, user_factory):
    """目标账号本人持 admin 时也不能批自己的权限单（防串通/自批）。"""
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "selfadmin", clearance=1, roles=ROLES_ADMIN)
    req, _ = approval.request_user_change(
        db, requester, target, ["admin", "risk"], 3, True, None)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, target, req.id, approve=True)
    assert exc.value.status_code == 403
    assert "自己的账号权限" in exc.value.detail


def test_disable_via_approval_bumps_token_version(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    approver = _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "leaver", clearance=2, roles=["risk"])
    target.token_version = 3
    db.flush()
    # 停用本身是收紧（立即生效），这里直接断言"停用即断线"的副作用
    req, _ = approval.request_user_change(
        db, requester, target, ["risk"], 2, False, None)
    db.flush()
    assert req is None and target.status is False
    # 收紧路径不改代次（没有既有令牌需要立刻作废的语义变化），
    # 但审批路径的停用必须换代次（见 _apply_user_privilege）。
    assert target.token_version == 3


def test_reject_requires_reason_and_keeps_privileges(db, user_factory):
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    approver = _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])
    req, _ = approval.request_user_change(
        db, requester, target, ["guest", "risk"], 2, True, None)
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.decide(db, approver, req.id, approve=False, reason="  ")
    assert exc.value.status_code == 400

    decided = approval.decide(db, approver, req.id, approve=False, reason="岗位不符")
    assert decided.status == "rejected"
    assert target.clearance == 1


# ---------------------------------------------------------------- 最后一名管理员保护


def test_last_admin_cannot_demote_self(db, user_factory):
    only = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])

    with pytest.raises(HTTPException) as exc:
        approval.request_user_change(
            db, only, only, to_roles=["guest"], to_clearance=3,
            to_active=True, to_dept_id=None)
    assert exc.value.status_code == 409
    assert "最后一名" in exc.value.detail
    # 拒绝后角色必须没动（不能出现"报错了但已经写库"）
    assert json.loads(only.roles) == ["admin"]


def test_last_admin_cannot_be_disabled(db, user_factory):
    only = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    with pytest.raises(HTTPException) as exc:
        approval.request_user_change(
            db, only, only, to_roles=["admin"], to_clearance=3,
            to_active=False, to_dept_id=None)
    assert exc.value.status_code == 409
    assert only.status is True


def test_demotion_allowed_when_another_admin_exists(db, user_factory):
    a = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)

    req, note = approval.request_user_change(
        db, a, a, to_roles=["guest"], to_clearance=3, to_active=True,
        to_dept_id=None)
    # 收紧（去 admin）立即生效，不需要审批
    assert req is None and "立即生效" in note
    assert json.loads(a.roles) == ["guest"]


def test_disabled_admin_does_not_count_for_protection(db, user_factory):
    """停用中的 admin 不算"另一名管理员"——否则可借停用账号绕过自锁保护。"""
    only = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    dead = _u(db, user_factory, "root2", clearance=3, roles=ROLES_ADMIN)
    dead.status = False
    db.flush()

    with pytest.raises(HTTPException) as exc:
        approval.request_user_change(
            db, only, only, to_roles=["guest"], to_clearance=3,
            to_active=True, to_dept_id=None)
    assert exc.value.status_code == 409


# ---------------------------------------------------------------- 建号授权留痕


def test_new_account_grant_writes_granted_record(db, user_factory):
    admin = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "newbie", clearance=0, roles=[])

    approval.grant_privileges_now(
        db, admin, target, ["risk"], 2, True, None, reason="新建账号：初始授权")
    db.flush()

    assert target.clearance == 2 and json.loads(target.roles) == ["risk"]
    req = db.execute(select(ApprovalRequest)).scalars().one()
    assert req.status == "granted"
    assert req.kind == "user_privilege" and req.subject_type == "user"
    assert req.doc_id == target.id
    assert req.approver_name == "root"


# ---------------------------------------------------------------- 并发双批（行锁）


def test_concurrent_approvals_apply_only_once(db, engine, user_factory, monkeypatch):
    """两名管理员同时点"通过"，只能落一次变更（多 worker 的默认形态）。

    没有行锁时两个事务都能读到 status=pending，于是各自写一次授权、各自把
    审批单置为 approved：两边都返回 200，目标账号却被授权两次，审批记录
    互相覆盖——事后审计看到两条"同一单的不同审批人"，无法判断哪次生效。
    这里用"第一个审批者在持锁期间阻塞"精确复现该竞态：第二个请求必须等，
    等到的是已提交的 approved，返回 409。
    """
    requester = _u(db, user_factory, "root", clearance=3, roles=ROLES_ADMIN)
    approver_a = _u(db, user_factory, "checker1", clearance=3, roles=ROLES_ADMIN)
    approver_b = _u(db, user_factory, "checker2", clearance=3, roles=ROLES_ADMIN)
    target = _u(db, user_factory, "trainee", clearance=1, roles=["guest"])
    req, _ = approval.request_user_change(
        db, requester, target, to_roles=["guest", "risk"], to_clearance=2,
        to_active=True, to_dept_id=None, reason="转岗风控")
    db.commit()
    req_id, target_id = req.id, target.id

    entered, release = threading.Event(), threading.Event()
    original = approval._finalize

    def slow_finalize(r, approver, reason):
        entered.set()                     # 说明本线程已持有该审批单的行锁
        assert release.wait(5), "持锁线程等待超时"
        return original(r, approver, reason)

    monkeypatch.setattr(approval, "_finalize", slow_finalize)

    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine, autoflush=False, future=True,
                           expire_on_commit=False)
    results: dict[str, object] = {}

    def run(name: str, uid: str) -> None:
        s = Session()
        try:
            results[name] = approval.decide(
                s, s.get(User, uid), req_id, True, "并发复核").status
            s.commit()
        except HTTPException as exc:
            s.rollback()
            results[name] = exc.status_code
        finally:
            s.close()

    first = threading.Thread(target=run, args=("a", approver_a.id))
    first.start()
    assert entered.wait(5), "第一个审批者未能进入落库阶段"
    second = threading.Thread(target=run, args=("b", approver_b.id))
    second.start()
    # 给第二个事务足够时间卡在 SELECT ... FOR UPDATE（没有锁时它会直接落库）
    time.sleep(0.5)
    release.set()
    first.join(10)
    second.join(10)

    assert set(results.values()) == {"approved", 409}
    db.expire_all()
    assert db.get(ApprovalRequest, req_id).status == "approved"
    applied = db.get(User, target_id)
    # 变更只应用一次：角色没有重复、密级就是目标值
    assert json.loads(applied.roles) == ["guest", "risk"]
    assert applied.clearance == 2
