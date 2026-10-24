# SPDX-License-Identifier: Apache-2.0
"""policy.py —— 权限引擎单元测试。

判定顺序是「密级硬门槛 → deny → ACL 模式 → 临时授权存活期」，
deny 永远优先。这里的用例逐条钉住这条顺序，外加 effective_clearance
的切片级提升语义（切片段只能上调密级，不能下调）。
"""
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import Document
from app.policy import (
    accessible_doc_ids, can_access, dept_chain, effective_clearance,
    invalidate_dept_cache,
)


# ---------------------------------------------------------------- 纯函数部分


@pytest.mark.parametrize(
    "doc_lvl,chunk_lvl,expected",
    [
        (1, None, 1),      # 切片无独立密级 → 继承文档密级
        (1, 3, 3),         # 切片密级高于文档 → 提升（只上调）
        (3, 1, 3),         # 切片密级低于文档 → 仍取文档密级（不能下调）
        (0, 0, 0),
        (None, None, 0),   # 脏值兜底
        (2, 2, 2),
    ],
)
def test_effective_clearance_is_max(doc_lvl, chunk_lvl, expected):
    assert effective_clearance(doc_lvl, chunk_lvl) == expected


def test_effective_clearance_never_downgrades():
    """CIA 语义核心：切片密级只能让内容变严，绝不能让高密文档的一段变松。"""
    for doc_lvl in range(4):
        assert effective_clearance(doc_lvl, 0) >= doc_lvl


# ---------------------------------------------------------------- 部门链


def test_dept_chain_includes_all_descendants(db, dept_factory, user_factory):
    root = dept_factory("总部")
    mid = dept_factory("风控中心", parent_id=root.id)
    leaf = dept_factory("风控一组", parent_id=mid.id)

    user = user_factory("u_root", dept_id=root.id)
    chain = dept_chain(db, user)
    assert {root.id, mid.id, leaf.id}.issubset(set(chain))


def test_dept_chain_is_one_directional(db, dept_factory, user_factory):
    """下级部门的用户不能反查上级部门的文档。"""
    root = dept_factory("总部")
    leaf = dept_factory("风控一组", parent_id=root.id)

    user = user_factory("u_leaf", dept_id=leaf.id)
    chain = dept_chain(db, user)
    assert leaf.id in chain
    assert root.id not in chain


def test_dept_chain_without_dept_is_sentinel(db, user_factory):
    user = user_factory("orphan", dept_id=None)
    assert dept_chain(db, user) == ["__none__"]


def test_dept_cache_invalidate_picks_up_new_dept(db, dept_factory, user_factory):
    """部门树缓存 TTL 5s：任何结构变更都要能立即失效，消除权限缓存时间窗。"""
    root = dept_factory("总部")
    user = user_factory("u", dept_id=root.id)
    assert dept_chain(db, user) == [root.id]

    child = dept_factory("新部门", parent_id=root.id)
    # 未失效前可能命中缓存
    invalidate_dept_cache()
    assert child.id in dept_chain(db, user)


# ---------------------------------------------------------------- 密级门槛


def test_clearance_equal_is_allowed(db, user_factory, doc_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="open")
    ok, reason = can_access(db, user, doc)
    assert ok is True
    assert reason == "公开文档"


def test_clearance_below_document_is_denied(db, user_factory, doc_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=2, acl_mode="open")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "密级不足" in reason
    assert "机密" in reason and "内部" in reason


def test_clearance_gate_runs_before_acl(db, user_factory, doc_factory, acl_factory):
    """密级硬门槛不依赖任何 ACL：显式 allow 也不能让低密用户看到高密文档。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=3, acl_mode="restrict", owner_dept_id=None)
    acl_factory(doc.id, "user", user.id, effect="allow")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "密级不足" in reason


# ---------------------------------------------------------------- ACL 三模式


def test_open_mode_visible_with_matching_clearance(db, user_factory, doc_factory):
    doc = doc_factory(clearance=0, acl_mode="open")
    user = user_factory("guest", clearance=0)
    ok, reason = can_access(db, user, doc)
    assert (ok, reason) == (True, "公开文档")


def test_dept_mode_same_dept_allowed(db, dept_factory, user_factory, doc_factory):
    dept = dept_factory("合规部")
    user = user_factory("u", clearance=1, dept_id=dept.id)
    doc = doc_factory(clearance=1, acl_mode="dept", owner_dept_id=dept.id)
    ok, reason = can_access(db, user, doc)
    assert (ok, reason) == (True, "同部门/上级部门可见")


def test_dept_mode_other_dept_denied(db, dept_factory, user_factory, doc_factory):
    a = dept_factory("合规部")
    b = dept_factory("投行部")
    user = user_factory("u", clearance=1, dept_id=a.id)
    doc = doc_factory(clearance=1, acl_mode="dept", owner_dept_id=b.id)
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "显式授权" in reason


def test_dept_mode_parent_sees_child_doc(db, dept_factory, user_factory, doc_factory):
    parent = dept_factory("总部")
    child = dept_factory("资管部", parent_id=parent.id)
    user = user_factory("boss", clearance=1, dept_id=parent.id)
    doc = doc_factory(clearance=1, acl_mode="dept", owner_dept_id=child.id)
    ok, _ = can_access(db, user, doc)
    assert ok is True


def test_dept_mode_child_cannot_see_parent_doc(db, dept_factory, user_factory, doc_factory):
    parent = dept_factory("总部")
    child = dept_factory("资管部", parent_id=parent.id)
    user = user_factory("staff", clearance=1, dept_id=child.id)
    doc = doc_factory(clearance=1, acl_mode="dept", owner_dept_id=parent.id)
    ok, _ = can_access(db, user, doc)
    assert ok is False


def test_restrict_mode_without_allow_is_denied(db, user_factory, doc_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "白名单模式" in reason


@pytest.mark.parametrize(
    "subject_type,subject_key_attr",
    [("user", "id"), ("role", "role_name")],
)
def test_restrict_mode_with_allow_grants_access(
    db, user_factory, doc_factory, acl_factory, subject_type, subject_key_attr
):
    user = user_factory("u", clearance=1, roles=["risk"])
    doc = doc_factory(clearance=1, acl_mode="restrict")
    key = user.id if subject_key_attr == "id" else "risk"
    acl_factory(doc.id, subject_type, key, effect="allow")
    ok, reason = can_access(db, user, doc)
    assert ok is True
    assert "显式授权" in reason


def test_restrict_mode_allow_by_dept_in_chain(db, dept_factory, user_factory,
                                              doc_factory, acl_factory):
    dept = dept_factory("研究部")
    user = user_factory("u", clearance=1, dept_id=dept.id)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    acl_factory(doc.id, "dept", dept.id, effect="allow")
    ok, _ = can_access(db, user, doc)
    assert ok is True


def test_explicit_allow_overrides_dept_scope(db, dept_factory, user_factory,
                                             doc_factory, acl_factory):
    """显式授权可越过部门归属限制（policy.accessible_doc_ids 的同款逻辑）。"""
    a = dept_factory("合规部")
    b = dept_factory("投行部")
    user = user_factory("u", clearance=1, dept_id=a.id)
    doc = doc_factory(clearance=1, acl_mode="dept", owner_dept_id=b.id)
    acl_factory(doc.id, "user", user.id, effect="allow")
    ok, reason = can_access(db, user, doc)
    assert (ok, reason) == (True, "显式授权（用户）")


# ---------------------------------------------------------------- deny 优先


def test_deny_beats_allow(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    acl_factory(doc.id, "user", user.id, effect="allow")
    acl_factory(doc.id, "user", user.id, effect="deny")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "显式拒绝" in reason


def test_deny_by_role_hits_role_member(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1, roles=["trader"])
    doc = doc_factory(clearance=1, acl_mode="open")
    acl_factory(doc.id, "role", "trader", effect="deny")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "trader" in reason


def test_deny_by_other_role_does_not_affect_user(db, user_factory, doc_factory,
                                                 acl_factory):
    user = user_factory("u", clearance=1, roles=["trader"])
    doc = doc_factory(clearance=1, acl_mode="open")
    acl_factory(doc.id, "role", "risk", effect="deny")
    ok, _ = can_access(db, user, doc)
    assert ok is True


def test_deny_by_dept_hits_dept_member(db, dept_factory, user_factory, doc_factory,
                                       acl_factory):
    dept = dept_factory("研究部")
    user = user_factory("u", clearance=1, dept_id=dept.id)
    doc = doc_factory(clearance=1, acl_mode="open")
    acl_factory(doc.id, "dept", dept.id, effect="deny")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "部门被显式拒绝" in reason


# ---------------------------------------------------------------- 临时授权到期


def test_expired_allow_is_not_effective(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    acl_factory(doc.id, "user", user.id, effect="allow",
                expires_at=datetime.utcnow() - timedelta(hours=1))
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "白名单模式" in reason


def test_unexpired_allow_is_effective(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    acl_factory(doc.id, "user", user.id, effect="allow",
                expires_at=datetime.utcnow() + timedelta(hours=1))
    ok, _ = can_access(db, user, doc)
    assert ok is True


def test_expired_deny_no_longer_blocks(db, user_factory, doc_factory, acl_factory):
    """到期的临时封禁应自动解除——不需要人工回收。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="open")
    acl_factory(doc.id, "user", user.id, effect="deny",
                expires_at=datetime.utcnow() - timedelta(minutes=1))
    ok, _ = can_access(db, user, doc)
    assert ok is True


def test_no_expiry_means_permanent(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="restrict")
    acl_factory(doc.id, "user", user.id, effect="allow", expires_at=None)
    ok, _ = can_access(db, user, doc)
    assert ok is True


# ---------------------------------------------------------------- SQL 下推


def _visible_ids(db, user):
    return set(db.execute(
        select(Document.id).where(Document.id.in_(accessible_doc_ids(db, user)))
    ).scalars().all())


def test_accessible_doc_ids_filters_by_clearance(db, user_factory, doc_factory):
    user = user_factory("u", clearance=1)
    low = doc_factory("内部", clearance=1, acl_mode="open")
    high = doc_factory("机密", clearance=2, acl_mode="open")
    top = doc_factory("绝密", clearance=3, acl_mode="open")

    ids = _visible_ids(db, user)
    assert low.id in ids
    assert high.id not in ids
    assert top.id not in ids


def test_accessible_doc_ids_requires_ready_status(db, user_factory, doc_factory):
    user = user_factory("u", clearance=1)
    ready = doc_factory("已就绪", clearance=1, acl_mode="open", status="ready")
    draft = doc_factory("处理中", clearance=1, acl_mode="open", status="processing")

    ids = _visible_ids(db, user)
    assert ready.id in ids
    assert draft.id not in ids


def test_accessible_doc_ids_deny_still_wins(db, user_factory, doc_factory, acl_factory):
    user = user_factory("u", clearance=1)
    doc = doc_factory(clearance=1, acl_mode="open")
    acl_factory(doc.id, "user", user.id, effect="deny")
    assert doc.id not in _visible_ids(db, user)


def test_accessible_doc_ids_restrict_needs_allow(db, user_factory, doc_factory,
                                                 acl_factory):
    user = user_factory("u", clearance=1)
    locked = doc_factory("受限", clearance=1, acl_mode="restrict")
    granted = doc_factory("已授权", clearance=1, acl_mode="restrict")
    acl_factory(granted.id, "user", user.id, effect="allow")

    ids = _visible_ids(db, user)
    assert locked.id not in ids
    assert granted.id in ids


def test_accessible_doc_ids_dept_scope(db, dept_factory, user_factory, doc_factory):
    a = dept_factory("合规部")
    b = dept_factory("投行部")
    user = user_factory("u", clearance=1, dept_id=a.id)
    own = doc_factory("本部门", clearance=1, acl_mode="dept", owner_dept_id=a.id)
    other = doc_factory("他部门", clearance=1, acl_mode="dept", owner_dept_id=b.id)

    ids = _visible_ids(db, user)
    assert own.id in ids
    assert other.id not in ids


# ---------------------------------------------------------------- status 闸（B5）


def test_can_access_rejects_non_ready_doc(db, user_factory, doc_factory):
    """B5：非 ready 文档在逐条后置校验同样拒绝——与 accessible_doc_ids 的
    SQL 下推口径对齐，堵住"列表/检索看不到、详情/下载却能拿到"的缝隙。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("处理中", clearance=1, acl_mode="open", status="processing")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert reason == "文档当前不可访问"


def test_can_access_status_gate_does_not_leak_status_value(
        db, user_factory, doc_factory):
    """理由文案不得含状态值：调用方多数统一转 404（存在性不可探测），
    透出"未就绪/已归档"等于把文档生命周期泄露给不该知道的人。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("已归档", clearance=1, acl_mode="open", status="archived")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert "archived" not in reason
    assert "归档" not in reason


def test_can_access_status_gate_precedes_clearance(
        db, user_factory, doc_factory):
    """status 闸是第 0 道（policy.py 判定顺序 0）：低密级用户撞一篇
    高密级非就绪文档，得到的仍是统一的"不可访问"——两个拒绝理由
    不叠加，避免从拒绝话术里反推文档属性。"""
    user = user_factory("u", clearance=0)
    doc = doc_factory("处理中的机密", clearance=3, acl_mode="open",
                      status="processing")
    ok, reason = can_access(db, user, doc)
    assert ok is False
    assert reason == "文档当前不可访问"
