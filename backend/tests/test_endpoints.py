# SPDX-License-Identifier: AGPL-3.0-only
"""routers/admin.py / routers/docs.py 的端点守卫（此前端点级零覆盖）。

组件逻辑各自有单测，但"谁能调这个端点"此前没人验过——而权限判断恰好写在
路由层（require_admin / 角色白名单 / can_access / 密级门槛），漏一处就是
一处可直接利用的口子。本文件按事故严重度排序：

  1. /approvals/*  降密审批被绕过 = 不可逆的信息外流（最高）
  2. /audit/verify 防篡改校验被非管理员触发/查看
  3. /{doc_id}/versions 版本链对无权用户泄漏元数据
  4. /departments、/users、reset-risk 越权改权限 / 抹掉风险分
  5. /{doc_id}/pii、reingest 越权读取 / 低密改写高密正文

断言口径按"非管理员/无权用户必须被挡住"写，而不是只测正常返回。
"""
import pytest
from fastapi.testclient import TestClient

from app.audit import flush_audit
from app.main import app as real_app
from app.models import ApprovalRequest, AuditLog, DocAcl, Document, User, new_id
from app.security import create_token

ADMIN = "/api/v1/admin"
DOCS = "/api/v1/docs"


# ------------------------------------------------------------------ 夹具


@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username, clearance=1, roles="[]"):
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=roles, pwd_hash="x", salt="y",
             status=True)
    db.add(u)
    db.commit()
    return u


def _mk_doc(db, title="测试文档", clearance=1, acl_mode="open",
            created_by="someone"):
    d = Document(id=new_id(), title=title, clearance=clearance,
                 acl_mode=acl_mode, status="ready", doc_type="txt",
                 created_by=created_by)
    db.add(d)
    db.commit()
    return d


def _mk_approval(db, doc, requester, from_value="3", to_value="1"):
    req = ApprovalRequest(
        id=new_id(), doc_id=doc.id, kind="clearance",
        from_value=from_value, to_value=to_value,
        requester_id=requester.id, requester_name=requester.username,
        status="pending",
    )
    db.add(req)
    db.commit()
    return req


def _auth(u):
    return {"Authorization": f"Bearer {create_token(u)}"}


def _last_audit(db, action):
    flush_audit(timeout=2.0)
    rows = db.query(AuditLog).filter(AuditLog.action == action).all()
    return rows[-1] if rows else None


# ------------------------------------------------------------------ 1. 降密审批


def test_approvals_list_requires_admin(db, client):
    """防：任何人都能看到降密审批队列（可据此挑软目标、踩审批节奏）。"""
    user = _mk_user(db, "u1", clearance=1)
    assert client.get(f"{ADMIN}/approvals", headers=_auth(user)).status_code == 403


def test_approvals_list_visible_to_admin(db, client):
    """防：管理员看不到待办，降密单永远没人复核（流程空转）。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    _mk_approval(db, doc, _mk_user(db, "requester", clearance=3))

    r = client.get(f"{ADMIN}/approvals", headers=_auth(admin))

    assert r.status_code == 200
    assert r.json()[0]["doc_id"] == doc.id


def test_approve_requires_admin(db, client):
    """防：非管理员自己批准自己的降密单——权限体系一步瓦解。"""
    user = _mk_user(db, "u1", clearance=3)
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, _mk_user(db, "requester", clearance=3))

    r = client.post(f"{ADMIN}/approvals/{req.id}/approve", json={},
                    headers=_auth(user))

    assert r.status_code == 403


def test_requester_cannot_approve_own_request(db, client):
    """防：双人复核被自批绕过——审批流形同虚设。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, admin)  # 申请人 = 审批人

    r = client.post(f"{ADMIN}/approvals/{req.id}/approve", json={},
                    headers=_auth(admin))

    assert r.status_code == 403


def test_approver_clearance_must_cover_target(db, client):
    """防：密级 1 的管理员批准把绝密文档开放出去（越权放行外流）。"""
    low_admin = _mk_user(db, "admin_low", clearance=1, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, _mk_user(db, "requester", clearance=3),
                       from_value="3", to_value="2")

    r = client.post(f"{ADMIN}/approvals/{req.id}/approve", json={},
                    headers=_auth(low_admin))

    assert r.status_code == 403
    db.refresh(doc)
    assert doc.clearance == 3, "审批被拒，文档密级不得变动"


def test_approve_applies_downgrade_and_audits(db, client):
    """防：批准生效却不留痕——事后无法回答"谁把绝密放成内部"。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, _mk_user(db, "requester", clearance=3),
                       from_value="3", to_value="1")

    r = client.post(f"{ADMIN}/approvals/{req.id}/approve",
                    json={"reason": "已过保密期"}, headers=_auth(admin))

    assert r.status_code == 200
    db.refresh(doc)
    assert doc.clearance == 1
    log = _last_audit(db, "approval")
    assert log is not None and log.decision == "allow"
    assert doc.title in log.target_label


def test_reject_requires_reason(db, client):
    """防：驳回不写理由——审批流变成没有责任的橡皮图章。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, _mk_user(db, "requester", clearance=3))

    r = client.post(f"{ADMIN}/approvals/{req.id}/reject", json={},
                    headers=_auth(admin))

    assert r.status_code == 400


def test_reject_keeps_clearance_and_audits(db, client):
    """防：驳回后文档密级仍被改动（审批结果不一致）。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, clearance=3)
    req = _mk_approval(db, doc, _mk_user(db, "requester", clearance=3),
                       from_value="3", to_value="1")

    r = client.post(f"{ADMIN}/approvals/{req.id}/reject",
                    json={"reason": "仍在保密期内"}, headers=_auth(admin))

    assert r.status_code == 200
    assert r.json()["status"] == "rejected"
    db.refresh(doc)
    assert doc.clearance == 3
    assert _last_audit(db, "approval").decision == "deny"


# ------------------------------------------------------------------ 2. 防篡改校验


def test_audit_verify_requires_admin(db, client):
    """防：非管理员触发/读取审计链校验结果（可据此定位被删记录的位置）。"""
    user = _mk_user(db, "u1", clearance=1)
    assert client.get(f"{ADMIN}/audit/verify", headers=_auth(user)).status_code == 403


def test_audit_verify_ok_for_admin(db, client):
    """防：管理员无法执行链校验——审计防篡改的合规底线没人能验证。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    r = client.get(f"{ADMIN}/audit/verify", headers=_auth(admin))
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_audit_list_requires_admin_or_compliance(db, client):
    """防：普通用户读全量审计日志（含他人查询内容与被拦截记录）。"""
    user = _mk_user(db, "u1", clearance=1, roles='["research"]')
    assert client.get(f"{ADMIN}/audit", headers=_auth(user)).status_code == 403


def test_audit_list_visible_to_compliance(db, client):
    """防：合规角色看不了审计日志，合规复核只能求人导出。"""
    compliance = _mk_user(db, "comp1", clearance=2, roles='["compliance"]')
    r = client.get(f"{ADMIN}/audit", headers=_auth(compliance))
    assert r.status_code == 200


# ------------------------------------------------------------------ 3. 版本追溯


def test_versions_hidden_from_unauthorized_user(db, client):
    """防：无权用户靠版本链元数据反推文档存在与变更节奏。

    存在性不可探测：无权与不存在必须同形（404），否则等于给拼图攻击
    提供"这篇文档存在且刚被改过"的信号。
    """
    outsider = _mk_user(db, "outsider", clearance=1)
    doc = _mk_doc(db, title="绝密并购清单", clearance=3, acl_mode="restrict")

    r = client.get(f"{DOCS}/{doc.id}/versions", headers=_auth(outsider))

    assert r.status_code == 404, "无权必须表现为 404，与「不存在」同形"
    assert "绝密并购清单" not in r.text


def test_versions_visible_to_authorized_user(db, client):
    """防：有权用户看不到版本链，无法回答"当时看到的是哪一版"。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, title="风控手册", clearance=1, acl_mode="open")

    r = client.get(f"{DOCS}/{doc.id}/versions", headers=_auth(user))

    assert r.status_code == 200
    assert r.json()["doc_id"] == doc.id


# ------------------------------------------------------------------ 4. 权限与风险分


def test_departments_require_admin(db, client):
    """防：非管理员遍历部门树（组织架构本身就是敏感信息）。"""
    user = _mk_user(db, "u1", clearance=1)
    assert client.get(f"{ADMIN}/departments", headers=_auth(user)).status_code == 403


def test_users_require_admin(db, client):
    """防：非管理员拉全量用户名单与密级（定向攻击的名单）。"""
    user = _mk_user(db, "u1", clearance=1)
    assert client.get(f"{ADMIN}/users", headers=_auth(user)).status_code == 403


def test_reset_risk_requires_admin(db, client):
    """防：被限流的账号自己把风险分清零——防拼图的长周期闸直接失效。"""
    attacker = _mk_user(db, "attacker", clearance=1)
    r = client.post(f"{ADMIN}/users/{attacker.id}/reset-risk",
                    headers=_auth(attacker))
    assert r.status_code == 403


def test_reset_risk_by_admin_is_audited(db, client):
    """防：人工复位风险分不留痕——成了绕过审计的后门。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    target = _mk_user(db, "target", clearance=1)
    target.risk_score = 5
    db.commit()

    r = client.post(f"{ADMIN}/users/{target.id}/reset-risk", headers=_auth(admin))

    assert r.status_code == 200
    assert r.json()["risk_score"] == 0
    assert r.json()["risk_before"] == 5
    db.refresh(target)
    assert target.risk_score == 0
    log = _last_audit(db, "admin")
    assert log is not None and "复位风险分" in log.reason


# ------------------------------------------------------------------ 5. PII 与正文替换


def test_pii_report_hidden_from_unauthorized_user(db, client):
    """防：无权用户借 PII 报告接口读到文档含哪些敏感字段。"""
    outsider = _mk_user(db, "outsider", clearance=1)
    doc = _mk_doc(db, title="绝密客户资料", clearance=3, acl_mode="restrict")

    r = client.get(f"{DOCS}/{doc.id}/pii", headers=_auth(outsider))

    assert r.status_code == 404
    assert "绝密客户资料" not in r.text


def test_pii_report_visible_to_authorized_user(db, client):
    """防：文档负责人看不到 PII 报告，无法自查合规风险。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, title="客户资料", clearance=1, acl_mode="open")

    r = client.get(f"{DOCS}/{doc.id}/pii", headers=_auth(user))

    assert r.status_code == 200


def test_reingest_rejected_for_user_below_doc_clearance(db, client):
    """防：低密账号借"更新正文"改写高密文档——绕开创建时的密级检查。

    admin 同样受限：管理员是"能管权限"，不是"能读一切"。
    """
    low_admin = _mk_user(db, "admin_low", clearance=1, roles='["admin"]')
    doc = _mk_doc(db, title="绝密并购方案", clearance=3, acl_mode="open")

    r = client.post(f"{DOCS}/{doc.id}/reingest", data={"content": "篡改内容"},
                    headers=_auth(low_admin))

    assert r.status_code == 403


def test_reingest_allowed_for_user_at_doc_clearance(db, client):
    """防：密级够的人反而被误拦，正常的内容订正走不通。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, title="风控手册", clearance=1, acl_mode="open")

    r = client.post(f"{DOCS}/{doc.id}/reingest",
                    data={"content": "更新后的正文内容，用于覆盖旧版本。"},
                    headers=_auth(user))

    assert r.status_code == 200


# ------------------------------------------------- 6. /stats 态势信息分级

# 运行模式三项：所有登录用户都要（前端聊天页侧栏依赖，见 Chat.vue）
_MODES = ("storage", "llm_mode", "embed_mode")
# 全库计数：仅管理员/合规可见，其余角色一律 None
_COUNTS = ("docs", "chunks", "users", "audits", "denied_7d", "throttled_7d",
           "jigsaw_risk", "blocked_7d")


def _seed_counts(db, audit_factory):
    """造出可辨识的真实计数：3 篇文档 / 2 个普通用户 / 2 条被拦审计。

    没有真实计数，"响应里不得出现计数"就是一条空断言——这里保证一旦
    分级失效，payload 里必然出现非 None 的整数。
    """
    from datetime import datetime

    for i in range(3):
        _mk_doc(db, title=f"统计样本{i}", clearance=1, acl_mode="open")
    _mk_user(db, "counter_a", clearance=1)
    _mk_user(db, "counter_b", clearance=1)
    for _ in range(2):
        audit_factory(ts=datetime.utcnow(), action="search", decision="deny")
    db.commit()


def test_stats_numbers_are_none_for_normal_user(db, client, audit_factory):
    """防：全库拦截/限流/阻断计数外泄给普通用户（探测是否已被发现的态势信号）。

    逐个字段断言而非只挑一个——漏字段是这类"分级返回"最典型的回归方式。
    值必须是 None 而不是 0：0 会被读成"没有拦截"，是假的安全感。
    """
    user = _mk_user(db, "u1", clearance=1, roles='["research"]')
    _seed_counts(db, audit_factory)

    r = client.get(f"{ADMIN}/stats", headers=_auth(user))

    # 分级方案（不是门禁方案）：端点必须对普通用户保持可用，否则聊天页
    # 侧栏静默变空 = 功能回退（Chat.vue 是 catch 吞错的，不会报错）。
    assert r.status_code == 200
    data = r.json()
    for f in _MODES:
        assert data[f], f"{f} 必须仍对普通用户可见（侧栏依赖）"
    for f in _COUNTS:
        assert data[f] is None, f"{f} 必须对普通用户为 None，不得回退成 0"


def test_stats_response_carries_no_real_number_for_normal_user(db, client,
                                                               audit_factory):
    """防：用"字段改名"绕过逐字段断言（改个名就不在清单里了）。

    不看字段名，直接扫 payload 里有没有整数值——新增/改名泄漏都能兜住。
    """
    user = _mk_user(db, "u1", clearance=1, roles='["guest"]')
    _seed_counts(db, audit_factory)
    assert db.query(Document).count() >= 3, "本条前提：库里确有可泄漏的真实计数"

    r = client.get(f"{ADMIN}/stats", headers=_auth(user))

    data = r.json()
    leaked = {k: v for k, v in data.items() if isinstance(v, int)}
    assert leaked == {}, f"普通用户不应拿到任何计数字段，实际：{leaked}"


def test_stats_full_numbers_for_admin(db, client, audit_factory):
    """防：分级过严——管理员自己看不到库规模与拦截态势，运维瞎掉。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    _seed_counts(db, audit_factory)

    r = client.get(f"{ADMIN}/stats", headers=_auth(admin))

    assert r.status_code == 200
    data = r.json()
    for f in _COUNTS:
        assert isinstance(data[f], int) and data[f] >= 0, (
            f"{f} 应对管理员返回非负整数，实际 {data[f]!r}")
    assert data["docs"] >= 3
    assert data["users"] >= 3      # 两个样本用户 + admin 自己
    assert data["denied_7d"] >= 2  # 造进去的两条被拦审计


def test_stats_full_numbers_for_compliance(db, client, audit_factory):
    """防：只给 admin 开全量、漏掉 compliance——合规角色反而看不了态势。"""
    compliance = _mk_user(db, "comp1", clearance=2, roles='["compliance"]')
    _seed_counts(db, audit_factory)

    r = client.get(f"{ADMIN}/stats", headers=_auth(compliance))

    assert r.status_code == 200
    data = r.json()
    for f in _COUNTS:
        assert isinstance(data[f], int) and data[f] >= 0, (
            f"{f} 应对合规角色返回非负整数，实际 {data[f]!r}")
    assert data["docs"] >= 3
    assert data["denied_7d"] >= 2


# ------------------------------------------------------------------ 6. 访问范围审批
#
# 闭环项：acl_mode / 归属部门 / allow 授权都是"放宽可见面"，和降密同级，
# 必须二次复核。此前 PATCH 直接落库、POST /acl 直接建行——上传人一个人
# 就能把「仅白名单可见」改成「全公司可见」，审批流形同虚设。


def _mk_admin(db, username="root"):
    return _mk_user(db, username, clearance=3, roles='["admin"]')


def test_acl_widening_requires_approval(db, client):
    """restrict → open 必须走审批，且审批通过前文档元数据不得变化。"""
    owner = _mk_user(db, "owner1", clearance=2)
    doc = _mk_doc(db, title="白名单文档", clearance=2, acl_mode="restrict",
                  created_by="owner1")

    r = client.patch(f"{DOCS}/{doc.id}", json={"acl_mode": "open"}, headers=_auth(owner))

    assert r.status_code == 202
    body = r.json()
    assert body.get("acl_approval_id")
    assert db.get(Document, doc.id).acl_mode == "restrict"   # 未生效
    req = db.get(ApprovalRequest, body["acl_approval_id"])
    assert req.kind == "acl"
    assert req.status == "pending"
    assert req.from_value == "restrict" and req.to_value == "open"


def test_acl_narrowing_applies_immediately(db, client):
    """反向不能卡：open → restrict 是收紧，立即生效，否则止血要等审批。"""
    owner = _mk_user(db, "owner2", clearance=2)
    doc = _mk_doc(db, title="公开文档", clearance=2, acl_mode="open",
                  created_by="owner2")

    r = client.patch(f"{DOCS}/{doc.id}", json={"acl_mode": "restrict"},
                     headers=_auth(owner))

    assert r.status_code == 200
    db.expire_all()   # 断言前丢弃本会话的身份映射缓存，读库里的真实值
    assert db.get(Document, doc.id).acl_mode == "restrict"
    assert db.query(ApprovalRequest).filter(
        ApprovalRequest.doc_id == doc.id).count() == 0


def test_dept_mode_switch_requires_approval(db, client):
    """dept 模式改挂部门 = 另一个部门获得可见性，同样属于放宽。"""
    owner = _mk_user(db, "owner3", clearance=2)
    doc = _mk_doc(db, title="部门文档", clearance=2, acl_mode="dept",
                  created_by="owner3")

    r = client.patch(f"{DOCS}/{doc.id}", json={"owner_dept_id": "dept-b"},
                     headers=_auth(owner))

    assert r.status_code == 202
    assert db.get(Document, doc.id).owner_dept_id is None


def test_approve_acl_change_applies_it(db, client):
    """审批通过后才真正改可见范围，并留下审批人与理由。"""
    owner = _mk_user(db, "owner4", clearance=2)
    admin = _mk_admin(db, "root4")
    doc = _mk_doc(db, title="待放开文档", clearance=1, acl_mode="restrict",
                  created_by="owner4")
    r = client.patch(f"{DOCS}/{doc.id}", json={"acl_mode": "open"}, headers=_auth(owner))
    aid = r.json()["acl_approval_id"]

    ok = client.post(f"{ADMIN}/approvals/{aid}/approve", json={"reason": "业务需要"},
                     headers=_auth(admin))

    assert ok.status_code == 200
    db.expire_all()
    assert db.get(Document, doc.id).acl_mode == "open"
    req = db.get(ApprovalRequest, aid)
    assert req.status == "approved" and req.approver_name == "root4"


def test_acl_change_cannot_be_self_approved(db, client):
    """申请人不能批自己——否则这条审批流只是多一次点击。"""
    owner = _mk_user(db, "owner5", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, title="自批文档", clearance=1, acl_mode="restrict",
                  created_by="owner5")
    r = client.patch(f"{DOCS}/{doc.id}", json={"acl_mode": "open"}, headers=_auth(owner))
    aid = r.json()["acl_approval_id"]

    r2 = client.post(f"{ADMIN}/approvals/{aid}/approve", json={},
                     headers=_auth(owner))

    assert r2.status_code == 403
    assert db.get(Document, doc.id).acl_mode == "restrict"


def test_allow_grant_requires_approval_deny_is_immediate(db, client):
    """allow 授权走审批；deny 是收紧，立即落库。"""
    owner = _mk_user(db, "owner6", clearance=2)
    doc = _mk_doc(db, title="授权文档", clearance=2, acl_mode="restrict",
                  created_by="owner6")

    allow = client.post(f"{DOCS}/{doc.id}/acl",
                        json={"subject_type": "dept", "subject_key": "dept-x",
                              "effect": "allow"}, headers=_auth(owner))
    assert allow.status_code == 202
    assert db.query(DocAcl).filter(DocAcl.doc_id == doc.id).count() == 0

    deny = client.post(f"{DOCS}/{doc.id}/acl",
                       json={"subject_type": "dept", "subject_key": "dept-y",
                             "effect": "deny"}, headers=_auth(owner))
    assert deny.status_code in (200, 201)
    assert db.query(DocAcl).filter(DocAcl.doc_id == doc.id,
                                   DocAcl.effect == "deny").count() == 1


def test_approve_grant_creates_acl_row(db, client):
    """批准授权后必须真的多出一条 allow 记录，否则审批通过等于空转。"""
    owner = _mk_user(db, "owner7", clearance=2)
    admin = _mk_admin(db, "root7")
    doc = _mk_doc(db, title="授权落库文档", clearance=1, acl_mode="restrict",
                  created_by="owner7")
    r = client.post(f"{DOCS}/{doc.id}/acl",
                    json={"subject_type": "user", "subject_key": "alice",
                          "effect": "allow", "expires_hours": 24},
                    headers=_auth(owner))
    aid = r.json()["approval_id"]

    ok = client.post(f"{ADMIN}/approvals/{aid}/approve", json={},
                     headers=_auth(admin))

    assert ok.status_code == 200
    rows = db.query(DocAcl).filter(DocAcl.doc_id == doc.id).all()
    assert len(rows) == 1
    assert rows[0].subject_type == "user" and rows[0].subject_key == "alice"
    assert rows[0].effect == "allow" and rows[0].expires_at is not None


def test_owner_who_lost_access_cannot_edit_or_grant(db, client):
    """上传人失去访问权后（文档被升密）不得继续改元数据/授权。"""
    owner = _mk_user(db, "owner8", clearance=1)
    doc = _mk_doc(db, title="已升密文档", clearance=3, acl_mode="restrict",
                  created_by="owner8")

    patch = client.patch(f"{DOCS}/{doc.id}", json={"title": "改名"},
                         headers=_auth(owner))
    grant = client.post(f"{DOCS}/{doc.id}/acl",
                        json={"subject_type": "user", "subject_key": "owner8",
                              "effect": "allow"}, headers=_auth(owner))

    assert patch.status_code == 404
    assert grant.status_code == 404
    assert db.get(Document, doc.id).title == "已升密文档"


def test_approver_clearance_must_cover_acl_target(db, client):
    """密级 1 的管理员不能批准开放密级 3 文档的访问范围。"""
    owner = _mk_user(db, "owner9", clearance=3)
    low_admin = _mk_user(db, "root9", clearance=1, roles='["admin"]')
    doc = _mk_doc(db, title="绝密文档", clearance=3, acl_mode="restrict",
                  created_by="owner9")
    r = client.patch(f"{DOCS}/{doc.id}", json={"acl_mode": "open"}, headers=_auth(owner))
    aid = r.json()["acl_approval_id"]

    r2 = client.post(f"{ADMIN}/approvals/{aid}/approve", json={},
                     headers=_auth(low_admin))

    assert r2.status_code == 403
    assert db.get(Document, doc.id).acl_mode == "restrict"
