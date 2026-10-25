# SPDX-License-Identifier: Apache-2.0
"""权限变更审批流（P2-9 密级；上线闭环：访问范围 / 显式授权 / 账号权限）。

统一威胁模型：**任何"放宽可见范围"的变更都必须由申请人之外的人复核**。
  · 密级下调              → 更多低密级用户可见
  · acl_mode 放宽          → restrict → dept → open，可见面逐级放大
  · 归属部门改挂           → 另一个部门获得可见性（dept 模式）
  · 新增 allow 显式授权     → 指定用户/部门/角色获得可见性
  · 用户角色/密级/启用状态放宽 → 该账号直接看到更多密级、拿到管理面

反向的"收紧"（升密、改 restrict、加 deny、撤销授权）不产生新的外流，
立即生效——给变严操作也卡审批，只会逼人绕过流程，反而劣化安全。
紧急旁路（APPROVAL_EMERGENCY_BYPASS）供事故处置临时开启。

审批单字段约定（kind）：
  clearance  from/to = 密级数字
  acl        from/to = acl_mode 字符串；payload = {"acl_mode","owner_dept_id"}
  acl_grant  from/to = 展示串；payload = {"subject_type","subject_key","expires_at"}
  user_privilege  from/to = 展示串；payload = {"to_roles","to_clearance",
                  "to_status","to_dept_id","username"}，doc_id = 目标用户 id

双人复核的两条硬规则：申请人不能批自己；审批人密级必须够得上目标文档密级
（密级 1 的账号不该有能力批准开放绝密内容）。用户权限审批额外要求：
审批人本人必须是管理员，且不能是目标账号本人；"最后一名管理员"不可被降权/停用。
"""
import json
from datetime import datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    APPROVAL_EMERGENCY_BYPASS, APPROVAL_UPGRADE_REQUIRED, LEVEL_NAMES,
    ROLES,
)

from .models import ApprovalRequest, DocAcl, Document, User

ACL_MODES = ("open", "dept", "restrict")
# 数值越大可见面越广：用于判断"这次改动是不是在放宽"
ACL_RANK = {"restrict": 0, "dept": 1, "open": 2}
ACL_LABELS = {"open": "全公司可见", "dept": "归属部门可见", "restrict": "仅白名单可见"}
# 安全上等价于 admin 的角色集合（新增任一都需要双人复核）
PRIVILEGED_ROLES = ("admin",)
# 仅管理员本人可授予/剥夺的密级下限（>=2 即机密/绝密）
PRIVILEGED_CLEARANCE = 2
# 所有需要复核的审批类型（供列表/角标聚合使用）
APPROVAL_KINDS = ("clearance", "acl", "acl_grant", "user_privilege")


def level_name(v) -> str:
    """密级值 → 中文名（对外供路由/序列化使用）。"""
    try:
        return LEVEL_NAMES.get(int(v), str(v))
    except Exception:
        return str(v)


_level = level_name


def acl_label(mode) -> str:
    return ACL_LABELS.get(str(mode), str(mode))


def _payload(req: ApprovalRequest) -> dict:
    try:
        data = json.loads(req.payload or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def describe(req: ApprovalRequest) -> tuple[str, str]:
    """审批单的"从 → 到"展示口径（各 kind 语义不同，不能都当密级读）。"""
    if req.kind == "clearance":
        return level_name(req.from_value), level_name(req.to_value)
    if req.kind == "acl":
        return acl_label(req.from_value), acl_label(req.to_value)
    if req.kind == "acl_grant":
        p = _payload(req)
        return "—", f"{p.get('subject_type', '')}:{p.get('subject_key', '')}"
    if req.kind == "user_privilege":
        return req.from_value, req.to_value
    return req.from_value, req.to_value


def summary(req: ApprovalRequest) -> str:
    """审计/通知用的一句话摘要。"""
    frm, to = describe(req)
    if req.kind == "clearance":
        return f"密级变更 {frm} → {to}"
    if req.kind == "acl":
        p = _payload(req)
        return f"访问范围 {frm} → {to}（归属部门 {p.get('owner_dept_id') or '无'}）"
    if req.kind == "acl_grant":
        p = _payload(req)
        exp = p.get("expires_at") or ""
        return f"新增授权 {p.get('subject_type')}:{p.get('subject_key')}" + (
            f"（{exp} 到期）" if exp else "")
    if req.kind == "user_privilege":
        p = _payload(req)
        who = p.get("username") or req.doc_id
        return f"账号权限变更 {who}：{frm} → {to}"
    return f"{req.kind} {frm} → {to}"


def _pending(db: Session, doc_id: str, kind: str) -> ApprovalRequest | None:
    return db.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.doc_id == doc_id,
            ApprovalRequest.kind == kind,
            ApprovalRequest.status == "pending",
        )
    ).scalars().first()


def _new_request(db: Session, subject, kind: str, user: User,
                 from_value: str, to_value: str, payload: dict,
                 reason: str, subject_type: str = "document") -> ApprovalRequest:
    req = ApprovalRequest(
        doc_id=subject.id, subject_type=subject_type, kind=kind,
        # 160 与 models.ApprovalRequest 列宽一致：acl_grant 的展示串是
        # "user:<36 位 UUID>"，按 32 截断会直接把凭据截成半截。
        from_value=str(from_value)[:160], to_value=str(to_value)[:160],
        payload=json.dumps(payload, ensure_ascii=False),
        requester_id=user.id, requester_name=user.username, reason=reason,
    )
    db.add(req)
    return req


def request_clearance_change(
    db: Session, user: User, doc: Document, to_clearance: int,
) -> tuple[ApprovalRequest | None, str]:
    """发起密级变更。返回 (审批单 or None, 说明)。

    None 表示不需要审批、直接生效（升密 / 紧急旁路 / 平级无变化）。
    """
    from_clearance = int(doc.clearance or 0)
    to_clearance = int(to_clearance)
    if to_clearance == from_clearance:
        return None, "密级未变化"

    downgrade = to_clearance < from_clearance
    if not downgrade and not APPROVAL_UPGRADE_REQUIRED:
        doc.clearance = to_clearance
        return None, f"密级提升为「{_level(to_clearance)}」立即生效（变严不产生外流）"
    if APPROVAL_EMERGENCY_BYPASS:
        doc.clearance = to_clearance
        return None, f"紧急旁路开启，密级直接变更为「{_level(to_clearance)}」"

    # 同一文档已有待审批的密级变更单时不重复建单，避免审批队列被刷屏
    pending = _pending(db, doc.id, "clearance")
    if pending:
        return pending, "该文档已有待审批的密级变更单"

    req = _new_request(db, doc, "clearance", user, from_clearance, to_clearance, {},
                       reason=f"密级 {_level(from_clearance)} → {_level(to_clearance)}")
    return req, (f"密级下调为「{_level(to_clearance)}」已提交审批，"
                 f"待他人复核后生效")


def request_acl_change(db: Session, user: User, doc: Document,
                       acl_mode: str | None = None,
                       owner_dept_id: str | None = None,
                       ) -> tuple[ApprovalRequest | None, str]:
    """发起 acl_mode / 归属部门变更。放宽 → 审批；收紧 → 立即生效。"""
    cur_mode = str(doc.acl_mode or "dept")
    to_mode = str(acl_mode) if acl_mode is not None else cur_mode
    if to_mode not in ACL_MODES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"acl_mode 必须是 {'/'.join(ACL_MODES)}")
    cur_dept = doc.owner_dept_id or ""
    to_dept = owner_dept_id if owner_dept_id is not None else cur_dept
    to_dept = (to_dept or "").strip()

    if to_mode == cur_mode and to_dept == cur_dept:
        return None, "访问范围未变化"

    # 可见面放大：模式放宽，或（dept 模式改挂部门 → 新部门获得可见性）。
    # open 模式下的归属部门只是标注字段，不触发审批。
    widening = ACL_RANK[to_mode] > ACL_RANK[cur_mode] or (
        to_mode == "dept" == cur_mode and to_dept != cur_dept)
    if not widening:
        doc.acl_mode, doc.owner_dept_id = to_mode, (to_dept or None)
        return None, f"访问范围收紧为「{acl_label(to_mode)}」立即生效"

    if APPROVAL_EMERGENCY_BYPASS:
        doc.acl_mode, doc.owner_dept_id = to_mode, (to_dept or None)
        return None, f"紧急旁路开启，访问范围直接变更为「{acl_label(to_mode)}」"

    pending = _pending(db, doc.id, "acl")
    if pending:
        return pending, "该文档已有待审批的访问范围变更单"

    req = _new_request(
        db, doc, "acl", user, cur_mode, to_mode,
        {"acl_mode": to_mode, "owner_dept_id": to_dept or None},
        reason=f"访问范围 {acl_label(cur_mode)} → {acl_label(to_mode)}",
    )
    return req, (f"访问范围放宽为「{acl_label(to_mode)}」已提交审批，"
                 f"待他人复核后生效")


def grant_acl(db: Session, user: User, doc: Document, subject_type: str,
              subject_key: str, expires_at: datetime | None,
              ) -> tuple[ApprovalRequest | None, str]:
    """新增 allow 显式授权：走审批单，不直接落库（紧急旁路除外）。"""
    expires_str = expires_at.strftime("%Y-%m-%dT%H:%M:%S") if expires_at else ""
    if APPROVAL_EMERGENCY_BYPASS:
        db.add(DocAcl(doc_id=doc.id, subject_type=subject_type,
                      subject_key=subject_key, effect="allow",
                      expires_at=expires_at,
                      granted_by=f"{user.username}（紧急旁路）"))
        return None, "紧急旁路开启，授权已直接生效"

    payload = {"subject_type": subject_type, "subject_key": subject_key,
               "expires_at": expires_str}
    # 完全相同的授权已待批时不重复建单；不同对象的授权各自建单
    pending = _pending(db, doc.id, "acl_grant")
    if pending and _payload(pending) == payload:
        return pending, "该授权已提交审批，待他人复核后生效"

    req = _new_request(db, doc, "acl_grant", user, "",
                       f"{subject_type}:{subject_key}", payload,
                       reason=f"新增 allow 授权 {subject_type}:{subject_key}")
    return req, (f"新增授权 {subject_type}:{subject_key} 已提交审批，"
                 f"待他人复核后生效")


def _finalize(req: ApprovalRequest, approver: User, reason: str) -> ApprovalRequest:
    req.status = "approved"
    req.approver_id = approver.id
    req.approver_name = approver.username
    req.decided_reason = (reason or "").strip()[:500]
    req.decided_at = datetime.utcnow()
    return req


def _reject_now(req: ApprovalRequest, approver: User, why: str) -> ApprovalRequest:
    req.status = "rejected"
    req.approver_id = approver.id
    req.approver_name = approver.username
    req.decided_reason = why[:500]
    req.decided_at = datetime.utcnow()
    return req


def _apply_acl(db: Session, approver: User, req: ApprovalRequest,
               reason: str) -> None:
    doc = db.get(Document, req.doc_id)
    if doc is None:
        _reject_now(req, approver, "原文档已不存在")
        return
    # 审批人必须能读到目标文档：密级 1 的账号不该批准开放绝密内容
    if int(approver.clearance or 0) < int(doc.clearance or 0):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"审批人密级（{_level(approver.clearance)}）低于文档密级"
            f"（{_level(doc.clearance)}），无权批准该变更")
    p = _payload(req)
    to_mode = str(p.get("acl_mode") or doc.acl_mode)
    if to_mode not in ACL_MODES:
        _reject_now(req, approver, "审批单内容非法")
        return
    doc.acl_mode = to_mode
    doc.owner_dept_id = p.get("owner_dept_id") or None
    _finalize(req, approver, reason)


def _apply_grant(db: Session, approver: User, req: ApprovalRequest,
                 reason: str) -> None:
    doc = db.get(Document, req.doc_id)
    if doc is None:
        _reject_now(req, approver, "原文档已不存在")
        return
    if int(approver.clearance or 0) < int(doc.clearance or 0):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"审批人密级（{_level(approver.clearance)}）低于文档密级"
            f"（{_level(doc.clearance)}），无权批准该授权")
    p = _payload(req)
    subject_type = str(p.get("subject_type") or "")
    subject_key = str(p.get("subject_key") or "")
    if subject_type not in ("user", "dept", "role") or not subject_key:
        _reject_now(req, approver, "审批单内容非法")
        return
    expires_at = None
    if p.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(str(p["expires_at"]))
        except ValueError:
            expires_at = None
        # 到期时间已过的授权落库即无效，直接按失效处理
        if expires_at is not None and expires_at <= datetime.utcnow():
            _reject_now(req, approver, "授权有效期已过")
            return
    db.add(DocAcl(doc_id=req.doc_id, subject_type=subject_type,
                  subject_key=subject_key, effect="allow",
                  expires_at=expires_at,
                  granted_by=f"{req.requester_name}（审批:{approver.username}）"))
    _finalize(req, approver, reason)


# ---------------------------------------------------------------- 账号权限

def _priv_display(roles, clearance, active: bool) -> str:
    role_txt = "+".join(sorted(roles)) or "无角色"
    return (f"{'启用' if active else '停用'} / 密级 {level_name(clearance)}"
            f" / {role_txt}")


def _norm_roles(raw) -> list[str]:
    """规范化角色列表：只保留配置里登记的角色（防越权写任意字符串）。"""
    out = []
    for r in raw or []:
        r = str(r).strip()
        if r in ROLES and r not in out:
            out.append(r)
    return sorted(out)


def privilege_widening(cur_roles: list[str], cur_clearance: int, cur_active: bool,
                       cur_dept: str | None, to_roles: list[str],
                       to_clearance: int, to_active: bool,
                       to_dept: str | None) -> tuple[bool, list[str]]:
    """判断这次账号变更是否**放宽**了权限；返回 (是否放宽, 放宽点列表)。

    放宽的四种形态：新增角色（角色可被文档 ACL 直接引用）、提高密级、
    停用→启用、改挂部门（dept 模式下的可见面跟着变）。收紧（去角色、降密、
    停用）与不变都不算放宽，立即生效。

    例外（很关键）：**同时摘掉 admin 时，新增的普通角色不算放宽**。
    "管理员 → 访客"是净收紧的典型操作（离职降级），按"加一个角色就排队"
    会被误判成放宽，导致撤销管理权必须等审批——正好与安全方向相反。
    反过来"管理员 + 新增风控角色"仍算放宽（没摘 admin，权限面确实扩大）。
    """
    why = []
    added = sorted(set(to_roles) - set(cur_roles))
    dropped_privileged = sorted(
        (set(cur_roles) & set(PRIVILEGED_ROLES)) - set(to_roles))
    if added and not dropped_privileged:
        why.append("新增角色 " + "+".join(added))
    if int(to_clearance) > int(cur_clearance):
        why.append(f"密级 {level_name(cur_clearance)} → {level_name(to_clearance)}")
    if to_active and not cur_active:
        why.append("停用 → 启用")
    if (to_dept or None) != (cur_dept or None):
        why.append(f"归属部门 {cur_dept or '无'} → {to_dept or '无'}")
    return bool(why), why


def admin_ids(db: Session, exclude: str | None = None) -> list[str]:
    """当前**启用中**的管理员 id（用于"最后一名管理员"保护）。"""
    rows = db.execute(select(User.id, User.roles, User.status)).all()
    out = []
    for uid, roles, active in rows:
        if not active or (exclude and uid == exclude):
            continue
        try:
            parsed = json.loads(roles or "[]")
        except Exception:
            parsed = []
        if "admin" in parsed:
            out.append(uid)
    return out


def assert_not_last_admin(db: Session, target: User,
                          to_roles: list[str], to_active: bool) -> None:
    """最后一名启用中的管理员不能被降权/停用：否则管理面永久无人可操作。

    这不是"防攻击"而是"防自锁"：一个管理员把自己的 admin 摘掉，之后再没人
    能批审批单、重置动态口令，只能改库才能救回来。宁可 409 拒绝。
    """
    if "admin" not in target.role_list():
        return
    if "admin" in to_roles and to_active:
        return
    if admin_ids(db, exclude=target.id):
        return
    raise HTTPException(
        status.HTTP_409_CONFLICT,
        "不能移除/停用最后一名启用中的管理员（会导致管理面无人可操作）。"
        "请先授予另一账号 admin 角色。")


def request_user_change(db: Session, requester: User, target: User,
                        to_roles: list[str], to_clearance: int,
                        to_active: bool, to_dept_id: str | None,
                        reason: str = "") -> tuple[ApprovalRequest | None, str]:
    """账号角色/密级/启用状态/部门的变更入口（P0-1：单人不得自行扩权）。

    返回 (待审批单 or None, 说明)。放宽 → 生成审批单并**不改库**；收紧/平级
    → 立即生效（仍过最后一名管理员保护）。这样"撤销权限"不会因为流程慢而
    被拖延——那是安全上唯一必须即时生效的方向。
    """
    cur_roles = sorted(target.role_list())
    to_roles = _norm_roles(to_roles)
    to_clearance = int(to_clearance if to_clearance is not None else target.clearance)
    to_active = bool(to_active)
    to_dept = (to_dept_id or None)
    cur_dept = target.dept_id or None

    if (to_roles == cur_roles
            and to_clearance == int(target.clearance or 0)
            and to_active == bool(target.status)
            and to_dept == cur_dept):
        return None, "账号权限无变化"

    widening, why = privilege_widening(
        cur_roles, int(target.clearance or 0), bool(target.status), cur_dept,
        to_roles, to_clearance, to_active, to_dept)

    if not widening or APPROVAL_EMERGENCY_BYPASS:
        assert_not_last_admin(db, target, to_roles, to_active)
        _write_privileges(target, to_roles, to_clearance, to_active, to_dept)
        tag = "紧急旁路即时生效" if (widening and APPROVAL_EMERGENCY_BYPASS) else "收紧/平级调整立即生效"
        return None, tag + (f"：{'；'.join(why)}" if why else "")

    pending = _pending(db, target.id, "user_privilege")
    if pending:
        return pending, "该账号已有一张待审批的权限变更单，请先处理或等待复核"
    frm = _priv_display(cur_roles, target.clearance, bool(target.status))
    to = _priv_display(to_roles, to_clearance, to_active)
    payload = {
        "username": target.username,
        "to_roles": to_roles, "to_clearance": to_clearance,
        "to_status": to_active, "to_dept_id": to_dept,
        "from_roles": cur_roles, "from_clearance": int(target.clearance or 0),
        "from_status": bool(target.status), "from_dept_id": cur_dept,
        "widening": why,
    }
    req = _new_request(db, target, "user_privilege", requester, frm, to,
                       payload, reason or "账号权限放宽（需双人复核）",
                       subject_type="user")
    return req, f"权限放宽（{'；'.join(why)}）已提交审批，待他人复核后生效"


def _write_privileges(target: User, roles: list[str], clearance: int,
                      active: bool, dept_id: str | None) -> None:
    target.roles = json.dumps(sorted(set(roles)), ensure_ascii=False)
    target.clearance = int(clearance)
    target.status = bool(active)
    target.dept_id = dept_id or None


def grant_privileges_now(db: Session, requester: User, target: User,
                         to_roles: list[str], to_clearance: int,
                         to_active: bool, to_dept_id: str | None,
                         reason: str) -> None:
    """建号时的一次性授权（新建账号还不存在"放宽"，等价于首次授予）。

    仍受最后一名管理员保护与角色白名单约束；并写一条 user_privilege 审批单
    作为**已批准**记录，使"谁在什么时候给了这个账号绝密"在审批中心可追溯。
    """
    to_roles = _norm_roles(to_roles)
    assert_not_last_admin(db, target, to_roles, to_active)
    _write_privileges(target, to_roles, to_clearance, to_active, to_dept_id)
    req = _new_request(
        db, target, "user_privilege", requester,
        "（新账号）", _priv_display(to_roles, to_clearance, to_active),
        {"username": target.username, "to_roles": to_roles,
         "to_clearance": int(to_clearance), "to_status": bool(to_active),
         "to_dept_id": to_dept_id, "initial": True},
        reason, subject_type="user")
    # 建号本身是申请人的动作，不能算"他自己批了"；因此审批人留空并把状态
    # 标成 approved 会削弱双人语义，这里改用 granted：记录"由谁直接授予"，
    # 便于审计；权限是否合规由建号流程本身（仅管理员可建号）保证。
    req.status = "granted"
    req.approver_id = requester.id
    req.approver_name = requester.username
    req.decided_reason = (reason or "")[:500]
    req.decided_at = datetime.utcnow()


def _apply_user_privilege(db: Session, approver: User, req: ApprovalRequest,
                          reason: str) -> None:
    target = db.get(User, req.doc_id)
    if target is None:
        _reject_now(req, approver, "目标账号已不存在")
        return
    p = _payload(req)
    to_roles = _norm_roles(p.get("to_roles"))
    try:
        to_clearance = int(p.get("to_clearance", target.clearance))
    except (TypeError, ValueError):
        _reject_now(req, approver, "审批单内容非法")
        return
    to_active = bool(p.get("to_status", target.status))
    to_dept = p.get("to_dept_id") or None
    # 目标账号本人不能是审批人（自己批自己），先于密级判定：语义更准确，
    # 且避免"密级不足"掩盖真正的越权意图。
    if target.id == approver.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "不能审批自己的账号权限变更")
    if int(approver.clearance or 0) < to_clearance:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"审批人密级（{_level(approver.clearance)}）低于目标密级"
            f"（{_level(to_clearance)}），无权批准该账号授权")
    assert_not_last_admin(db, target, to_roles, to_active)
    was_active = bool(target.status)
    _write_privileges(target, to_roles, to_clearance, to_active, to_dept)
    if was_active and not to_active:
        # 停用即断线：换代次让既有令牌立刻失效，并吊销会话表行
        target.token_version = int(target.token_version or 0) + 1
        try:
            from .security import revoke_user_sessions
            revoke_user_sessions(db, target.id, reason="account_disabled")
        except Exception:  # noqa: BLE001 - 吊销失败不该让审批决定丢失
            pass
    _finalize(req, approver, reason)


def decide(db: Session, approver: User, req_id: str, approve: bool,
           reason: str = "") -> ApprovalRequest:
    """审批决定：通过则落变更，拒绝则必须写理由。

    取单必须加行锁：多 worker 下两个管理员同时点"通过"时，若只做
    `status != pending` 的应用层判断，两个事务都能读到 pending 并各自
    落一次变更（重复授权/重复改密级，且两条审批结果互相覆盖）。
    `with_for_update` 把第二个请求串行化，它读到的已是 committed 的终态。
    """
    req = db.get(ApprovalRequest, req_id, with_for_update=True)
    if req is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "审批单不存在")
    if req.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"该审批单已{req.status}，不可重复处理")

    # 双人复核的核心：不能自己批自己，否则审批流等于没有
    if req.requester_id and req.requester_id == approver.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "申请人不能审批自己提交的变更申请")

    if not approve:
        if not (reason or "").strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "拒绝必须填写理由")
        return _reject_now(req, approver, reason.strip())

    if req.kind == "clearance":
        to_clearance = int(req.to_value)
        if int(approver.clearance or 0) < to_clearance:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"审批人密级（{_level(approver.clearance)}）低于目标密级"
                f"（{_level(to_clearance)}），无权批准该变更")
        doc = db.get(Document, req.doc_id)
        if doc is None:
            return _reject_now(req, approver, "原文档已不存在")
        doc.clearance = to_clearance
        return _finalize(req, approver, reason)
    if req.kind == "acl":
        _apply_acl(db, approver, req, reason)
        return req
    if req.kind == "acl_grant":
        _apply_grant(db, approver, req, reason)
        return req
    if req.kind == "user_privilege":
        _apply_user_privilege(db, approver, req, reason)
        return req
    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"未知审批类型：{req.kind}")


def pending_doc_ids(db: Session) -> set[str]:
    """有待审批变更单的文档 id 集合（供列表接口打"审批中"标记）。"""
    rows = db.execute(
        select(ApprovalRequest.doc_id).where(
            ApprovalRequest.kind.in_(APPROVAL_KINDS),
            ApprovalRequest.status == "pending",
        )
    ).scalars().all()
    return set(rows)
