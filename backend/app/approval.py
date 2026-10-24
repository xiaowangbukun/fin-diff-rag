# SPDX-License-Identifier: Apache-2.0
"""权限变更审批流（P2-9 密级；上线闭环：访问范围 / 显式授权）。

统一威胁模型：**任何"放宽可见范围"的变更都必须由申请人之外的人复核**。
  · 密级下调              → 更多低密级用户可见
  · acl_mode 放宽          → restrict → dept → open，可见面逐级放大
  · 归属部门改挂           → 另一个部门获得可见性（dept 模式）
  · 新增 allow 显式授权     → 指定用户/部门/角色获得可见性

反向的"收紧"（升密、改 restrict、加 deny、撤销授权）不产生新的外流，
立即生效——给变严操作也卡审批，只会逼人绕过流程，反而劣化安全。
紧急旁路（APPROVAL_EMERGENCY_BYPASS）供事故处置临时开启。

审批单字段约定（kind）：
  clearance  from/to = 密级数字
  acl        from/to = acl_mode 字符串；payload = {"acl_mode","owner_dept_id"}
  acl_grant  from/to = 展示串；payload = {"subject_type","subject_key","expires_at"}

双人复核的两条硬规则：申请人不能批自己；审批人密级必须够得上目标文档密级
（密级 1 的账号不该有能力批准开放绝密内容）。
"""
import json
from datetime import datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    APPROVAL_EMERGENCY_BYPASS, APPROVAL_UPGRADE_REQUIRED, LEVEL_NAMES,
)

from .models import ApprovalRequest, DocAcl, Document, User

ACL_MODES = ("open", "dept", "restrict")
# 数值越大可见面越广：用于判断"这次改动是不是在放宽"
ACL_RANK = {"restrict": 0, "dept": 1, "open": 2}
ACL_LABELS = {"open": "全公司可见", "dept": "归属部门可见", "restrict": "仅白名单可见"}
# 所有需要复核的审批类型（供列表/角标聚合使用）
APPROVAL_KINDS = ("clearance", "acl", "acl_grant")


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
    return f"{req.kind} {frm} → {to}"


def _pending(db: Session, doc_id: str, kind: str) -> ApprovalRequest | None:
    return db.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.doc_id == doc_id,
            ApprovalRequest.kind == kind,
            ApprovalRequest.status == "pending",
        )
    ).scalars().first()


def _new_request(db: Session, doc: Document, kind: str, user: User,
                 from_value: str, to_value: str, payload: dict,
                 reason: str) -> ApprovalRequest:
    req = ApprovalRequest(
        doc_id=doc.id, kind=kind,
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


def decide(db: Session, approver: User, req_id: str, approve: bool,
           reason: str = "") -> ApprovalRequest:
    """审批决定：通过则落变更，拒绝则必须写理由。"""
    req = db.get(ApprovalRequest, req_id)
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
