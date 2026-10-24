# SPDX-License-Identifier: Apache-2.0
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..approval import (
    decide, describe as approval_describe, summary as approval_summary,
)
from ..audit import write_log
from ..config import ROLES
from ..db import get_db
from ..embed import embedder
from ..models import ApprovalRequest, AuditLog, Chunk, Department, Document, User
from ..recovery import remaining as recovery_remaining
from ..schemas import StatsOut
from ..policy import invalidate_dept_cache
from ..security import current_user, hash_password, require_admin
from ..serializers import user_out
from .auth import client_ip

router = APIRouter(prefix="/admin", tags=["管理与审计"])


class UserIn(BaseModel):
    # username 格式 + 长度：空用户名曾经能过唯一约束且可登录（admin.py 旧代码
    # 只 strip 不校验）；超 64 字符在 PG 侧是 DataError 500。\w 走 unicode，
    # 兼容中文名；业务上不放行空白/控制字符。
    username: str = Field(min_length=3, max_length=64, pattern=r"^[\w.\-@]{3,64}$")
    password: str = ""
    display_name: str = Field(default="", max_length=64)
    dept_id: str | None = None
    roles: list[str] = []
    clearance: int = Field(default=1, ge=0, le=3)
    status: bool = True

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v: str) -> str:
        # 留空 = 走默认初始口令（兼容既有建号流程，见 create_user）；
        # 非空必须 ≥8 位——否则管理员能建出 1 字符口令的账号，
        # 在线爆破成本趋近于零（#11 的口径强度下限）。
        if v and len(v) < 8:
            raise ValueError("口令至少 8 位（留空则使用默认初始口令）")
        return v


class DeptIn(BaseModel):
    name: str
    parent_id: str | None = None


def _assert_roles(roles: list[str]):
    bad = [r for r in roles if r not in ROLES]
    if bad:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"非法角色：{','.join(bad)}")


@router.get("/users")
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    return [user_out(db, u) for u in users]


@router.post("/users", status_code=201)
def create_user(body: UserIn, request: Request,
                _: User = Depends(require_admin), db: Session = Depends(get_db)):
    _assert_roles(body.roles)
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "用户名已存在")
    pwd_hash, salt = hash_password(body.password or "Fin@123456")
    u = User(
        username=body.username.strip(), display_name=body.display_name or body.username,
        dept_id=body.dept_id or None, roles=json.dumps(body.roles, ensure_ascii=False),
        clearance=body.clearance, pwd_hash=pwd_hash, salt=salt, status=body.status,
        # 管理员知道初始口令 = 该口令不算用户私有凭证：首次登录必须换掉，
        # 否则管理员永远持有每个员工账号的可用口令（审计上不可辩护）。
        must_change_password=True,
    )
    db.add(u)
    db.commit()
    write_log(db, user=_, action="create_user", target_id=u.id, target_label=u.username,
              reason=(f"密级{body.clearance} 角色{','.join(body.roles) or '-'}"
                      "；首次登录须修改初始口令"),
              ip=client_ip(request))
    return user_out(db, u)


@router.post("/users/{uid}/mfa-reset")
def reset_mfa(uid: str, request: Request,
              admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """管理员重置某账号的动态口令（手机丢失/换机/密钥无法解密时的唯一出口）。

    与重置口令同一口径：清空密钥 + 换会话代次（踢掉旧会话），并留痕。
    若开了 MFA_ENFORCE_ADMIN/ALL，该用户下次登录会被要求重新绑定。
    """
    u = db.get(User, uid)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    had = bool(u.totp_confirmed_at)
    dropped = recovery_remaining(u.recovery_codes)
    u.totp_secret = ""
    u.totp_confirmed_at = None
    u.totp_last_step = 0
    # 恢复码是第二因子的替代凭证：重置必须连它一起清，否则旧码还能登录
    u.recovery_codes = ""
    u.token_version = int(u.token_version or 0) + 1
    db.commit()
    write_log(db, user=admin, action="mfa_reset", target_id=u.id,
              target_label=u.username, decision="allow",
              reason=("清除已绑定的动态口令" if had else "清除待绑定的动态口令密钥")
              + (f"，作废 {dropped} 个恢复码" if dropped else "")
              + "，旧会话已全部失效；下次登录须重新绑定",
              ip=client_ip(request))
    return {"id": u.id, "username": u.username,
            "mfa_enabled": False, "was_enrolled": had,
            "recovery_codes_dropped": dropped}


@router.patch("/users/{uid}")
def update_user(uid: str, body: UserIn, request: Request,
                _: User = Depends(require_admin), db: Session = Depends(get_db)):
    _assert_roles(body.roles)
    u = db.get(User, uid)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    before = f"密级{u.clearance} 角色{u.roles}"
    u.display_name = body.display_name or u.display_name
    u.dept_id = body.dept_id or None
    u.roles = json.dumps(body.roles, ensure_ascii=False)
    u.clearance = body.clearance
    u.status = body.status
    if body.password:
        u.pwd_hash, u.salt = hash_password(body.password)
        # 管理员重置口令 = 管理员知道了新口令，必须让本人下次登录改掉；
        # 同时换代次，把重置前签发的所有会话踢下线。
        u.must_change_password = True
        u.token_version = int(u.token_version or 0) + 1
    db.commit()
    write_log(db, user=_, action="update_user", target_id=u.id, target_label=u.username,
              reason=(f"{before} → 密级{u.clearance} 角色{u.roles}"
                      + ("；已重置口令，下次登录须改密且旧会话失效"
                         if body.password else "")),
              ip=client_ip(request))
    return user_out(db, u)


@router.post("/users/{uid}/reset-risk")
def reset_risk(uid: str, request: Request,
               admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """人工审核通过后复位风险分（P1-7）。

    风险分是自动判定的产物，可能误伤高频合规专员——必须留一个人工纠正入口，
    且这个入口本身要留痕，否则就成了绕过审计的后门。
    """
    u = db.get(User, uid)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    before = getattr(u, "risk_score", 0) or 0
    u.risk_score = 0
    u.last_risk_ts = None
    db.commit()
    db.refresh(u)
    write_log(db, user=admin, action="admin", target_id=u.id, target_label=u.username,
              decision="allow",
              reason=f"人工复位风险分（{before} → 0），该账号恢复问答访问",
              ip=client_ip(request))
    # 刻意不返回 user_out：风险分不进 user_out（登录响应也用它），
    # 否则等于把"你还差几分就被锁"直接告诉当事人，方便其校准规避节奏。
    return {
        "id": u.id, "username": u.username,
        "risk_before": before, "risk_score": 0, "last_risk_ts": None,
    }


@router.get("/approvals")
def list_approvals(_: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """权限变更审批队列（密级 / 访问范围 / 新增授权）。"""
    rows = db.execute(
        select(ApprovalRequest).order_by(ApprovalRequest.created_at.desc()).limit(200)
    ).scalars().all()
    out = []
    for r in rows:
        frm, to = approval_describe(r)
        out.append({
            "id": r.id, "doc_id": r.doc_id, "kind": r.kind,
            "from_level": frm, "to_level": to,
            "summary": approval_summary(r),
            "requester": r.requester_name, "approver": r.approver_name,
            "status": r.status, "reason": r.reason,
            "decided_reason": r.decided_reason,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
            "decided_at": r.decided_at.strftime("%Y-%m-%d %H:%M:%S") if r.decided_at else "",
        })
    return out


class DecideIn(BaseModel):
    reason: str = ""


@router.post("/approvals/{aid}/approve")
def approve_req(aid: str, body: DecideIn, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    req = decide(db, admin, aid, True, body.reason)
    doc = db.get(Document, req.doc_id)
    db.commit()
    write_log(db, user=admin, action="approval", target_id=req.doc_id,
              target_label=doc.title if doc else "", decision="allow",
              reason=(f"批准{approval_summary(req)}（申请人 {req.requester_name}）"),
              ip=client_ip(request))
    return {"id": req.id, "status": req.status,
            "doc_clearance": doc.clearance if doc else None}


@router.post("/approvals/{aid}/reject")
def reject_req(aid: str, body: DecideIn, request: Request,
               admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    req = decide(db, admin, aid, False, body.reason)
    doc = db.get(Document, req.doc_id)
    db.commit()
    write_log(db, user=admin, action="approval", target_id=req.doc_id,
              target_label=doc.title if doc else "", decision="deny",
              reason=(f"驳回{approval_summary(req)}：{req.decided_reason}"),
              ip=client_ip(request))
    return {"id": req.id, "status": req.status}


@router.get("/report/daily")
def daily_report_api(date: str = "", _: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    """运维监控日报（P2-12）：?date=YYYY-MM-DD，留空=今天（REPORT_TZ 当地自然日）。

    只读聚合，刻意不写审计——看板刷新不该污染当天的风险计数与哈希链。
    """
    from ..monitor import daily_report, include_text, render_report

    try:
        rep = daily_report(db, date or None)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    if include_text():
        rep["text"] = render_report(rep)
    return rep


@router.get("/metrics")
def metrics_api(days: int = 14, _: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    """安全指标监控（P2-12）：?days=14 的拦截率时序 + 异常判定。

    未启用（METRICS_ENABLED=false）时返回 503 并给出启用方式——
    "没开监控"和"开了监控但今天没异常"必须能一眼区分，否则运维会把
    空列表当成平安无事。
    """
    from ..config import METRICS_ENABLED
    from ..metrics import build_metrics

    if not METRICS_ENABLED:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "安全指标监控未启用：在 backend/.env 中设置 METRICS_ENABLED=true 并重启服务后访问")
    return build_metrics(db, days)


@router.post("/metrics/cleanup")
def metrics_cleanup(request: Request, days: int | None = None,
                    admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """清理过期的运维日报 markdown（只删 backend/reports/*.md，不碰库表）。

    审计日志与暴露账本刻意不在清理范围：前者是哈希链与合规留痕，
    后者是防拼图安全证据——保留矩阵见 README「九、数据保留与删除」。
    days 缺省取 METRICS_RETENTION_DAYS，夹到 [1, 3650]。
    """
    from ..metrics import cleanup_old_reports

    result = cleanup_old_reports(days=days)
    write_log(db, user=admin, action="metrics_cleanup", target_id="reports",
              target_label=f"保留 {result['days']} 天", decision="allow",
              reason=f"清理过期日报 {len(result['deleted'])} 份，保留 {result['kept']} 份",
              ip=client_ip(request))
    return result


@router.get("/departments")
def list_depts(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    depts = db.execute(select(Department).order_by(Department.name)).scalars().all()
    return [{"id": d.id, "name": d.name, "parent_id": d.parent_id} for d in depts]


@router.post("/departments", status_code=201)
def create_dept(body: DeptIn, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.execute(select(Department).where(Department.name == body.name)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "部门已存在")
    d = Department(name=body.name.strip(), parent_id=body.parent_id or None)
    db.add(d)
    db.commit()
    invalidate_dept_cache()  # 部门树变化后，可见部门链必须重算
    return {"id": d.id, "name": d.name, "parent_id": d.parent_id}


@router.get("/jigsaw")
def jigsaw_board(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    """拼图攻击风险榜：按累积披露比例排序的高危 用户×文档 组合。"""
    from ..config import LEVEL_NAMES
    from ..jigsaw import risk_board

    rows = risk_board(db, limit=30)
    for r in rows:
        u = db.get(User, r["user_id"])
        d = db.get(Document, r["doc_id"])
        r["username"] = u.username if u else "(已删除)"
        r["doc_title"] = d.title if d else "(已删除)"
        r["clearance_name"] = LEVEL_NAMES.get(d.clearance, "") if d else ""
    return rows


@router.get("/audit")
def list_audit(action: str = "", decision: str = "", username: str = "", limit: int = 100,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not ({"admin", "compliance"} & set(user.role_list())):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "仅管理员/合规角色可查看审计日志")
    q = select(AuditLog).order_by(desc(AuditLog.ts)).limit(min(limit, 500))
    if action:
        q = q.where(AuditLog.action == action)
    if decision:
        q = q.where(AuditLog.decision == decision)
    if username:
        q = q.where(AuditLog.username.like(f"%{username}%"))
    rows = db.execute(q).scalars().all()
    return [{
        "id": r.id,
        "ts": r.ts.strftime("%Y-%m-%d %H:%M:%S") if r.ts else "",
        "username": r.username, "action": r.action, "target_label": r.target_label,
        "query": r.query[:200], "decision": r.decision, "reason": r.reason,
        "prev_hash": r.prev_hash, "row_hash": r.row_hash,
    } for r in rows]


@router.get("/audit/anchor")
def audit_anchor_status(user: User = Depends(current_user)):
    """审计锚点状态：本地锚点 + 外置锚点（只读，不写审计以免污染链）。"""
    if "admin" not in user.role_list():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "仅管理员可查看审计锚点")
    from .. import anchors
    from ..config import AUDIT_ANCHOR_EXTERNAL_FILE, AUDIT_ANCHOR_URL

    local = {}
    try:
        import json as _json
        from ..audit import ANCHOR_FILE
        if ANCHOR_FILE.is_file():
            local = _json.loads(ANCHOR_FILE.read_text(encoding="utf-8"))
    except Exception:
        local = {}
    external = anchors.read_external(limit=50)
    latest = external[-1] if external else {}
    return {
        "local": local,
        "external": {
            "enabled": anchors.enabled(),
            "file": bool(AUDIT_ANCHOR_EXTERNAL_FILE),
            "url": bool(AUDIT_ANCHOR_URL),
            "records": len(external),
            "bad_signature": sum(1 for r in external if r.get("sig_ok") is False),
            "latest": latest,
        },
    }


@router.post("/audit/anchor")
def audit_anchor_flush(request: Request, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    """立即外发一次链尾锚点（运维在关键操作后手动打点用）。"""
    from .. import anchors, audit as audit_mod

    if not anchors.enabled():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "未配置外置锚点：请设置 AUDIT_ANCHOR_EXTERNAL_FILE 或 AUDIT_ANCHOR_URL")
    record = anchors.emit(audit_mod._last_hash, audit_mod._last_seq, force=True)  # noqa: SLF001
    if record is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "外置锚点外发失败，请检查 sink 可用性（审计写入未受影响）")
    write_log(db, user=admin, action="audit_anchor", target_id=str(record["seq"]),
              target_label="外置锚点", decision="allow",
              reason=f"手动外发链尾锚点 seq={record['seq']}", ip=client_ip(request))
    return record


@router.get("/audit/verify")
def verify_audit_chain(limit: int = 5000, user: User = Depends(current_user),
                       db: Session = Depends(get_db)):
    """P0-2：审计链完整性校验。逐行重算哈希 + 邻链链接统计。
    ok=false 说明有审计记录被篡改或删除——金融合规的不可抵赖性检查。"""
    if "admin" not in user.role_list():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "仅管理员可执行审计链校验")
    from ..audit import verify_chain

    result = verify_chain(db, limit=limit)
    if not result["ok"]:
        write_log(db, user=user, action="audit_verify", decision="deny",
                  reason=f"审计链校验失败：篡改 {result['broken_rows']} 行 / "
                         f"断链 {result['broken_links']} 处",
                  detail=json.dumps(result, ensure_ascii=False))
    return result


@router.get("/stats", response_model=StatsOut)
def stats(user: User = Depends(current_user), db: Session = Depends(get_db)):
    # 态势信息分级：库规模与拦截/限流/阻断/风险榜计数都是**全库**口径，对
    # 攻击者是有价值的态势信号——他能据此判断自己的探测是否已被发现、该不该
    # 收敛节奏（正好喂给防拼图的对抗面）。仅管理员/合规可见。
    # 其他角色只拿到运行模式三项（前端聊天页侧栏依赖，见 Chat.vue），
    # 数值字段一律 None——不是 0，0 会被读成"没有拦截"。
    from ..config import JIGSAW_ENABLED, LLM_API_KEY

    modes = {
        # #21：存储只有一种，字段保留为前端既有契约，值固定不再分支。
        "storage": "PostgreSQL + pgvector",
        "llm_mode": "远程大模型" if LLM_API_KEY else "抽取式降级（未配置 Key）",
        "embed_mode": f"embedding:{embedder.mode}",
    }
    if not ({"admin", "compliance"} & set(user.role_list())):
        return StatsOut(**modes)

    docs = db.execute(select(func.count()).select_from(Document)).scalar() or 0
    chunks = db.execute(select(func.count()).select_from(Chunk)).scalar() or 0
    users = db.execute(select(func.count()).select_from(User)).scalar() or 0
    audits = db.execute(select(func.count()).select_from(AuditLog)).scalar() or 0
    since = datetime.utcnow() - timedelta(days=7)
    denied = db.execute(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.ts >= since, AuditLog.decision.in_(["deny", "abstain"])
        )
    ).scalar() or 0
    throttled = db.execute(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.ts >= since, AuditLog.decision == "throttle"
        )
    ).scalar() or 0
    blocked = db.execute(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.ts >= since, AuditLog.decision.in_(["block", "degrade"])
        )
    ).scalar() or 0
    jigsaw_risk = 0
    if JIGSAW_ENABLED:
        from ..jigsaw import risk_board
        jigsaw_risk = len(risk_board(db, limit=100))
    return StatsOut(
        docs=docs, chunks=chunks, users=users, audits=audits, denied_7d=denied,
        throttled_7d=throttled, jigsaw_risk=jigsaw_risk, blocked_7d=blocked,
        **modes,
    )


@router.get("/audit/{log_id}")
def audit_detail(log_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not ({"admin", "compliance"} & set(user.role_list())):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "仅管理员/合规角色可查看审计日志")
    log = db.get(AuditLog, log_id)
    if log is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "记录不存在")
    try:
        detail = json.loads(log.detail or "{}")
    except Exception:
        detail = {}
    return {
        "id": log.id, "ts": log.ts.strftime("%Y-%m-%d %H:%M:%S") if log.ts else "",
        "username": log.username, "action": log.action, "target_label": log.target_label,
        "query": log.query, "decision": log.decision, "reason": log.reason,
        "detail": detail,
    }
