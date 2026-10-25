# SPDX-License-Identifier: AGPL-3.0-only
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import CLEARANCE_LEVELS, LEVEL_NAMES
from .models import Chunk, Department, DocAcl, Document, User
from .recovery import remaining as _recovery_remaining
from .security import mfa_setup_required as _mfa_setup_required


def dept_name(db: Session, dept_id: str | None) -> str:
    if not dept_id:
        return "未分配"
    d = db.get(Department, dept_id)
    return d.name if d else "未知部门"


def user_out(db: Session, u: User):
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "dept_id": u.dept_id,
        "dept_name": dept_name(db, u.dept_id),
        "roles": u.role_list(),
        "clearance": u.clearance,
        "clearance_name": LEVEL_NAMES.get(u.clearance, ""),
        "is_admin": "admin" in u.role_list(),
        "status": u.status,
        # 前端据此弹"首次登录必须改密"的强制弹窗；服务端另有硬闸，
        # 这个字段只用于体验，不作为安全边界。
        "must_change_password": bool(u.must_change_password),
        # 动态口令三态：已绑定 / 未绑定 / 未绑定且被强制（安全设置页与
        # 强制绑定弹窗共用；同样只是展示，闸门在 security.current_user）。
        "mfa_enabled": bool(getattr(u, "totp_confirmed_at", None)),
        "mfa_setup_required": _mfa_setup_required(u),
        "recovery_codes_remaining": _recovery_remaining(
            getattr(u, "recovery_codes", "")),
    }


def doc_out(db: Session, d: Document, with_acl: bool = True):
    chunk_count = db.execute(
        select(func.count()).where(Chunk.doc_id == d.id)
    ).scalar() or 0
    max_chunk_clearance = db.execute(
        select(func.max(Chunk.clearance)).where(Chunk.doc_id == d.id)
    ).scalar()
    acl = []
    if with_acl:
        rows = db.execute(select(DocAcl).where(DocAcl.doc_id == d.id)).scalars().all()
        acl = [
            {
                "id": a.id, "subject_type": a.subject_type,
                "subject_key": a.subject_key, "effect": a.effect,
                "expires_at": a.expires_at.strftime("%Y-%m-%d %H:%M") if a.expires_at else "",
            }
            for a in rows
        ]
    return {
        "id": d.id,
        "title": d.title,
        "doc_type": d.doc_type,
        "clearance": d.clearance,
        "clearance_name": LEVEL_NAMES.get(d.clearance, ""),
        "acl_mode": d.acl_mode,
        "owner_dept_id": d.owner_dept_id,
        "owner_dept": dept_name(db, d.owner_dept_id),
        "tags": d.tags,
        "pii_hits": d.pii_hits,
        "inject_risk": d.inject_risk or 0,
        "chunk_count": chunk_count,
        "parse_quality": d.parse_quality or "ok",
        # P2-10：当前版本号。引用里带上它，事后能还原"当时看到的是哪一版"。
        "version": int(d.version or 1),
        "max_chunk_clearance": max_chunk_clearance,
        "created_at": d.created_at.strftime("%Y-%m-%d %H:%M") if d.created_at else "",
        "created_by": d.created_by,
        "acl": acl,
    }


def level_options():
    return [{"value": v, "label": k} for k, v in sorted(CLEARANCE_LEVELS.items(), key=lambda x: x[1])]
