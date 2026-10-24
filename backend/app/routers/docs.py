# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.orm import Session

from ..approval import level_name as _lvl
from ..approval import (
    grant_acl, request_acl_change, request_clearance_change,
    summary as approval_summary,
)
from ..audit import write_log
from ..db import get_db
from ..ingest import ParseError, ingest_document, parse_bytes, reingest_document
from ..jigsaw import check_full_read, record_full_read
from ..models import ApprovalRequest, Chunk, DocAcl, Document, DocumentVersion, User
from ..pii import scan
from ..policy import accessible_doc_ids, can_access, effective_clearance
from ..schemas import AclIn, DocCreateIn, DocUpdateIn
from ..security import current_user
from ..serializers import dept_name, doc_out, level_options
from .auth import client_ip

router = APIRouter(prefix="/docs", tags=["知识库"])


def _mask_not_found(db: Session, user: User, doc_id: str, reason: str):
    """元数据明文泄漏封堵：文档的存在性本身就是敏感信息。
    越权访问统一返回 404（与"真的不存在"不可区分），真实原因只进审计。"""
    write_log(db, user=user, action="view", target_id=doc_id, decision="deny", reason=reason)
    raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")


def _require_manage_right(db: Session, user: User, doc: Document, prefix: str) -> None:
    """改元数据/授权的前置检查。

    管理员按角色放行（admin 是"能管权限"，不代表能读一切——正文读取另有
    密级闸门）。上传人只有在"仍读得到这篇文档"时才可继续操作：文档被升密
    或改挂部门之后，上传人身份不该变成一张永久后门。
    """
    if "admin" in user.role_list():
        return
    if doc.created_by == user.username:
        if doc.status == "ready" and int(doc.clearance or 0) <= int(user.clearance or 0):
            return
        _mask_not_found(db, user, doc.id,
                        f"{prefix}被拒：上传人已失去该文档访问权")
    ok, why = can_access(db, user, doc)
    if not ok:
        _mask_not_found(db, user, doc.id, f"{prefix}被拒：{why}")


@router.get("/meta")
def meta(user: User = Depends(current_user), db: Session = Depends(get_db)):
    from ..config import ROLES
    from ..models import Department
    depts = [
        {"id": d.id, "name": d.name} for d in
        db.execute(select(Department).order_by(Department.name)).scalars().all()
    ]
    return {"levels": level_options(), "roles": ROLES, "departments": depts,
            "acl_modes": [{"value": "open", "label": "全公司可见"},
                          {"value": "dept", "label": "归属部门可见"},
                          {"value": "restrict", "label": "仅白名单可见"}]}


@router.get("")
def list_docs(user: User = Depends(current_user), db: Session = Depends(get_db)):
    subq = accessible_doc_ids(db, user)
    docs = db.execute(
        select(Document).where(Document.id.in_(subq)).order_by(Document.created_at.desc())
    ).scalars().all()
    return [doc_out(db, d) for d in docs]


@router.post("", status_code=201)
def create_doc(body: DocCreateIn, request: Request,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.clearance > user.clearance:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "不能创建高于自身密级的文档")
    try:
        doc = ingest_document(
            db, title=body.title, content=body.content, doc_type=body.doc_type,
            source_name="手动录入", owner_dept_id=body.owner_dept_id or user.dept_id,
            clearance=body.clearance, acl_mode=body.acl_mode, tags=body.tags,
            created_by=user.username,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    flagged = doc.inject_risk > 0
    write_log(db, user=user, action="upload", target_id=doc.id, target_label=doc.title,
              decision="flag" if flagged else "allow",
              reason=(f"密级 {doc.clearance} / {doc.acl_mode}"
                      + (f" / 检出疑似提示注入 {doc.inject_risk} 处" if flagged else "")),
              ip=client_ip(request))
    return doc_out(db, doc)


@router.post("/upload", status_code=201)
async def upload_doc(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(""),
    clearance: int = Form(1),
    acl_mode: str = Form("dept"),
    owner_dept_id: str = Form(""),
    tags: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if clearance > user.clearance:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "不能上传高于自身密级的文档")
    filename = file.filename or "upload.bin"
    ext = os.path.splitext(filename)[1].lstrip(".").lower()
    if ext not in ("pdf", "docx", "doc", "xlsx", "xls", "csv", "md", "txt", "text"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"暂不支持的文件类型：{ext or '未知'}")
    data = await file.read()
    # 上限走配置（MAX_UPLOAD_MB），不再硬编码两处 20MB；函数内 import 是为了
    # 让单测能 monkeypatch config 模块属性改小上限验证边界。
    from ..config import MAX_UPLOAD_MB

    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"单个文件不得超过 {MAX_UPLOAD_MB}MB")
    try:
        text, quality = parse_bytes(data, ext, filename)
    except ParseError as e:
        # 解析失败（加密/损坏/扫描件无 OCR）→ 400 + 可读原因，
        # 伪文本绝不入库（P1：失败必须拒绝，而不是吞成正文）
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    text = text.strip()
    if not text:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "未能从文件中提取到文本内容")
    doc = ingest_document(
        db, title=title or filename, content=text, doc_type=ext, source_name=filename,
        owner_dept_id=owner_dept_id or user.dept_id, clearance=clearance,
        acl_mode=acl_mode, tags=tags, created_by=user.username,
        parse_quality=quality,
    )
    # P1-4：上传内容检出注入话术 → 审计 decision=flag（标记留痕，不拦截入库：
    # 文档本身可能是含攻击样本的演练材料，拦截会误伤正常归档）
    flagged = doc.inject_risk > 0
    write_log(db, user=user, action="upload", target_id=doc.id, target_label=doc.title,
              decision="flag" if flagged else "allow",
              reason=(f"文件 {filename} / 密级 {doc.clearance}"
                      + (f" / 检出疑似提示注入 {doc.inject_risk} 处" if flagged else "")),
              ip=client_ip(request))
    return doc_out(db, doc)


@router.get("/{doc_id}")
def get_doc(doc_id: str, request: Request,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    ok, reason = can_access(db, user, doc)
    if not ok:
        _mask_not_found(db, user, doc.id, reason)
    # 全文详情是拼图攻击最省事的入口：一次请求拿走全部切片，连"拼"都不用。
    # 限制窗口内读取次数，并把已读切片计入同一本超额账本。
    allowed, msg = check_full_read(db, user, doc)
    if not allowed:
        write_log(db, user=user, action="view", target_id=doc.id, target_label=doc.title,
                  decision="throttle", reason=msg, ip=client_ip(request))
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, msg)

    chunks = db.execute(
        select(Chunk).where(Chunk.doc_id == doc.id).order_by(Chunk.seq)
    ).scalars().all()
    # 颗粒度下沉的出口：同一篇文档内，切片级密级高于用户密级的段落不返回
    # （段落级撕裂防护——文档可见 ≠ 每一段都可见）。
    visible = [c for c in chunks
               if effective_clearance(doc.clearance, c.clearance) <= user.clearance]
    hidden = len(chunks) - len(visible)
    record_full_read(db, user, doc, visible)

    out = doc_out(db, doc)
    out["chunks"] = [
        {"id": c.id, "seq": c.seq, "content": c.content} for c in visible
    ]
    out["hidden_chunks"] = hidden
    write_log(db, user=user, action="view", target_id=doc.id, target_label=doc.title,
              decision="allow",
              reason=(f"全文读取（{len(visible)} 段"
                      + (f"，{hidden} 段因切片密级不可见" if hidden else "") + "）"),
              ip=client_ip(request))
    return out


@router.patch("/{doc_id}")
def update_doc(doc_id: str, body: DocUpdateIn, request: Request,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    _require_manage_right(db, user, doc, "元数据变更")
    is_admin = "admin" in user.role_list()
    before = f"密级{doc.clearance}/{doc.acl_mode}"
    # 元数据（标题/标签）先行落地：降密要走审批，但不能因此把同一请求里的
    # 其它修改一起吞掉——调用方会误以为整包更新成功。
    # title/tags 的长度已由 DocUpdateIn 夹到 ≤200，库列 255 永不会触顶。
    if body.title is not None:
        doc.title = body.title
    if body.tags is not None:
        doc.tags = body.tags
    meta_changed = body.title is not None or body.tags is not None

    # 访问范围（acl_mode / 归属部门）与密级同属"授权面"，放宽必须二次复核：
    # 否则上传人一个人就能把「仅白名单可见」改成「全公司可见」，审批流形同虚设。
    acl_req, acl_note = None, ""
    if body.acl_mode is not None or body.owner_dept_id is not None:
        acl_req, acl_note = request_acl_change(
            db, user, doc, body.acl_mode, body.owner_dept_id)

    clr_req, clr_note = None, ""
    if body.clearance is not None:
        if body.clearance > user.clearance and not is_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "不能将文档提升到高于自身密级")
        # P2-9：降密不可逆，必须他人复核；升密（变严）默认直接生效。
        clr_req, clr_note = request_clearance_change(db, user, doc, body.clearance)

    db.commit()
    if clr_req is not None or acl_req is not None:
        notes = [n for n in (clr_note, acl_note) if n]
        write_log(db, user=user, action="approval_request",
                  target_id=doc.id, target_label=doc.title, decision="allow",
                  reason=("；".join(
                      [approval_summary(r) for r in (clr_req, acl_req) if r is not None]
                      + ([f"说明：{'；'.join(notes)}"] if notes else [])
                      + (["同请求的元数据变更已立即生效"] if meta_changed else []))),
                  ip=client_ip(request))
        content = {"status": "pending", "message": "；".join(notes),
                   "meta_applied": meta_changed, "doc": doc_out(db, doc)}
        if clr_req is not None:
            content["approval_id"] = clr_req.id
        if acl_req is not None:
            content["acl_approval_id"] = acl_req.id
        # 兼容旧字段：只要有一个审批单，approval_id 总是存在
        content.setdefault("approval_id", acl_req.id if acl_req else "")
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=content)

    write_log(db, user=user, action="update", target_id=doc.id, target_label=doc.title,
              decision="allow",
              reason=(f"{before} → 密级{doc.clearance}/{doc.acl_mode}"
                      + (f"（{acl_note}）" if acl_note else "")),
              ip=client_ip(request))
    return doc_out(db, doc)


@router.post("/{doc_id}/reingest")
async def reingest_doc(
    doc_id: str, request: Request,
    file: UploadFile | None = File(None),
    content: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """以新内容替换文档正文（P2-10），旧切片作废、新版本入版本链。

    支持两种提交方式：上传新文件，或在表单里直接给 content 文本。
    正文替换不触碰密级——改密级请走审批流，两件事分开留痕。
    """
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    is_admin = "admin" in user.role_list()
    if not is_admin and doc.created_by != user.username:
        ok, reason = can_access(db, user, doc)
        if not ok:
            _mask_not_found(db, user, doc.id, reason)
    # 低密级账号借"更新内容"改写高密文档，等于绕过创建时的密级检查。
    # 管理员同样受限：admin 是"能管权限"而不是"能读一切"，让密级 1 的管理员
    # 改写自己根本读不到的绝密正文，等于开了一条提权写入面。
    if int(user.clearance or 0) < int(doc.clearance or 0):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"自身密级低于文档密级（{_lvl(doc.clearance)}），无权替换该文档正文")

    doc_type, quality, src = doc.doc_type, "ok", "手动更新"
    text = (content or "").strip()
    if file is not None and (file.filename or "").strip():
        filename = file.filename or "upload.bin"
        ext = os.path.splitext(filename)[1].lstrip(".").lower()
        if ext not in ("pdf", "docx", "doc", "xlsx", "xls", "csv", "md", "txt", "text"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"暂不支持的文件类型：{ext or '未知'}")
        data = await file.read()
        from ..config import MAX_UPLOAD_MB

        if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                f"单个文件不得超过 {MAX_UPLOAD_MB}MB")
        try:
            text, quality = parse_bytes(data, ext, filename)
        except ParseError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        doc_type, src = ext, filename

    try:
        doc, ver, created = reingest_document(
            db, doc, content=text, doc_type=doc_type,
            parse_quality=quality, actor=user.username,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    write_log(db, user=user, action="update", target_id=doc.id, target_label=doc.title,
              decision="flag" if doc.inject_risk > 0 else "allow",
              reason=(f"正文替换（{src}）→ 版本 v{ver.version}"
                      + ("" if created else "，内容与当前版本一致，未新增版本")
                      + (f" / 检出疑似提示注入 {doc.inject_risk} 处"
                         if doc.inject_risk > 0 else "")),
              ip=client_ip(request))
    out = doc_out(db, doc)
    out["version"] = ver.version
    out["version_created"] = created
    return out


@router.get("/{doc_id}/versions")
def list_versions(doc_id: str, request: Request,
                  user: User = Depends(current_user), db: Session = Depends(get_db)):
    """版本链（P2-10）：谁在何时以何密级替换过正文，内容与当前版本是否一致。

    只返回元数据与指纹，不含全文——版本追溯要能回答"当时存的是哪份内容"，
    不需要把每一版全文复制一份。
    """
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    ok, reason = can_access(db, user, doc)
    if not ok:
        _mask_not_found(db, user, doc.id, reason)

    rows = db.execute(
        select(DocumentVersion).where(DocumentVersion.doc_id == doc.id)
        .order_by(DocumentVersion.version)
    ).scalars().all()
    if rows:
        current = rows[-1].content_hash
    else:
        from ..ingest import content_hash
        current = content_hash(
            "".join(c.content for c in
                    db.execute(select(Chunk).where(Chunk.doc_id == doc.id)
                               .order_by(Chunk.seq)).scalars().all())
        )
    return {
        "doc_id": doc.id,
        "title": doc.title,
        "total": len(rows),
        "versions": [
            {
                "version": v.version,
                "content_hash": v.content_hash[:16],
                "chunk_count": v.chunk_count,
                "clearance": v.clearance,
                "clearance_name": _lvl(v.clearance),
                "created_by": v.created_by,
                "created_at": v.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "is_current": v.content_hash == current,
            }
            for v in rows
        ],
    }


@router.delete("/{doc_id}")
def delete_doc(doc_id: str, request: Request,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    if "admin" not in user.role_list() and doc.created_by != user.username:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "仅管理员或上传人可删除")
    title = doc.title
    # 文档没了，版本链与待批密级单也该一起走：留着是孤儿记录，
    # 且版本快照会让人误以为"内容还在某处可追溯"
    db.execute(sa_delete(DocumentVersion).where(DocumentVersion.doc_id == doc_id))
    db.execute(sa_delete(ApprovalRequest).where(
        ApprovalRequest.doc_id == doc_id, ApprovalRequest.status == "pending"))
    db.delete(doc)
    db.commit()
    write_log(db, user=user, action="delete", target_id=doc_id, target_label=title,
              decision="allow", ip=client_ip(request))
    return {"ok": True}


@router.post("/{doc_id}/acl")
def add_acl(doc_id: str, body: AclIn, request: Request,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    _require_manage_right(db, user, doc, "授权变更")
    if body.subject_type not in ("user", "dept", "role"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "subject_type 必须是 user/dept/role")
    if body.effect not in ("allow", "deny"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "effect 必须是 allow/deny")
    if not body.subject_key.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "授权对象不能为空")
    if len(body.subject_key.strip()) > 64:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "授权对象过长")
    if body.expires_hours is not None and abs(body.expires_hours) > 87600:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "有效期超出允许范围（±10 年）")
    expires_at = (datetime.utcnow() + timedelta(hours=body.expires_hours)
                  if body.expires_hours is not None else None)
    subject_key = body.subject_key.strip()

    # allow = 指定主体获得可见性（放宽），必须他人复核；deny = 收紧，立即生效。
    # 只给 allow 挂审批、deny 直通，才不会把"止血"操作也卡在审批队列里。
    if body.effect == "allow":
        req, note = grant_acl(db, user, doc, body.subject_type, subject_key, expires_at)
        db.commit()
        if req is not None:
            write_log(db, user=user, action="approval_request",
                      target_id=doc.id, target_label=doc.title, decision="allow",
                      reason=approval_summary(req), ip=client_ip(request))
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={"approval_id": req.id, "status": "pending",
                         "message": note, "doc": doc_out(db, doc)})
        exp_note = (f"（{expires_at:%Y-%m-%d %H:%M} 到期）" if expires_at else "")
        write_log(db, user=user, action="grant", target_id=doc.id,
                  target_label=doc.title, decision="allow",
                  reason=f"{note} allow {body.subject_type}:{subject_key}{exp_note}",
                  ip=client_ip(request))
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=doc_out(db, doc))

    row = DocAcl(doc_id=doc_id, subject_type=body.subject_type,
                 subject_key=subject_key, effect=body.effect,
                 expires_at=expires_at, granted_by=user.username)
    db.add(row)
    db.commit()
    exp_note = (f"（{expires_at:%Y-%m-%d %H:%M} 到期）" if expires_at else "")
    write_log(db, user=user, action="grant", target_id=doc.id, target_label=doc.title,
              decision="allow",
              reason=f"{body.effect} {body.subject_type}:{subject_key}{exp_note}",
              ip=client_ip(request))
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=doc_out(db, doc))


@router.delete("/{doc_id}/acl/{acl_id}")
def del_acl(doc_id: str, acl_id: str, request: Request,
            user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    _require_manage_right(db, user, doc, "撤销授权")
    row = db.get(DocAcl, acl_id)
    if row is None or row.doc_id != doc_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "授权项不存在")
    reason = f"撤销 {row.effect} {row.subject_type}:{row.subject_key}"
    db.delete(row)
    db.commit()
    write_log(db, user=user, action="revoke", target_id=doc.id, target_label=doc.title,
              decision="allow", reason=reason, ip=client_ip(request))
    return doc_out(db, doc)


@router.get("/{doc_id}/pii")
def pii_report(doc_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """敏感信息扫描报告：仅返回类型与数量，低密级用户不返回原文片段。"""
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    ok, reason = can_access(db, user, doc)
    if not ok:
        _mask_not_found(db, user, doc.id, reason)
    chunks = db.execute(select(Chunk).where(Chunk.doc_id == doc.id)).scalars().all()
    kinds: dict[str, int] = {}
    for c in chunks:
        for h in scan(c.content):
            kinds[h.kind] = kinds.get(h.kind, 0) + 1
    return {"doc_id": doc.id, "title": doc.title, "kinds": kinds,
            "total": sum(kinds.values()),
            "note": "低密级用户在问答链路中看到的内容已自动脱敏"}
