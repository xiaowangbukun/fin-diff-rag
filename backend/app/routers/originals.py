# SPDX-License-Identifier: AGPL-3.0-only
"""原件审查接口（仅管理员）：台账 / 下载 / 完整性复核。

三条口径（与正文接口一致，不能因为是"管理员"就放宽）：
1. **密级闸门**：admin 是"能管权限"，不等于"能读一切正文"。原件比切片更
   完整，密级不够一律 404 掩码（存在性本身即敏感），真实原因只进审计。
2. **不发明文地址**：一律由后端流式下发并逐次留痕，不签发预签名 URL——
   预签名一旦拿到手就脱离了审计与吊销范围，等于把原件复制权外发。
3. **先校验再下发**：哈希与台账不一致时拒绝下发（见 originals.fetch）。
"""
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from .. import originals
from ..audit import write_log
from ..db import get_db
from ..models import Document, User
from ..security import require_admin
from .auth import client_ip

router = APIRouter(prefix="/admin/documents", tags=["管理与审计"])


def _doc_or_404(db: Session, user: User, doc_id: str, action: str,
                ip: str = "") -> Document:
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    if int(user.clearance or 0) < int(doc.clearance or 0):
        write_log(db, user=user, action=action, target_id=doc.id,
                  target_label=doc.title, decision="deny",
                  reason=f"原件访问被拒：自身密级 {user.clearance} 低于文档密级 {doc.clearance}",
                  ip=ip)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "文档不存在")
    return doc


def _filename(doc: Document) -> str:
    """下载文件名：只用服务端已知字段，剔除路径分隔符（防 Content-Disposition 注入）。"""
    base = (doc.source_name or doc.title or "original").replace("\\", "_").replace("/", "_")
    ext = "".join(ch for ch in (doc.doc_type or "") if ch.isalnum()).lower()
    if ext and not base.lower().endswith("." + ext):
        base = f"{base}.{ext}"
    return base[:180] or "original.bin"


@router.get("/{doc_id}/original/meta")
def original_meta(doc_id: str, request: Request,
                  user: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    """台账：每个版本是否留存原件、指纹、体积、写入时间（只读，不打对象存储）。"""
    doc = _doc_or_404(db, user, doc_id, "view_original", client_ip(request))
    out = originals.meta(db, doc)
    out["checked_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return out


@router.get("/{doc_id}/original")
def download_original(doc_id: str, request: Request,
                      version: int | None = Query(default=None, ge=1),
                      user: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    """下载原件（默认当前版本）。每次下发都记审计；哈希不符则拒发。"""
    ip = client_ip(request)
    doc = _doc_or_404(db, user, doc_id, "view_original", ip)
    try:
        data, row = originals.fetch(db, doc, version=version)
    except originals.OriginalIntegrityError as e:
        write_log(db, user=user, action="view_original", target_id=doc.id,
                  target_label=doc.title, decision="deny",
                  reason=f"原件下发被拒：{e}", ip=ip)
        # 409：台账里"应该有原件"但实际取不到/不一致，属于状态冲突而非越权
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    write_log(db, user=user, action="view_original", target_id=doc.id,
              target_label=doc.title, decision="allow",
              reason=(f"原件下载 v{row.version}：{len(data)}B / "
                      f"sha256={row.original_sha256[:16]}…"),
              ip=ip)
    name = _filename(doc)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            # no-store：原件不得进浏览器/代理缓存（与全局安全头口径一致）
            "Cache-Control": "no-store",
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "X-Original-SHA256": row.original_sha256,
            "X-Original-Version": str(row.version),
        },
    )


@router.post("/{doc_id}/original/verify")
def verify_original(doc_id: str, request: Request,
                    version: int | None = Query(default=None, ge=1),
                    user: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """完整性复核：重新取回并比对 sha256，结果写审计（定期抽查/事故取证用）。"""
    ip = client_ip(request)
    doc = _doc_or_404(db, user, doc_id, "verify_original", ip)
    out = originals.verify(db, doc, version=version)
    write_log(db, user=user, action="verify_original", target_id=doc.id,
              target_label=doc.title,
              decision="allow" if out.get("ok") else "flag",
              reason=(f"原件完整性复核 v{out.get('version')}："
                      + ("一致" if out.get("ok") else f"不一致（{out.get('reason')}）")
                      + f" / expected={(out.get('expected') or '')[:16]}…"
                      + f" / actual={(out.get('actual') or '')[:16]}…"),
              ip=ip)
    out["checked_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    out["checked_by"] = user.username
    return out
