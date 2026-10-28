# SPDX-License-Identifier: AGPL-3.0-only
"""原件留存编排：上传期写入、审查期取回、完整性复核。

与 blobstore（纯对象存储客户端）分开的理由：这里承载的是**业务口径**——
哪个版本存、存不上怎么办、谁可以取、取回后要不要比对哈希、每次动作怎么留痕。
换掉 MinIO 换成别的 S3 或文件后端时，本模块不动。
"""
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import blobstore
from . import config as cfg
from .audit import write_log
from .models import Document, DocumentVersion, User

ENTRY_PREFIX_CHARS = 16   # 审计里只放指纹前缀，避免整串哈希刷屏


class OriginalStoreError(blobstore.OriginalStoreError):
    """对外暴露的同一类错误（严格模式下上传端点据此拒绝入库）。"""


class OriginalIntegrityError(blobstore.OriginalIntegrityError):
    """取回校验失败（原件被替换/损坏）。"""


def _version_rows(db: Session, doc: Document) -> list[DocumentVersion]:
    return db.execute(
        select(DocumentVersion).where(DocumentVersion.doc_id == doc.id)
        .order_by(DocumentVersion.version)
    ).scalars().all()


def current_version_row(db: Session, doc: Document) -> DocumentVersion | None:
    """当前版本台账行。版本链上层已保证 (doc_id, version) 唯一。"""
    rows = _version_rows(db, doc)
    if not rows:
        return None
    for row in rows:
        if row.version == int(doc.version or 0):
            return row
    return rows[-1]


def _attach(db: Session, doc_id: str, version: int, *, key: str,
            digest: str, size: int) -> DocumentVersion | None:
    row = db.execute(
        select(DocumentVersion)
        .where(DocumentVersion.doc_id == doc_id,
               DocumentVersion.version == int(version))
    ).scalars().first()
    if row is None:          # 版本行缺失属异常，但不阻断入库（原件已在对象存储）
        return None
    row.original_key = key[:512]
    row.original_sha256 = digest
    row.original_size = int(size)
    row.original_stored_at = datetime.utcnow()
    db.commit()
    return row


def _resolve_store() -> tuple[object | None, str]:
    """取后端实例：返回 (store, err)。err 非空表示"开了但用不了"。

    单独抽出来是因为后端构造本身会失败（缺端点/缺凭据/缺 SDK）——这类错误
    必须和"写入失败"走同一条降级路径，否则配置问题会变成上传 500。
    """
    try:
        store = blobstore.get_store()
    except Exception as e:   # OriginalStoreError 及其它构造期异常
        return None, f"{type(e).__name__}: {e}"
    return store, ""


def _store_failure(db: Session, *, user: User | None, doc: Document, reason: str,
                   request_ip: str = "") -> dict:
    """统一降级口径：留审计 flag；严格模式则抛错让上传回滚。"""
    write_log(db, user=user, action="store_original", target_id=doc.id,
              target_label=doc.title, decision="flag",
              reason=(f"原件留存失败（v{doc.version}）：{reason[:200]}；"
                      + ("已按严格模式拒绝入库"
                         if cfg.ORIGINAL_STORE_STRICT else "入库继续，原件缺失")),
              ip=request_ip)
    if cfg.ORIGINAL_STORE_STRICT:
        raise OriginalStoreError(reason)
    return {"enabled": True, "stored": False, "reason": reason[:200],
            "version": int(doc.version or 0)}


def save_original(db: Session, *, user: User | None, doc: Document, data: bytes,
                  ext: str, request_ip: str = "") -> dict:
    """把本次上传的原始字节写进对象存储，并把台账挂到对应版本行上。

    返回 {"enabled": bool, "stored": bool, "reason": str, ...}；调用方把它
    原样放进响应，让上传者立刻知道"这次有没有留下原件"。

    失败语义：默认宽容（stored=false + 审计 flag），`ORIGINAL_STORE_STRICT=true`
    时抛 OriginalStoreError，由上传端点回滚整次入库——「承诺留存却悄悄没留」
    比直接报错更难排查。
    """
    store, err = _resolve_store()
    if store is None and not err:
        return {"enabled": False, "stored": False, "reason": "原件留存未启用"}
    if store is None:
        return _store_failure(db, user=user, doc=doc, reason=err,
                              request_ip=request_ip)
    body = data or b""
    digest = blobstore.sha256_bytes(body)
    key = blobstore.key_for(doc.id, doc.version, ext)
    try:
        info = store.put(key, body, digest)
    except Exception as e:   # 含 SDK 内部各种网络/权限异常
        return _store_failure(db, user=user, doc=doc,
                              reason=f"{type(e).__name__}: {e}",
                              request_ip=request_ip)

    size = int(info.get("size") or len(body))
    _attach(db, doc.id, int(doc.version or 0), key=key, digest=digest, size=size)
    write_log(db, user=user, action="store_original", target_id=doc.id,
              target_label=doc.title, decision="allow",
              reason=(f"原件留存 v{doc.version}：{size}B / "
                      f"sha256={digest[:ENTRY_PREFIX_CHARS]}… / key={key}"),
              ip=request_ip)
    return {"enabled": True, "stored": True, "reason": "", "key": key,
            "sha256": digest, "size": size, "version": int(doc.version or 0)}


def meta(db: Session, doc: Document) -> dict:
    """审查端台账视图：每个版本有没有原件、指纹、体积、写入时间。

    只读，不做对象存储往返——台账本身就能回答"该不该有原件"，先看台账
    再决定是否真去取，避免每次审查都打一遍对象存储。
    """
    rows = _version_rows(db, doc)
    items = [
        {
            "version": r.version,
            "is_current": r.version == int(doc.version or 0),
            "stored": bool(r.original_key),
            "key": r.original_key,
            "sha256": r.original_sha256,
            "size": int(r.original_size or 0),
            "stored_at": (r.original_stored_at.strftime("%Y-%m-%d %H:%M:%S")
                          if r.original_stored_at else ""),
        }
        for r in rows
    ]
    return {
        "doc_id": doc.id,
        "title": doc.title,
        "clearance": int(doc.clearance or 0),
        "enabled": bool(cfg.ORIGINAL_STORE_ENABLED),
        "bucket": cfg.ORIGINAL_STORE_BUCKET if cfg.ORIGINAL_STORE_ENABLED else "",
        "strict": bool(cfg.ORIGINAL_STORE_STRICT),
        "total": len(items),
        "items": items,
    }


def fetch(db: Session, doc: Document, *, version: int | None = None) -> tuple[bytes, DocumentVersion]:
    """取回指定版本（默认当前版本）的原件，并在下发前校验哈希。

    校验失败必须拒发：把与台账不一致的字节交给审查端，等于用一份被替换过的
    文件冒充"当时提交的原文"，比报错危险得多。
    """
    store, err = _resolve_store()
    if store is None:
        raise OriginalIntegrityError(err or "原件留存未启用")
    rows = _version_rows(db, doc)
    row = None
    if version is not None:
        row = next((r for r in rows if r.version == int(version)), None)
    else:
        row = current_version_row(db, doc)
    if row is None or not row.original_key:
        raise OriginalIntegrityError("该版本没有留存原件")
    cap = max(1, int(cfg.ORIGINAL_STORE_GET_MAX_MB)) * 1024 * 1024
    try:
        data = store.get_bytes(row.original_key, max_bytes=cap)
    except Exception as e:
        # 取不到（对象被删/桶被删/网络断）同样是"状态冲突"，不能 500
        raise OriginalIntegrityError(f"原件取回失败：{type(e).__name__}: {e}") from e
    actual = blobstore.sha256_bytes(data)
    if row.original_sha256 and actual != row.original_sha256:
        raise OriginalIntegrityError(
            f"原件哈希与台账不一致（台账 {row.original_sha256[:ENTRY_PREFIX_CHARS]}…，"
            f"实取 {actual[:ENTRY_PREFIX_CHARS]}…）")
    return data, row


def verify(db: Session, doc: Document, *, version: int | None = None) -> dict:
    """完整性复核：重新取回并比对 sha256（供定期抽查/事故取证用）。"""
    store, err = _resolve_store()
    if store is None:
        return {"ok": False, "reason": err or "原件留存未启用", "doc_id": doc.id}
    rows = _version_rows(db, doc)
    targets = ([r for r in rows if r.version == int(version)] if version is not None
               else [r for r in rows if r.version == int(doc.version or 0)]
               or ([rows[-1]] if rows else []))
    if not targets or not targets[0].original_key:
        return {"ok": False, "reason": "该版本没有留存原件", "doc_id": doc.id}
    row = targets[0]
    try:
        data = store.get_bytes(row.original_key,
                               max_bytes=max(1, int(cfg.ORIGINAL_STORE_GET_MAX_MB)) * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "reason": f"取回失败：{type(e).__name__}", "doc_id": doc.id,
                "version": row.version, "expected": row.original_sha256, "actual": ""}
    actual = blobstore.sha256_bytes(data)
    remote = ""
    try:
        remote = str(store.stat(row.original_key).get("sha256") or "")
    except Exception:
        remote = ""   # 元数据读不到不影响主判定（以字节哈希为准）
    return {
        "ok": bool(actual == row.original_sha256),
        "doc_id": doc.id,
        "version": row.version,
        "size": len(data),
        "expected": row.original_sha256,
        "actual": actual,
        "object_meta_sha256": remote,
        "reason": "" if actual == row.original_sha256 else "原件与台账哈希不一致",
    }
