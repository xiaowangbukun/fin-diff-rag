# SPDX-License-Identifier: Apache-2.0
"""
权限引擎 —— 全链路防泄密的核心。

判定顺序（deny 永远优先）：
  0. 文档未就绪（status != ready）           → 拒绝（与 SQL 下推口径一致）
  1. 密级硬门槛：用户密级 < 文档密级 → 直接拒绝（不依赖任何 ACL）
  2. deny 名单命中 → 拒绝
  3. acl_mode == open  → 允许
  4. acl_mode == dept  → 命中部门链（本部门及所有下级部门）→ 允许
  5. acl_mode == restrict → 必须命中 allow（user/dept/role 任一）
关键约束：过滤必须下推到 SQL（见 accessible_doc_ids），
          不允许"先全量捞回再在应用层过滤"，避免越权数据进入内存与日志。

两道新增的横切防线：
  · 颗粒度下沉：除文档级密门外，切片可携带独立密级（chunk_clearance_cond），
    同一篇文档内可实现跨密级隔离（段落级撕裂的解法）。
  · 消除缓存时间窗：部门树缓存仅 TTL 秒级，任何结构变更立即失效；
    ACL 支持 expires_at 临时授权，到期自动失效，不需要人工回收。
"""
import time
from datetime import datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .config import DEPT_CACHE_TTL, LEVEL_NAMES
from .models import Chunk, Department, DocAcl, Document, User


_CHILDREN_CACHE: dict[str, list[str]] | None = None
_CHILDREN_TS: float = 0.0


def _children_map(db: Session) -> dict[str, list[str]]:
    """部门子映射。带 TTL 的短缓存：结构变更最长 TTL 秒后必然重算，
    配合 invalidate_dept_cache() 即时失效，杜绝权限缓存时间窗。"""
    global _CHILDREN_CACHE, _CHILDREN_TS
    now = time.monotonic()
    if _CHILDREN_CACHE is None or now - _CHILDREN_TS > max(0.1, DEPT_CACHE_TTL):
        m: dict[str, list[str]] = {}
        for did, pid in db.execute(select(Department.id, Department.parent_id)).all():
            m.setdefault(pid or "__root__", []).append(did)
        _CHILDREN_CACHE = m
        _CHILDREN_TS = now
    return _CHILDREN_CACHE


def invalidate_dept_cache():
    global _CHILDREN_CACHE
    _CHILDREN_CACHE = None


def dept_chain(db: Session, user: User) -> list[str]:
    """用户所属部门 + 全部下级部门：上级可以查看下级文档，下级不能反查上级。"""
    if not user.dept_id:
        return ["__none__"]  # 保证 SQL 中 in_() 非空
    children = _children_map(db)
    ids, stack = [], [user.dept_id]
    while stack:
        cur = stack.pop()
        if cur in ids:
            continue
        ids.append(cur)
        stack.extend(children.get(cur, []))
    return ids or ["__none__"]


def _acl_alive():
    """临时授权有效期：expires_at 为空表示长期有效，否则必须未到期。"""
    return or_(DocAcl.expires_at.is_(None), DocAcl.expires_at > datetime.utcnow())


def _subject_match(user: User, dept_ids: list[str], roles: list[str]):
    return or_(
        and_(DocAcl.subject_type == "user", DocAcl.subject_key == user.id),
        and_(DocAcl.subject_type == "dept", DocAcl.subject_key.in_(dept_ids)),
        and_(DocAcl.subject_type == "role", DocAcl.subject_key.in_(roles or ["__none__"])),
    )


def chunk_clearance_cond(user: User):
    """切片级密级门槛：切片密级为 NULL 时继承文档密级（由文档级过滤覆盖），
    显式设置时必须不高于用户密级。与 accessible_doc_ids 同时下推到 SQL。"""
    return or_(Chunk.clearance.is_(None), Chunk.clearance <= user.clearance)


def effective_clearance(doc_clearance: int, chunk_clearance: int | None) -> int:
    """有效密级 = max(文档密级, 切片密级)。切片密级只能上调、不能下调。"""
    return max(int(doc_clearance or 0), int(chunk_clearance or 0))


def accessible_doc_ids(db: Session, user: User):
    """返回"用户可见文档 id"的 SQL 子查询，可直接嵌入检索 SQL。"""
    dept_ids = dept_chain(db, user)
    roles = user.role_list()
    allow_exists = (
        select(DocAcl.id)
        .where(DocAcl.doc_id == Document.id, DocAcl.effect == "allow",
               _acl_alive(), _subject_match(user, dept_ids, roles))
        .exists()
    )
    deny_exists = (
        select(DocAcl.id)
        .where(DocAcl.doc_id == Document.id, DocAcl.effect == "deny",
               _acl_alive(), _subject_match(user, dept_ids, roles))
        .exists()
    )
    return (
        select(Document.id)
        .where(
            Document.status == "ready",
            Document.clearance <= user.clearance,          # 密级硬门槛
            ~deny_exists,                                   # deny 优先
            or_(
                Document.acl_mode == "open",
                and_(Document.acl_mode == "dept", Document.owner_dept_id.in_(dept_ids)),
                and_(Document.acl_mode == "restrict", allow_exists),
                allow_exists,                               # 显式授权可越过部门限制
            ),
        )
    )


def can_access(db: Session, user: User, doc: Document) -> tuple[bool, str]:
    """逐条后置校验：用于检索结果、下载、切片预览等所有出口。

    必须与 accessible_doc_ids 的 SQL 下推口径一致：那边已过滤
    status == "ready"，这里若不过滤，同一篇非就绪文档就会
    "列表/检索里看不到、详情/下载却能拿到"——两道防线出现缝隙。
    理由文案刻意不含状态值：调用方多数统一转 404（存在性不可探测），
    透出"未就绪/已归档"等于把文档生命周期泄露给不该知道的人。
    """
    if doc.status != "ready":
        return False, "文档当前不可访问"
    if doc.clearance > user.clearance:
        return False, (
            f"密级不足：文档为「{LEVEL_NAMES.get(doc.clearance, '未知')}」，"
            f"当前用户为「{LEVEL_NAMES.get(user.clearance, '未知')}」"
        )
    dept_ids = dept_chain(db, user)
    roles = user.role_list()
    acls = db.execute(
        select(DocAcl).where(DocAcl.doc_id == doc.id, _acl_alive())
    ).scalars().all()

    for a in acls:
        if a.effect != "deny":
            continue
        if a.subject_type == "user" and a.subject_key == user.id:
            return False, "该文档对您设置了显式拒绝"
        if a.subject_type == "dept" and a.subject_key in dept_ids:
            return False, "您所属部门被显式拒绝访问该文档"
        if a.subject_type == "role" and a.subject_key in roles:
            return False, f"角色 {a.subject_key} 被显式拒绝访问该文档"

    if doc.acl_mode == "open":
        return True, "公开文档"
    if doc.acl_mode == "dept":
        if doc.owner_dept_id in dept_ids:
            return True, "同部门/上级部门可见"
    for a in acls:
        if a.effect != "allow":
            continue
        if a.subject_type == "user" and a.subject_key == user.id:
            return True, "显式授权（用户）"
        if a.subject_type == "dept" and a.subject_key in dept_ids:
            return True, "显式授权（部门）"
        if a.subject_type == "role" and a.subject_key in roles:
            return True, f"显式授权（角色 {a.subject_key}）"
    if doc.acl_mode == "restrict":
        return False, "文档为白名单模式，您不在授权名单内"
    return False, "不属于该文档归属部门，且无显式授权"
