# SPDX-License-Identifier: AGPL-3.0-only
"""
混合检索 + 全链路权限过滤（双校验架构）。

对应「双校验架构：兼顾查询性能与安全精准度」：
  第一道 粗筛（低延迟）：文档级标签（ACL / 密级 / 部门）SQL 下推，
                        快速排除绝大多数无关切片，候选池保持在千级以内；
  第二道 精校验（高安全）：细粒度规则比对（切片级密级）+ Top-K 密级校验
                        + 隐式向量验证（不信任召回行里的明文字段，逐条回库复核）。
两道之间还有 RRF 融合与轻量 Rerank。任何一道不过，内容都不进入上下文。

 Fail-Secure 降级通道：public_only_search() 只碰公开域（密级 0 + open），
 与用户身份完全解耦，供权限/检索组件异常时的容灾链路使用。
"""
import re
from dataclasses import dataclass, field

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session

from .config import CANDIDATE_POOL, HNSW_EF_SEARCH, LEVEL_NAMES
from .embed import embedder
from .models import Chunk, Document, User
from .policy import accessible_doc_ids, can_access, chunk_clearance_cond, effective_clearance

STOP = set("的了和与在是对为有个我们你他它们这那吗呢吧啊请帮我查询一下什么是如何怎么样哪些".strip())
MIN_SCORE = 0.28          # 向量相似度准入线
MIN_COVERAGE = 0.34       # 关键词覆盖率准入线
PUBLIC_CLEARANCE = 0      # Fail-Secure 降级通道使用的"公开用户"密级


@dataclass
class Hit:
    chunk_id: str
    doc_id: str
    doc_title: str
    clearance: int          # 有效密级 = max(文档密级, 切片密级)
    seq: int = 0
    content: str = ""
    vec_score: float = 0.0
    kw_hits: int = 0
    score: float = 0.0
    sources: list[str] = field(default_factory=list)


def extract_terms(query: str, limit: int = 12) -> list[str]:
    """关键词抽取：英文按词，中文按 bigram，去停用与重复。"""
    words = re.findall(r"[a-zA-Z0-9]{2,}", query)
    han = re.findall(r"[\u4e00-\u9fff]+", query)
    grams: list[str] = []
    for seg in han:
        if len(seg) <= 2:
            grams.append(seg)
            continue
        grams += [seg[i:i + 2] for i in range(len(seg) - 1)]
    out, seen = [], set()
    for t in words + grams:
        t = t.lower()
        if len(t) < 2 or t in seen:
            continue
        if all(c in STOP for c in t):
            continue
        seen.add(t)
        out.append(t)
    return out[:limit]


_COLS = (
    Chunk.id, Chunk.doc_id, Chunk.seq, Chunk.content,
    Document.title, Document.clearance, Chunk.clearance,
)


def _public_doc_ids(db: Session):
    """Fail-Secure 降级通道的可见集合：仅公开域，与任何用户身份无关。"""
    return select(Document.id).where(
        Document.status == "ready",
        Document.clearance <= PUBLIC_CLEARANCE,
        Document.acl_mode == "open",
    )


def _vector_recall(db: Session, subq, clearance: int, vec: list[float], pool: int
                   ) -> dict[str, tuple[float, tuple]]:
    """向量召回：pgvector 近似检索（#21 后唯一通道，SQLite 内存余弦分支已移除）。

    可访问文档 id 先物化成参数列表再用 `= ANY(:ids)` 绑定。原实现把子查询
    compile 后的 SQL 字符串插进 `IN (...)`：虽子查询自身参数化到位，但拼接
    形态在子查询含 LIKE '%..%' 时会踩 psycopg 的 % 字面量转义，且可读性差。
    这条路径从"SQLite 模式的备用分支"升为唯一通道，按参数绑定重写。
    代价是多一次 round-trip 取 id 列表——ACL 过滤后的可见文档数通常在百级，
    相对向量检索本身的开销可以忽略。
    clearance 为调用方的密级口径，切片级门槛在 SQL 层一并下推。
    """
    out: dict[str, tuple[float, tuple]] = {}
    # P1-6：HNSW 查询期召回宽度。SET LOCAL 是事务级（随隐式事务自动回收），
    # 不会污染连接池里的其他会话；部分连接池代理不支持 SET LOCAL，失败静默。
    if HNSW_EF_SEARCH:
        try:
            db.execute(text(f"SET LOCAL hnsw.ef_search = {int(HNSW_EF_SEARCH)}"))
        except Exception:
            pass
    doc_ids = [str(r[0]) for r in db.execute(subq).all()]
    if not doc_ids:
        return out
    vec_lit = "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
    sql = text(
        "SELECT c.id, c.doc_id, c.seq, c.content, d.title, d.clearance, c.clearance, "
        "(c.embedding <=> CAST(:qvec AS vector)) AS dist "
        "FROM chunks c JOIN documents d ON d.id = c.doc_id "
        "WHERE c.doc_id = ANY(:ids) "
        "AND (c.clearance IS NULL OR c.clearance <= :clearance) "
        "ORDER BY dist ASC LIMIT :pool"
    )
    rows = db.execute(sql, {
        "qvec": vec_lit, "pool": int(pool),
        "ids": doc_ids, "clearance": int(clearance),
    })
    for r in rows:
        row = (r[0], r[1], r[2], r[3], r[4], r[5], r[6])
        out[r[0]] = (max(0.0, 1.0 - float(r[7])), row)
    return out


def _keyword_recall(db: Session, subq, clearance: int, terms: list[str], pool: int
                    ) -> dict[str, tuple[int, tuple]]:
    if not terms:
        return {}
    cond = or_(*[Chunk.content.like(f"%{t}%") for t in terms])
    rows = db.execute(
        select(*_COLS)
        .join(Document, Document.id == Chunk.doc_id)
        .where(Chunk.doc_id.in_(subq), cond,
               or_(Chunk.clearance.is_(None), Chunk.clearance <= clearance))
        .limit(pool * 3)
    ).all()
    out = {}
    for r in rows:
        content = r[3] or ""
        hits = sum(1 for t in terms if t in content)
        if hits:
            out[r[0]] = (hits, tuple(r[:7]))
    return out


def _rrf_fuse(vec_res, kw_res, k: int = 60) -> list[Hit]:
    def _mk(cid: str, row: tuple, **kw) -> Hit:
        return Hit(
            chunk_id=cid, doc_id=row[1], doc_title=row[4],
            clearance=effective_clearance(row[5], row[6]),
            seq=row[2], content=row[3], **kw,
        )

    merged: dict[str, Hit] = {}
    for rank, (cid, (sim, row)) in enumerate(
        sorted(vec_res.items(), key=lambda x: -x[1][0]), start=1
    ):
        merged[cid] = _mk(cid, row, vec_score=sim, sources=["vector"])
        merged[cid].score += 1.0 / (k + rank)
    for rank, (cid, (hits, row)) in enumerate(
        sorted(kw_res.items(), key=lambda x: -x[1][0]), start=1
    ):
        h = merged.get(cid)
        if h is None:
            h = _mk(cid, row, sources=[])
            merged[cid] = h
        h.kw_hits = hits
        h.sources.append("keyword")
        h.score += 1.0 / (k + rank)
    return list(merged.values())


def _rerank(hits: list[Hit], query: str, terms: list[str]) -> list[Hit]:
    q = query.strip()
    for h in hits:
        bonus = 0.0
        if len(q) >= 4 and q in h.content:
            bonus += 0.25
        if any(t in h.doc_title for t in terms):
            bonus += 0.12
        bonus += min(h.kw_hits, 6) * 0.02
        h.score += bonus
        h.score += (h.vec_score or 0.0) * 0.35  # 向量相似度作为基础权重
    hits.sort(key=lambda h: -h.score)
    return hits


def _recall(db: Session, subq, clearance: int, query: str, terms: list[str],
            vec: list[float]) -> list[Hit]:
    vec_res = _vector_recall(db, subq, clearance, vec, CANDIDATE_POOL)
    kw_res = _keyword_recall(db, subq, clearance, terms, CANDIDATE_POOL)
    return _rerank(_rrf_fuse(vec_res, kw_res), query, terms)


def _empty_verify(mode: str = "dual") -> dict:
    return {"mode": mode, "coarse": {"corpus_docs": 0, "accessible_docs": 0, "excluded": 0},
            "fine": {"checked": 0, "blocked": 0, "delivered": 0},
            "implicit_verify": False}


def _stage_stats(db: Session, subq, candidates: int, mode: str = "dual") -> dict:
    """双校验指标：粗筛排除量 + 精校验明细，供审计与前端展示。"""
    corpus = db.execute(
        select(func.count()).select_from(Document).where(Document.status == "ready")
    ).scalar() or 0
    accessible = db.execute(
        select(func.count()).select_from(subq.subquery())
    ).scalar() or 0
    return {
        "mode": mode,
        "coarse": {"corpus_docs": int(corpus), "accessible_docs": int(accessible),
                   "excluded": max(0, int(corpus) - int(accessible))},
        "fine": {"checked": int(candidates), "blocked": 0, "delivered": 0},
        "implicit_verify": True,
    }


def _deny(denied: list, seen: set, doc: Document, reason: str, kind: str):
    if doc.id in seen:
        return
    seen.add(doc.id)
    denied.append({
        "doc_ref": doc.id[:8],
        "clearance": LEVEL_NAMES.get(doc.clearance, ""),
        "reason": reason,
        "kind": kind,  # doc = 文档级拦截；chunk = 切片级（段落级撕裂）拦截
    })


def search(db: Session, user: User, query: str, top_k: int
           ) -> tuple[list[Hit], list[dict], dict]:
    """返回 (通过全部校验的命中, 被拦截的越权文档摘要, 双校验指标)。"""
    query = (query or "").strip()
    if not query:
        return [], [], _empty_verify()

    subq = accessible_doc_ids(db, user)
    vec = embedder.embed_one(query)
    terms = extract_terms(query)
    hits = _recall(db, subq, user.clearance, query, terms, vec)
    verify = _stage_stats(db, subq, len(hits))

    # ---- 第二道 精校验：细粒度规则比对 + Top-K 密级校验 + 隐式向量验证 ----
    # 隐式向量验证：召回行里的明文字段（标题/密级）一律不可信，
    # 逐条回库重载文档记录重新判定，防止索引污染或缓存越权。
    passed, denied = [], []
    denied_seen: set[str] = set()
    for h in hits:
        doc = db.get(Document, h.doc_id)
        if doc is None:
            continue
        ok, reason = can_access(db, user, doc)
        if not ok:
            _deny(denied, denied_seen, doc, reason, "doc")
            continue
        if h.clearance > user.clearance:
            _deny(denied, denied_seen, doc,
                  f"切片密级不足：该段为「{LEVEL_NAMES.get(h.clearance, '')}」，"
                  f"当前用户为「{LEVEL_NAMES.get(user.clearance, '')}」", "chunk")
            continue
        passed.append(h)
        if len(passed) >= top_k:
            break
    verify["fine"]["blocked"] = len(denied)
    verify["fine"]["delivered"] = len(passed)
    return passed, denied, verify


def public_only_search(db: Session, query: str, top_k: int
                       ) -> tuple[list[Hit], list[dict], dict]:
    """
    Fail-Secure 降级通道：只检索公开域（密级 0 + acl_mode=open），
    与用户身份完全解耦——组件异常时也保证"绝不越权一个字"。
    """
    query = (query or "").strip()
    if not query:
        return [], [], _empty_verify("public_only")
    subq = _public_doc_ids(db)
    vec = embedder.embed_one(query)
    terms = extract_terms(query)
    hits = _recall(db, subq, PUBLIC_CLEARANCE, query, terms, vec)
    verify = _stage_stats(db, subq, len(hits), "public_only")
    hits = hits[:top_k]
    verify["fine"]["delivered"] = len(hits)
    return hits, [], verify


def unauthorized_probe(db: Session, user: User, query: str) -> dict:
    """统计"若无权限控制会命中多少越权文档"——仅返回数量与密级分布，不返回任何内容。"""
    terms = extract_terms(query)
    if not terms:
        return {"total": 0, "by_level": {}}
    cond = or_(*[Chunk.content.like(f"%{t}%") for t in terms])
    subq = accessible_doc_ids(db, user)
    rows = db.execute(
        select(Document.id, Document.clearance)
        .join(Chunk, Chunk.doc_id == Document.id)
        .where(cond, Document.id.not_in(subq))
    ).all()
    by_level: dict[str, int] = {}
    for _did, lvl in rows:
        name = LEVEL_NAMES.get(lvl, "未知")
        by_level[name] = by_level.get(name, 0) + 1
    return {"total": len(rows), "by_level": by_level}


def is_reliable(hits: list[Hit], term_count: int = 1) -> bool:
    """
    防幻觉闸门：相关性过低时直接拒答，而不是让模型编造。
    单一弱关键词命中（如只中了"公司"这种通用词）不足以构成依据；
    本地哈希向量语义能力有限，此时必须以关键词证据为唯一准绳。
    """
    if not hits:
        return False
    top = hits[0]
    coverage = top.kw_hits / max(1, term_count)
    kw_ok = coverage >= MIN_COVERAGE and top.kw_hits >= 2
    if not embedder.api_mode:
        return kw_ok
    return (top.vec_score >= MIN_SCORE) or kw_ok
