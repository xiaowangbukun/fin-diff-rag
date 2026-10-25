# SPDX-License-Identifier: AGPL-3.0-only
"""
拼图攻击（Jigsaw Attack / Salami Slicing）防护引擎。

威胁模型
--------
攻击者每一次提问都"合法"——召回的内容确实在其授权范围内，单次策略判定必然放行。
他靠的是多轮窄问，每次换取同一篇文档的不同切片，离线拼接即可还原全貌。
另一种形态是直接 GET 文档详情一次性拉走全部切片，连"拼"的步骤都省了。

结论：**单次判定在数学上无法防御拼图攻击**，必须在服务端维护跨会话的累积暴露账本，
以"已披露比例"而不是"单次请求合法性"作为裁决依据。

四道防线
--------
L1 单文档覆盖率闸：已见切片数 / 文档总切片数
     >= WARN → 每轮最多再给 1 段（限流）； >= STOP → 停止供给该文档的新切片
     短文档（段数低于 JIGSAW_MIN_DOC_CHUNKS）不启用：2 段文档问两句就 100%，
     本身没有"可拼"的空间，启用只会把正常用户锁死。
L1b 重复提问豁免：候选全部是已见切片时不构成新增泄漏，允许重放，不计入预算。
     拼图攻击的本质是"每次换新碎片"，重复拿同一碎片没有边际收益。
L2 单文档切片配额：窗口内单用户对单文档可见切片总数上限
L2b 单轮交付上限：单轮单文档最多交付 N 段新切片。
    这一条最容易被忽略却最致命——top_k=8 时，一篇 9 段的文档一轮就能被拿走 89%，
    覆盖率闸再严也拦不住"一轮搬空"。必须从单轮就开始限流。
L3 用户窗口总闸：窗口内触及文档数与累计披露字符总量上限 → 直接停答进入冷却
L4 全篇直读闸：限制绕过问答直接拉全文的次数，且读过的切片计入同一本账，
                防止"先全文读、再用问答补漏"的组合式绕过

所有拦截结果写入审计日志（decision=throttle/block），并在管理端风险榜可查。
"""
import json
import time
import warnings
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import (
    JIGSAW_ADMIN_EXEMPT, JIGSAW_DOC_COVER_STOP, JIGSAW_DOC_COVER_WARN,
    JIGSAW_ENABLED, JIGSAW_FULLREAD_LIMIT, JIGSAW_LONG_DOC_CHAR,
    JIGSAW_LONG_USER_CHAR, JIGSAW_LONG_WINDOW_DAYS, JIGSAW_MAX_CHUNKS_PER_DOC,
    JIGSAW_MAX_PER_TURN, JIGSAW_MIN_DOC_CHUNKS, JIGSAW_RISK_READONLY,
    JIGSAW_USER_CHAR_LIMIT, JIGSAW_USER_DOC_LIMIT, JIGSAW_WINDOW_HOURS,
)
from .models import Chunk, ExposureLedger, User

SEEN_DETAIL_CAP = 3000      # 明细存储上限，超出后仅保留计数
_ORDER = {"none": 0, "warn": 1, "restrict": 2, "block": 3}


def _max_level(a: str, b: str) -> str:
    return a if _ORDER[a] >= _ORDER[b] else b


def _window_key() -> str:
    """滚动窗口桶编号：天然过期，无需清理任务。"""
    span = max(1, JIGSAW_WINDOW_HOURS) * 3600
    return f"w{int(time.time()) // span}"


def current_window_key() -> str:
    """对外暴露的窗口键（意图网关等模块需要同一口径）。"""
    return _window_key()


def _emtpy_report() -> dict:
    return {
        "level": "none", "message": "", "docs": [],
        "window": {"docs": 0, "chars": 0, "queries": 0},
    }


def _load_seen(row: ExposureLedger | None) -> set[str]:
    if row is None or not row.seen_chunks:
        return set()
    try:
        return set(json.loads(row.seen_chunks))
    except Exception:
        return set()


def _touch(db: Session, user_id: str, doc_id: str) -> ExposureLedger:
    wk = _window_key()
    row = db.execute(
        select(ExposureLedger).where(
            ExposureLedger.user_id == user_id,
            ExposureLedger.doc_id == doc_id,
            ExposureLedger.window_key == wk,
        )
    ).scalars().first()
    if row is None:
        row = ExposureLedger(user_id=user_id, doc_id=doc_id, window_key=wk)
        db.add(row)
        db.flush()
    return row


def _doc_chunk_total(db: Session, doc_id: str) -> int:
    return int(db.execute(
        select(func.count()).select_from(Chunk).where(Chunk.doc_id == doc_id)
    ).scalar() or 0)


def _exempt(user) -> bool:
    return bool(JIGSAW_ADMIN_EXEMPT) and "admin" in user.role_list()


def long_window_keys(days: int) -> list[str]:
    """反推近 N 天覆盖到的全部滚动窗口键。

    window_key = f"w{epoch // span}" 是纯算术结果，可以直接往前推，
    不需要额外字段就能把短窗口记账聚合成长周期口径——零 schema 变更。
    span=24h 时 7 天是 7 个键；span=1h 时是 168 个（IN 列表由
    ix_exposure_user_window 索引覆盖，可接受）。
    """
    import math

    span = max(1, JIGSAW_WINDOW_HOURS) * 3600
    base = int(time.time()) // span
    n = max(1, math.ceil(days * 86400 / span))
    return [f"w{base - i}" for i in range(n)]


def long_period_totals(db: Session, user) -> tuple[int, dict[str, int]]:
    """近 N 日的累计披露字符量：返回 (用户总量, {文档 id: 该文档总量})。

    口径用 char_total 而不是 seen_count：char_total 按窗口行累加精确无重叠；
    seen_count 各窗口存的是窗口内集合，跨窗口取并集要么依赖明细、要么失真近似。
    """
    keys = long_window_keys(max(1, JIGSAW_LONG_WINDOW_DAYS))
    rows = db.execute(
        select(ExposureLedger.doc_id, ExposureLedger.char_total).where(
            ExposureLedger.user_id == user.id,
            ExposureLedger.window_key.in_(keys),
        )
    ).all()
    per_doc: dict[str, int] = {}
    for doc_id, chars in rows:
        per_doc[doc_id] = per_doc.get(doc_id, 0) + int(chars or 0)
    return sum(per_doc.values()), per_doc


def effective_risk(risk_score: int, last_risk_ts, now=None) -> int:
    """惰性衰减后的有效风险分：每满 30 天减去 1，最低 0。

    不写库——衰减是读取时计算，避免定时任务在无人访问时也要扫全表。
    """
    if not risk_score or last_risk_ts is None:
        return 0
    now = now or datetime.utcnow()
    try:
        days = max(0, (now - last_risk_ts).days)
    except Exception:
        return max(0, int(risk_score))
    return max(0, int(risk_score) - (days // 30))


def bump_risk(db: Session, user) -> int:
    """风险事件 +1（防拼图 block / 单文档停机阈值）。返回累加后的分数。

    用**调用方 Session 的 savepoint** 提交，不再另起独立 Session：
    独立 Session 会另起一条连接与一个事务，既看不到调用方尚未提交的账本写入，
    又要与之争同一行锁；更糟的是那个异常没人兜，会一路冒泡把"被限流"的请求
    打成 500。savepoint 把这次提交挂在调用方事务上，语义清晰且不会引入第二条连接。

    提交是必须的：block 路径上调用方随后会随请求结束回滚，不提交则风险分
    永远留不住，长周期闸也就永远升不了级（等于整条 P1-7 失效）。
    当前两个调用点都在账本写入之前 return，所以这次提交不会顺带把
    "被拦下的提问"记进账本；将来若在账本写入之后调用，需重新评估这一点。

    任何异常一律吞掉并记 warning：风险分只是画像，累加失败绝不能影响主流程响应。
    """
    try:
        u = db.get(User, user.id)
        if u is None:
            return 0
        u.risk_score = int(u.risk_score or 0) + 1
        u.last_risk_ts = datetime.utcnow()
        score, ts = int(u.risk_score), u.last_risk_ts
        with db.begin_nested():  # savepoint：写入失败只回滚这一笔，不污染外层事务
            db.flush()
        db.commit()
    except Exception as e:  # 兜住：宁可少记一笔风险分，也不能把请求打挂
        warnings.warn(f"[jigsaw] 风险分累加失败（已忽略，不影响主流程）：{e}")
        try:
            db.rollback()
        except Exception:
            pass
        return 0
    # 同步给调用方持有的对象，保证同一请求内再判定（如 chat 入口拦截）是最新值
    try:
        user.risk_score = score
        user.last_risk_ts = ts
    except Exception:
        pass
    return score


def is_high_risk(user) -> bool:
    """有效风险分达到阈值 → 该账号的访问权限已交人工审核。

    admin 豁免与 JIGSAW_ADMIN_EXEMPT 保持同一口径：管理员日常要看全量风险榜，
    被自己的策略锁住会直接瘫痪运营。
    """
    if JIGSAW_RISK_READONLY <= 0 or _exempt(user):
        return False
    return effective_risk(user.risk_score, user.last_risk_ts) >= JIGSAW_RISK_READONLY


def evaluate(db: Session, user, hits: list) -> tuple[list, dict]:
    """
    对检索结果做累积暴露裁决。

    返回 (本轮允许交付的 hits, 风险报告)。副作用：把本轮交付的切片记入账本并提交。
    调用方必须放在权限后置校验之后——这里假定 hits 本身已通过权限校验。
    """
    report = _emtpy_report()
    if not JIGSAW_ENABLED or _exempt(user) or not hits:
        return hits, report

    wk = _window_key()
    rows = db.execute(
        select(ExposureLedger).where(
            ExposureLedger.user_id == user.id, ExposureLedger.window_key == wk
        )
    ).scalars().all()
    ledger = {r.doc_id: r for r in rows}

    win_docs = len(rows)
    win_chars = sum(r.char_total for r in rows)
    win_queries = sum(r.query_count for r in rows)
    report["window"] = {"docs": win_docs, "chars": win_chars, "queries": win_queries}

    # ---- L3 用户窗口总闸 ----
    if win_chars >= JIGSAW_USER_CHAR_LIMIT or win_docs >= JIGSAW_USER_DOC_LIMIT:
        report["level"] = "block"
        report["message"] = (
            f"本时间窗（{JIGSAW_WINDOW_HOURS} 小时）内已触及 {win_docs} 篇文档、"
            f"累计披露 {win_chars} 字符，超出防批量拉取阈值，已暂停应答。"
            f"如需批量导出请走合规审批流程。"
        )
        bump_risk(db, user)
        return [], report

    # ---- L5 长周期累计闸（P1-7）：堵慢速拼图 ----
    # 短窗口滚过去就清零，攻击者每天卡在阈值 90% 慢拉，长期照样搬空语料。
    # 放在 L3 之后：短窗口先挡急性批量拉取，长周期挡慢性渗透。
    days = max(1, JIGSAW_LONG_WINDOW_DAYS)
    long_chars, long_per_doc = long_period_totals(db, user)
    report["long"] = {
        "days": days, "chars": long_chars, "user_limit": JIGSAW_LONG_USER_CHAR,
    }
    if long_chars >= JIGSAW_LONG_USER_CHAR:
        report["level"] = "block"
        report["message"] = (
            f"近 {days} 日累计披露已达 {long_chars} 字符，超出长期防批量拉取阈值"
            f"（{JIGSAW_LONG_USER_CHAR}），已暂停应答。如需长期批量用数请走合规审批流程。"
        )
        bump_risk(db, user)
        return [], report

    by_doc: dict[str, list] = {}
    for h in hits:
        by_doc.setdefault(h.doc_id, []).append(h)

    level = "none"
    reasons: list[str] = []
    allowed: list = []

    for doc_id, group in by_doc.items():
        row = ledger.get(doc_id) or _touch(db, user.id, doc_id)
        seen = _load_seen(row)
        seen_n = max(row.seen_count, len(seen))
        total = _doc_chunk_total(db, doc_id) or seen_n
        title = group[0].doc_title

        row.query_count += 1

        # 本轮候选里真正是"新信息"的切片
        fresh = [h for h in group if h.chunk_id not in seen]

        # ---- L1b 重复提问豁免：没有新碎片 = 没有新增泄漏，允许重放 ----
        # 注意：这不是限流。capped 必须为 False，否则前端会把正常的重复提问
        # 显示成"已被防拼图拦截"，用户会以为自己被系统盯上了。
        if not fresh:
            replay = group[:JIGSAW_MAX_PER_TURN]
            allowed.extend(replay)
            report["docs"].append({
                "doc_id": doc_id, "title": title, "seen": seen_n, "total": total,
                "coverage": round(seen_n / max(1, total), 3),
                "delivered": 0, "replayed": len(replay), "capped": False,
            })
            continue

        # ---- 短文档不启用覆盖率闸（无拼图价值，避免误伤）----
        coverage = (seen_n / max(1, total)) if total >= JIGSAW_MIN_DOC_CHUNKS else 0.0
        capped = False

        # ---- L2 切片配额 ----
        budget = max(0, JIGSAW_MAX_CHUNKS_PER_DOC - seen_n)

        # ---- L2b 单轮交付上限：无论覆盖率多低，单轮都不许一次搬空一篇 ----
        budget = min(budget, JIGSAW_MAX_PER_TURN)

        # ---- L1 覆盖率闸 ----
        if coverage >= JIGSAW_DOC_COVER_STOP:
            budget = 0
            capped = True
            reasons.append(
                f"《{title}》已向你披露 {seen_n}/{total} 段（{coverage:.0%}），"
                f"达到防拼图停机阈值，本轮起暂停提供该文档新内容"
            )
            level = _max_level(level, "restrict")
        elif coverage >= JIGSAW_DOC_COVER_WARN:
            budget = min(budget, 1)
            capped = True
            reasons.append(
                f"《{title}》累计披露已达 {coverage:.0%}（{seen_n}/{total} 段），"
                f"已触发防拼图限流，每次仅返回 1 段新内容"
            )
            level = _max_level(level, "warn")

        # ---- L5b 单文档长周期闸（P1-7）：近 N 日累计字符超上限 → 该文档停机 ----
        # 与短窗口互补：单文档每天取一点点，短窗口覆盖率闸永远看不到全貌，
        # 但字符量会持续累积，长周期口径能识别这种"蚂蚁搬家"。
        doc_long = int(long_per_doc.get(doc_id, 0))
        if doc_long >= JIGSAW_LONG_DOC_CHAR:
            budget = 0
            capped = True
            reasons.append(
                f"《{title}》近 {days} 日已累计披露 {doc_long} 字符，"
                f"达到长期累计上限（{JIGSAW_LONG_DOC_CHAR}），"
                f"本轮起暂停提供该文档新内容"
            )
            level = _max_level(level, "restrict")

        take = fresh[:budget]
        if group and not take and fresh:
            reasons.append(f"《{title}》本时间窗切片配额已用尽（{seen_n}/{JIGSAW_MAX_CHUNKS_PER_DOC}）")
            level = _max_level(level, "restrict")

        for h in take:
            seen.add(h.chunk_id)
            allowed.append(h)

        added = sum(len(h.content or "") for h in take)
        row.seen_count = len(seen) if len(seen) <= SEEN_DETAIL_CAP else max(row.seen_count, len(seen))
        if len(seen) <= SEEN_DETAIL_CAP:
            row.seen_chunks = json.dumps(sorted(seen))
        row.char_total += added
        row.last_ts = datetime.utcnow()

        report["docs"].append({
            "doc_id": doc_id, "title": title, "seen": seen_n, "total": total,
            "coverage": round(coverage, 3), "delivered": len(take), "capped": capped,
        })

    # 风险分刻意**只记 block，不记单文档停机阈值（L1 STOP）**：
    # 单文档 70% 覆盖率是正常深度阅读也会撞到的——一个认真啃同一份材料的分析师
    # 一个月内撞三次就被锁死，这是把正常工作方式当成攻击。真正异常的是跨文档的
    # 批量拉取（短窗口 12 万字符 / 近 7 日 6 万字符），那才是要留画像的行为。
    db.commit()

    report["level"] = level
    if reasons:
        report["message"] = "；".join(dict.fromkeys(reasons))
    return allowed, report


def check_full_read(db: Session, user, doc) -> tuple[bool, str]:
    """L4 前置检查：是否还允许一次性读取该文档全文。"""
    if not JIGSAW_ENABLED or _exempt(user):
        return True, ""
    row = db.execute(
        select(ExposureLedger).where(
            ExposureLedger.user_id == user.id,
            ExposureLedger.doc_id == doc.id,
            ExposureLedger.window_key == _window_key(),
        )
    ).scalars().first()
    used = row.full_read_count if row else 0
    if used >= JIGSAW_FULLREAD_LIMIT:
        return False, (
            f"《{doc.title}》在本时间窗内已全文读取 {used} 次，达到上限（{JIGSAW_FULLREAD_LIMIT} 次）。"
            f"防批量拉取策略已生效，如需继续请通过对该文档的具体提问获取。"
        )
    return True, ""


def record_full_read(db: Session, user, doc, chunks: list) -> None:
    """
    全文读取同样计入同一本账：既限制次数，又把已读切片标记为已披露，
    堵住"全文通读 + 问答补漏"的组合式拼图。
    """
    if not JIGSAW_ENABLED or _exempt(user):
        return
    row = _touch(db, user.id, doc.id)
    seen = _load_seen(row)
    seen.update(c.id for c in chunks)
    row.full_read_count += 1
    # max 保护：明细被截断或 JSON 解析失败时 _load_seen 只能拿到残缺集合，
    # 直接写 len(seen) 会把已披露计数往回调——那等于给攻击者一条刷新额度的捷径。
    row.seen_count = max(int(row.seen_count or 0), len(seen))
    if len(seen) <= SEEN_DETAIL_CAP:
        row.seen_chunks = json.dumps(sorted(seen))
    row.char_total += sum(len(c.content or "") for c in chunks)
    row.last_ts = datetime.utcnow()
    db.commit()


def risk_board(db: Session, limit: int = 20) -> list[dict]:
    """管理端拼图风险榜：按累积披露比例排序的高危 用户×文档 组合。"""
    rows = db.execute(
        select(ExposureLedger).order_by(ExposureLedger.seen_count.desc()).limit(200)
    ).scalars().all()
    out = []
    for r in rows:
        total = _doc_chunk_total(db, r.doc_id)
        cov = (r.seen_count / total) if total else 0.0
        # 短文档不启用覆盖率闸，风险榜同样不报，避免噪声淹没真实信号
        if total < JIGSAW_MIN_DOC_CHUNKS:
            risk = "low"
        elif cov >= JIGSAW_DOC_COVER_STOP:
            risk = "high"
        elif cov >= JIGSAW_DOC_COVER_WARN:
            risk = "medium"
        else:
            risk = "low"
        out.append({
            "user_id": r.user_id, "doc_id": r.doc_id,
            "seen": r.seen_count, "total": total,
            "coverage": round(cov, 3), "chars": r.char_total,
            "queries": r.query_count, "full_reads": r.full_read_count,
            "window": r.window_key, "risk": risk,
        })
    out.sort(key=lambda x: (-x["coverage"], -x["chars"]))
    return [o for o in out if o["risk"] != "low"][:limit]
