# SPDX-License-Identifier: AGPL-3.0-only
"""运维监控日报（P2-12）：按自然日聚合审计日志与库内状态，只读产出。

为什么只读：日报本身不该往审计链里写东西。写一行"生成了日报"的审计，
明天的"拦截数"里就多一条噪音；更糟的是它会让 hashes 链随看板刷新而增长，
把"审计链被改过"和"有人看了日报"混成同一件事。所以本模块只做 SELECT。

时间与口径：审计 ts 以 naive UTC 落库（datetime.utcnow），日报按 REPORT_TZ
（默认 Asia/Shanghai）的当地自然日切分——中国运营看"今天"不会错位成昨天，
时区由 parse_day/report_tz 统一换算，存储语义不动。
"""
from __future__ import annotations

import re
import warnings
from collections import Counter
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import JIGSAW_RISK_READONLY, REPORT_INCLUDE_TEXT, REPORT_TZ, REPORT_TOP_N
from .jigsaw import effective_risk
from .models import ApprovalRequest, AuditLog, Document, User

# 日报只关心"被处置过的动作"：放行量单独统计，不进告警榜。
ALERT_DECISIONS: tuple[str, ...] = (
    "deny", "throttle", "flag", "block", "degrade", "mask",
)

# 拦截类（deny 与等价的拒答/降级口径）与限流类分别计价，
# 运营看的是"被拦下多少"和"被拖慢多少"两个不同信号。
BLOCK_DECISIONS: tuple[str, ...] = ("deny", "abstain", "block", "degrade")

# 计入"文档被访问"的动作范围：刻意只取文档相关动作——
# create_user / login 等也带 target_id（那是用户 id），混进来会让"热门文档"
# 榜首变成用户名，运营一眼看上去就是在读一份叫 "research" 的文档。
DOC_ACTIONS: tuple[str, ...] = (
    "chat", "view", "search", "upload", "update", "delete", "grant", "revoke",
)

DATE_FORMAT = "%Y-%m-%d"

# 严格日期形状：四位数年 + 补零月日。strptime 本身会放行 "2024-3-5"，
# 但前端日期选择器与定时任务都只会产出补零格式，放行非补零只会让
# "同一天"出现两种 key（2024-03-05 与 2024-3-5），趋势图上就是两条线。
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def report_tz() -> tzinfo:
    """REPORT_TZ 的有效时区对象；无法识别时告警并回落固定 UTC。

    两级保护：
    1. 配错时区字符串（打字错误、环境没注入）→ 退回 UTC，口径回到旧行为，
       看板照常出，但告警必须留——静默回落等于把错口径的数据当正常数据用；
    2. 连 ZoneInfo 都不可用（Windows 无系统 tz 数据库且未装 tzdata 包，
       见 requirements.txt）→ 用 datetime.timezone.utc 固定偏移兜底，
       保证日报链路永远不因为时区问题整个挂掉。
    """
    try:
        return ZoneInfo(REPORT_TZ)
    except Exception:
        warnings.warn(
            f"REPORT_TZ={REPORT_TZ!r} 无法识别，已回落 UTC"
            "（Windows 环境请确认已安装 tzdata 包，见 requirements.txt）",
            RuntimeWarning, stacklevel=2)
    return timezone.utc


def parse_day(date: str | None = None) -> tuple[datetime, datetime]:
    """解析日报日期 → (当日 00:00:00, 次日 00:00:00)，均为 naive UTC。

    日期按 REPORT_TZ 的当地日解释，再换算成 UTC 瞬时：
    REPORT_TZ=Asia/Shanghai 时 2026-10-19 的起始边界是 2026-10-18 16:00:00。
    date 为空表示 REPORT_TZ 的"今天"；格式错误抛 ValueError，由路由层转 400——
    静默吞掉会导致日报算出一张空表，运营会误判成"今天没有风险事件"。

    存储侧 ts 是 naive UTC，本函数只负责"当地日 → UTC 瞬时"的换算，
    不改动任何存储语义。
    """
    tz = report_tz()
    if date:
        day = (date or "").strip()[:10]
        if not _DAY_RE.match(day):
            raise ValueError(f"日期格式应为 {DATE_FORMAT}（须补零，如 2026-01-05），实际：{date}")
        try:
            local_midnight = datetime.strptime(day, DATE_FORMAT)
        except ValueError as e:
            raise ValueError(f"日期格式应为 {DATE_FORMAT}，实际：{date}") from e
    else:
        local_midnight = datetime.now(tz).replace(
            hour=0, minute=0, second=0, microsecond=0)
    start = local_midnight.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)
    return start, start + timedelta(days=1)


def daily_report(db: Session, date: str | None = None, top_n: int = 0) -> dict:
    """生成指定日期的运维日报（结构化 dict）。

    top_n 为 0 时取配置 REPORT_TOP_N。返回的 dict 可直接 JSON 序列化，
    也可交给 render_report() 渲染成人类可读文本。
    """
    top_n = max(1, int(top_n or REPORT_TOP_N))
    tz = report_tz()
    start, end = parse_day(date)
    # 日报标题必须用**当地日期**：start 是 UTC 瞬时（Asia/Shanghai 下为前一日
    # 16:00），直接 strftime 会把"今天的日报"标成昨天——运营按标题找当天报表
    # 会找不到，而"报表没生成"和"标题差一天"是两种完全不同的事故。
    day = start.replace(tzinfo=timezone.utc).astimezone(tz).strftime(DATE_FORMAT)

    rows = db.execute(
        select(AuditLog).where(AuditLog.ts >= start, AuditLog.ts < end)
    ).scalars().all()

    decisions: Counter = Counter((r.decision or "") for r in rows)
    actions: Counter = Counter((r.action or "") for r in rows)

    # ---- 用户榜：按"被处置次数"排序（放行量再多也不算风险）----
    alert_by_user: Counter = Counter()
    action_by_user: Counter = Counter()
    for r in rows:
        if not r.username:
            continue
        action_by_user[r.username] += 1
        if (r.decision or "") in ALERT_DECISIONS:
            alert_by_user[r.username] += 1
    top_users = [
        {"username": u, "alerts": c, "actions": action_by_user[u]}
        for u, c in alert_by_user.most_common(top_n)
    ]

    # ---- 文档榜：按被访问/被命中次数排序，标题回库解析（已删除则退回标签）----
    hit_by_doc: Counter = Counter()
    alert_by_doc: Counter = Counter()
    labels: dict[str, str] = {}
    for r in rows:
        if not r.target_id or (r.action or "") not in DOC_ACTIONS:
            continue
        hit_by_doc[r.target_id] += 1
        labels.setdefault(r.target_id, r.target_label or "")
        if (r.decision or "") in ALERT_DECISIONS:
            alert_by_doc[r.target_id] += 1
    top_docs = []
    for doc_id, hits in hit_by_doc.most_common(top_n):
        d = db.get(Document, doc_id)
        top_docs.append({
            "doc_id": doc_id,
            "title": d.title if d else (labels.get(doc_id) or "(已删除)"),
            "hits": hits,
            "alerts": alert_by_doc.get(doc_id, 0),
        })

    # ---- 注入 / PII：当日入库文档的命中情况 ----
    docs_today = db.execute(
        select(Document).where(Document.created_at >= start, Document.created_at < end)
    ).scalars().all()
    inject_docs = [d for d in docs_today if int(d.inject_risk or 0) > 0]
    pii_docs = [d for d in docs_today if int(d.pii_hits or 0) > 0]
    chat_inject_flags = sum(
        1 for r in rows
        if (r.decision or "") == "flag" and "注入" in (r.reason or "")
    )

    # ---- 待批密级变更单：卡在队列里没人处理的降密申请 ----
    pending_approvals = db.execute(
        select(func.count()).select_from(ApprovalRequest).where(
            ApprovalRequest.status == "pending")
    ).scalar() or 0

    # ---- 风险分超阈值账号：已转人工审核、等待处置的账号 ----
    now = datetime.utcnow()
    high_risk_accounts = []
    for u in db.execute(select(User)).scalars().all():
        score = effective_risk(u.risk_score, u.last_risk_ts, now)
        if score >= JIGSAW_RISK_READONLY:
            high_risk_accounts.append({"username": u.username, "risk": score})

    blocked = sum(decisions.get(k, 0) for k in BLOCK_DECISIONS)
    return {
        "date": day,
        "generated_at": now.replace(tzinfo=timezone.utc).astimezone(
            report_tz()).strftime("%Y-%m-%d %H:%M:%S"),
        "range": {
            "start": start.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end.strftime("%Y-%m-%d %H:%M:%S"),
            "tz": str(report_tz()),
        },
        "totals": {
            "actions": len(rows),
            "alerts": sum(decisions.get(k, 0) for k in ALERT_DECISIONS),
        },
        "decisions": {
            "deny": decisions.get("deny", 0),
            "throttle": decisions.get("throttle", 0),
            "flag": decisions.get("flag", 0),
            "block": decisions.get("block", 0),
            "degrade": decisions.get("degrade", 0),
            "mask": decisions.get("mask", 0),
            "abstain": decisions.get("abstain", 0),
            "allow": decisions.get("allow", 0),
        },
        "intercept": {
            "blocked": blocked,
            "throttled": decisions.get("throttle", 0),
            "flagged": decisions.get("flag", 0),
        },
        "actions_top": [
            {"action": a, "count": c} for a, c in actions.most_common(top_n)
        ],
        "top_users": top_users,
        "top_docs": top_docs,
        "injection": {
            "docs_flagged": len(inject_docs),
            "hits": sum(int(d.inject_risk or 0) for d in inject_docs),
            "chat_flags": chat_inject_flags,
        },
        "pii": {
            "docs_hit": len(pii_docs),
            "hits": sum(int(d.pii_hits or 0) for d in pii_docs),
        },
        "approvals_pending": pending_approvals,
        "high_risk": {
            "threshold": JIGSAW_RISK_READONLY,
            "count": len(high_risk_accounts),
            "accounts": high_risk_accounts[:top_n],
        },
        "inventory": {
            "docs_total": db.execute(
                select(func.count()).select_from(Document)).scalar() or 0,
            "users_total": db.execute(
                select(func.count()).select_from(User)).scalar() or 0,
            "docs_new_today": len(docs_today),
        },
    }


def render_report(rep: dict) -> str:
    """把日报 dict 渲染成可直接贴进日报/群播的文本（人读比 JSON 快）。"""
    line = "-" * 46
    parts: list[str] = [
        f"fin-rag 运维日报 {rep.get('date', '')}（{rep.get('range', {}).get('tz', 'UTC')}）",
        line,
        f"请求量 {rep['totals']['actions']} 条，需关注 {rep['totals']['alerts']} 条",
        f"拦截 {rep['intercept']['blocked']} / 限流 {rep['intercept']['throttled']}"
        f" / 标记 {rep['intercept']['flagged']}",
        f"注入命中 {rep['injection']['hits']} 处（{rep['injection']['docs_flagged']} 篇文档）"
        f"，问答出口检出 {rep['injection']['chat_flags']} 次",
        f"敏感信息命中 {rep['pii']['hits']} 处（{rep['pii']['docs_hit']} 篇文档）",
        f"待审批密级变更 {rep['approvals_pending']} 单",
        f"风险分超阈值（≥{rep['high_risk']['threshold']}）账号 "
        f"{rep['high_risk']['count']} 个",
        line,
    ]
    users = rep.get("top_users") or []
    parts.append("触发最多的账号：" + ("、".join(
        f"{u['username']}（{u['alerts']} 次）" for u in users) if users else "无"))
    docs = rep.get("top_docs") or []
    parts.append("被访问最多的文档：" + ("、".join(
        f"《{d['title']}》（{d['hits']} 次）" for d in docs) if docs else "无"))
    accounts = rep.get("high_risk", {}).get("accounts") or []
    if accounts:
        parts.append("待人工审核账号：" + "、".join(
            f"{a['username']}（{a['risk']} 分）" for a in accounts))
    parts.append(line)
    parts.append(f"库内：文档 {rep['inventory']['docs_total']} 篇"
                 f"（当日新增 {rep['inventory']['docs_new_today']}）"
                 f" / 账号 {rep['inventory']['users_total']} 个")
    return "\n".join(parts)


def daily_report_text(db: Session, date: str | None = None, top_n: int = 0) -> str:
    """一步拿到文本日报（供脚本/定时任务直接调用）。"""
    return render_report(daily_report(db, date=date, top_n=top_n))


def include_text() -> bool:
    """接口是否附带 text 字段（大库下可关掉以省带宽）。"""
    return bool(REPORT_INCLUDE_TEXT)
