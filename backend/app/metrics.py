# SPDX-License-Identifier: Apache-2.0
"""安全指标监控（P2-12 设计文档口径）：多日时序 + 异常判定 + 落盘 + 告警。

与 monitor.py 的分工：
- monitor.py 回答"今天发生了什么"（单日明细：Top 账号/文档、注入、PII、待批、风险账号）；
- 本模块回答"最近 N 天趋势如何、有没有异常"（时序 + block_rate 阈值判定）。

三条硬边界：
1. **纯只读**：只 SELECT 审计，不写审计——否则"拦截率"会把监控自己的心跳算进去，
   越监控越像被攻击。
2. **默认不落盘**：METRICS_ENABLED 默认 false。关着的时候一个字节都不写，
   reports/ 目录都不会创建——监控不该在没有运维同意时往磁盘上堆文件。
3. **告警失败不影响主链路**：webhook 打不通只记 warning，接口照常返回数据。
   告警通道挂掉时，最坏情况应该是"没人收到告警"，而不是"运维看板打不开"。
"""
from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .config import BASE_DIR
from .monitor import (
    BLOCK_DECISIONS, DATE_FORMAT, daily_report, parse_day, report_tz,
)
from .models import AuditLog

# 时序默认跨度与上限（上限防止 ?days=100000 把整张审计表扫穿）
DEFAULT_TREND_DAYS = 14
MAX_TREND_DAYS = 366

# markdown 日报落盘目录：backend/reports/YYYY-MM-DD.md
REPORTS_DIR = Path(BASE_DIR) / "reports"

WEBHOOK_TIMEOUT = 5.0


def trend(db: Session, days: int = DEFAULT_TREND_DAYS) -> dict:
    """按天聚合审计决策，产出时序 + 超阈值告警。

    days 会被夹到 [1, MAX_TREND_DAYS]；日期分桶沿用 monitor.parse_day 的
    REPORT_TZ 左闭右开口径（今日当地 00:00 起往前推 days-1 天），**桶标签与
    行分桶都按 REPORT_TZ 当地日期**（见 _local_date），不是 UTC 日期。
    block_rate = blocked / total，当天无动作记 0（不是 NaN、不是 1）。
    """
    days = max(1, min(int(days or DEFAULT_TREND_DAYS), MAX_TREND_DAYS))
    tz = report_tz()
    today_start, today_end = parse_day()
    start = today_start - timedelta(days=days - 1)

    def _local_date(utc_naive: datetime) -> str:
        """UTC 瞬时 → REPORT_TZ 当地日期字符串（分桶与标签必须同一口径）。

        窗口边界是"当地 0 点"的 UTC 瞬时，行的 ts 是 naive UTC。标签若直接
        按 UTC 日期写，Asia/Shanghai 下 UTC 日期等于"今天"的那半天行会落进
        不存在的桶被整段丢弃——图上看像"今天没数据"，实则是最危险的误判；
        range.end 也会比最后一天差一天。UTC 口径下本函数是恒等变换。
        """
        return utc_naive.replace(tzinfo=timezone.utc).astimezone(tz).strftime(
            DATE_FORMAT)

    series = [
        {"date": _local_date(start + timedelta(days=i)),
         "total": 0, "blocked": 0, "throttled": 0, "flagged": 0, "block_rate": 0.0}
        for i in range(days)
    ]
    index = {row["date"]: row for row in series}

    rows = db.execute(
        select(AuditLog.ts, AuditLog.decision).where(
            AuditLog.ts >= start, AuditLog.ts < today_end)
    ).all()
    for ts, decision in rows:
        if ts is None:
            continue
        bucket = index.get(_local_date(ts))
        if bucket is None:
            continue
        bucket["total"] += 1
        d = decision or ""
        if d in BLOCK_DECISIONS:
            bucket["blocked"] += 1
        elif d == "throttle":
            bucket["throttled"] += 1
        elif d == "flag":
            bucket["flagged"] += 1

    for row in series:
        row["block_rate"] = (
            round(row["blocked"] / row["total"], 4) if row["total"] else 0.0
        )

    alerts = [
        {
            "date": row["date"],
            "block_rate": row["block_rate"],
            "threshold": config.ALERT_BLOCK_RATE,
            "blocked": row["blocked"],
            "total": row["total"],
        }
        for row in series
        # 样本量门槛与拦截率阈值是与关系：量不够就不判定，而不是判成"平安无事"
        if row["total"] >= config.ALERT_MIN_ACTIONS
        and row["block_rate"] > config.ALERT_BLOCK_RATE
    ]
    return {
        "days": days,
        "range": {
            "start": _local_date(start),
            "end": _local_date(today_start),
            "tz": str(tz),
        },
        "series": series,
        "alerts": alerts,
    }


def render_markdown(day_report: dict) -> str:
    """把单日日报（monitor.daily_report 的产物）渲染成 markdown。"""
    rep = day_report or {}
    intercept = rep.get("intercept", {}) or {}
    injection = rep.get("injection", {}) or {}
    pii = rep.get("pii", {}) or {}
    high = rep.get("high_risk", {}) or {}
    totals = rep.get("totals", {}) or {}
    inventory = rep.get("inventory", {}) or {}

    lines: list[str] = [
        f"# fin-rag 运维日报 {rep.get('date', '')}"
        f"（{rep.get('range', {}).get('tz', 'UTC')}）",
        "",
        f"- 请求量 **{totals.get('actions', 0)}** 条，需关注 {totals.get('alerts', 0)} 条",
        f"- 拦截 {intercept.get('blocked', 0)} / 限流 {intercept.get('throttled', 0)}"
        f" / 标记 {intercept.get('flagged', 0)}",
        f"- 注入命中 {injection.get('hits', 0)} 处"
        f"（{injection.get('docs_flagged', 0)} 篇文档），"
        f"问答出口检出 {injection.get('chat_flags', 0)} 次",
        f"- 敏感信息命中 {pii.get('hits', 0)} 处（{pii.get('docs_hit', 0)} 篇文档）",
        f"- 待审批密级变更 {rep.get('approvals_pending', 0)} 单",
        f"- 风险分超阈值（≥{high.get('threshold', 0)}）账号 {high.get('count', 0)} 个",
        "",
        f"> 库内文档 {inventory.get('docs_total', 0)} 篇"
        f"（当日新增 {inventory.get('docs_new_today', 0)}）"
        f" / 账号 {inventory.get('users_total', 0)} 个",
        "",
        "## 触发最多的账号",
        "",
        "| 账号 | 告警次数 | 总动作 |",
        "| --- | --- | --- |",
    ]
    users = rep.get("top_users") or []
    lines += [f"| {u['username']} | {u['alerts']} | {u['actions']} |" for u in users] \
        or ["| （无） | 0 | 0 |"]
    lines += ["", "## 被访问最多的文档", "", "| 文档 | 命中次数 | 其中告警 |", "| --- | --- | --- |"]
    docs = rep.get("top_docs") or []
    lines += [f"| 《{d['title']}》 | {d['hits']} | {d['alerts']} |" for d in docs] \
        or ["| （无） | 0 | 0 |"]
    accounts = high.get("accounts") or []
    if accounts:
        lines += ["", "## 待人工审核账号", ""]
        lines += [f"- {a['username']}（有效风险分 {a['risk']}）" for a in accounts]
    lines += ["", f"<!-- 生成于 {rep.get('generated_at', '')}，数据源：审计日志（只读聚合） -->"]
    return "\n".join(lines)


def write_markdown(day_report: dict, base_dir: str | Path | None = None) -> str | None:
    """落盘 markdown 日报，返回路径；METRICS_ENABLED 为假时返回 None 且不建目录。

    目录创建刻意放在开关判断之后：关着的时候连 reports/ 都不该凭空出现。
    """
    if not config.METRICS_ENABLED:
        return None
    day = (day_report or {}).get("date") or datetime.now(report_tz()).strftime(DATE_FORMAT)
    target = Path(base_dir) if base_dir else REPORTS_DIR
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{day}.md"
    path.write_text(render_markdown(day_report), encoding="utf-8")
    return str(path)


def cleanup_old_reports(days: int | None = None,
                        reports_dir: str | Path | None = None) -> dict:
    """清理超过保留天数的日报 markdown（只删文件，不建目录、不碰库表）。

    按文件名里的日期（YYYY-MM-DD.md）判定新旧而不是 mtime：文件可能被拷贝、
    同步，写在名字里的日期才是运营语义上的"哪天的日报"。名字解析不了的
    文件一律不动并单独计数——reports/ 里万一放了运维的其他东西，不能误删。

    目录不存在直接返回空结果：清理是幂等的，不该为了清理而凭空创建目录
    （与 write_markdown"关着时连 reports/ 都不该出现"的同一条哲学）。

    days 缺省取 METRICS_RETENTION_DAYS，夹到 [1, 3650]；reports_dir 缺省取
    模块级 REPORTS_DIR（测试注入临时目录用）。
    """
    days = config.METRICS_RETENTION_DAYS if days is None else int(days)
    days = max(1, min(int(days), 3650))
    target = REPORTS_DIR if reports_dir is None else Path(reports_dir)
    if not target.is_dir():
        return {"days": days, "deleted": [], "kept": 0, "unparsable": 0}
    cutoff = datetime.now(report_tz()).date() - timedelta(days=days)
    deleted: list[str] = []
    kept = 0
    unparsable = 0
    for path in sorted(target.glob("*.md")):
        try:
            file_day = datetime.strptime(path.stem, DATE_FORMAT).date()
        except ValueError:
            unparsable += 1
            continue
        if file_day < cutoff:
            path.unlink()
            deleted.append(path.name)
        else:
            kept += 1
    return {"days": days, "deleted": deleted, "kept": kept, "unparsable": unparsable}


def send_alert(alerts: list[dict], date: str = "") -> dict:
    """把异常日摘要 POST 到 ALERT_WEBHOOK_URL。

    URL 为空 → 整段跳过；发送失败 → 只 warnings.warn，绝不向上抛。
    用项目已有的 httpx（requirements.txt 已声明 httpx>=0.26），不引新依赖；
    非 2xx 响应同样按失败处理——webhook 回 4xx/5xx 说明告警没能送达。
    """
    url = (config.ALERT_WEBHOOK_URL or "").strip()
    if not url:
        return {"sent": False, "reason": "未配置 ALERT_WEBHOOK_URL，跳过告警推送"}
    if not alerts:
        return {"sent": False, "reason": "无异常日，无需推送"}

    payload = {
        "source": "fin-rag-metrics",
        "date": date or (alerts[0].get("date") if alerts else ""),
        "alert_count": len(alerts),
        "alerts": alerts,
        "summary": "；".join(
            f"{a['date']} 拦截率 {a['block_rate']} 超阈值 {a['threshold']}"
            f"（{a['blocked']}/{a['total']}）" for a in alerts
        ),
    }
    try:
        resp = httpx.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
    except httpx.HTTPError as e:
        # 告警通道挂了不影响看板：运维还能打开 /api/admin/metrics 自己看
        warnings.warn(f"[metrics] 告警推送失败（{url}）：{e}")
        return {"sent": False, "reason": f"推送失败：{e}"}
    if resp.status_code >= 400:
        warnings.warn(f"[metrics] 告警推送被拒（{url}）：HTTP {resp.status_code}")
        return {"sent": False, "reason": f"推送失败：HTTP {resp.status_code}"}
    return {"sent": True, "status": resp.status_code}


def build_metrics(db: Session, days: int = DEFAULT_TREND_DAYS) -> dict:
    """一次性产出接口所需的全部内容：时序 + 告警 +（启用时）落盘与推送。"""
    t = trend(db, days)
    out: dict = {
        "enabled": config.METRICS_ENABLED,
        "days": t["days"],
        "range": t["range"],
        "series": t["series"],
        "alerts": t["alerts"],
        "markdown_path": "",
    }
    if not config.METRICS_ENABLED:
        return out
    out["markdown_path"] = write_markdown(daily_report(db)) or ""
    out["webhook"] = send_alert(t["alerts"])
    return out
