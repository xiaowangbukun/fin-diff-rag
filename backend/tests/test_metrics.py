# SPDX-License-Identifier: AGPL-3.0-only
"""metrics.py —— 安全指标监控单元测试（P2-12）。

三条硬边界，本文件逐条钉住：
  1. **纯只读**：只 SELECT 审计，不写审计（否则拦截率会把监控自己的心跳算进去）；
  2. **默认不落盘**：METRICS_ENABLED 默认 false，关着时连 reports/ 目录都不建；
  3. **告警失败不影响主链路**：webhook 打不通只 warn，接口照常返回。

开关口径（与 monitor.py 不同，别用同一套打法）：
  metrics.py 是 `from . import config` + `config.X` **惰性读**，所以 patch
  `app.config.X` 生效；而 monitor.py 是导入时拷值，得 patch `app.monitor.X`。
  下面 `cfg` 夹具就是按惰性读写的，并有一条用例专门证明这个差异。

webhook 失败路径刻意用假 httpx.post 而不是真连 socket：本环境把 127.0.0.1:9
黑洞化了（真连会等满 WEBHOOK_TIMEOUT），慢且依赖宿主网络栈。

时区口径（#8）：cfg 夹具把 monitor.REPORT_TZ 钉成 UTC——默认
Asia/Shanghai 会让 `_day(0)` 的整点行跨两个当地日，本文件除
`test_trend_buckets_by_report_tz` 外全部按 UTC 日期叙事。
"""
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app import metrics, monitor
from app.config import METRICS_ENABLED
from app.models import AuditLog

DAY = "2024-03-05"


def _t(hour=10, minute=0, second=0, day=DAY):
    """构造某天某时刻的 UTC 时间（日报/时序边界用例用）。"""
    return datetime.strptime(day, "%Y-%m-%d") + timedelta(
        hours=hour, minutes=minute, seconds=second)


@pytest.fixture
def cfg(monkeypatch):
    """默认全部关干净，逐条按需打开（惰性读 app.config，见模块 docstring）。"""
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", False, raising=False)
    monkeypatch.setattr(metrics.config, "ALERT_BLOCK_RATE", 0.30, raising=False)
    monkeypatch.setattr(metrics.config, "ALERT_MIN_ACTIONS", 20, raising=False)
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL", "", raising=False)
    # monitor 是导入时拷值：分桶口径（parse_day/report_tz）必须 patch
    # app.monitor.REPORT_TZ，patch app.config.REPORT_TZ 无效。
    monkeypatch.setattr(monitor, "REPORT_TZ", "UTC", raising=False)
    return metrics.config


def _audit_rows(db, day, *, total, blocked, throttled=0, flagged=0):
    """在某一天铺 total 行审计，按给定数量分布到各决策桶。"""
    from app.models import new_id

    plan = (["deny"] * blocked + ["throttle"] * throttled + ["flag"] * flagged
            + ["allow"] * (total - blocked - throttled - flagged))
    for i, decision in enumerate(plan):
        db.add(AuditLog(id=new_id(), ts=_t(hour=i % 24, day=day),
                        action="chat", decision=decision, username="u"))
    db.flush()


def _day(n_days_ago):
    return (datetime.utcnow() - timedelta(days=n_days_ago)).strftime("%Y-%m-%d")


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


def _alert(date=DAY, block_rate=0.4, threshold=0.30, blocked=8, total=20):
    """构造一条**完整**的告警 dict —— send_alert 的 summary 会读全部五个键。"""
    return {"date": date, "block_rate": block_rate, "threshold": threshold,
            "blocked": blocked, "total": total}


# ------------------------------------------------------------------ trend 结构


def test_trend_default_is_14_days(cfg, db):
    t = metrics.trend(db)
    assert t["days"] == metrics.DEFAULT_TREND_DAYS == 14
    assert len(t["series"]) == 14


def test_trend_series_is_ascending_and_consecutive(cfg, db):
    series = metrics.trend(db)["series"]
    dates = [r["date"] for r in series]
    assert dates == sorted(dates)
    assert len(set(dates)) == len(dates)
    for a, b in zip(dates, dates[1:]):
        d1 = datetime.strptime(a, "%Y-%m-%d")
        d2 = datetime.strptime(b, "%Y-%m-%d")
        assert (d2 - d1) == timedelta(days=1)


def test_trend_series_ends_today(cfg, db):
    t = metrics.trend(db)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert t["series"][-1]["date"] == today
    assert t["range"]["end"] == today
    assert t["range"]["start"] == datetime.strptime(
        t["series"][0]["date"], "%Y-%m-%d").strftime("%Y-%m-%d")
    assert t["range"]["tz"] == "UTC"


def test_trend_buckets_by_report_tz(cfg, db, monkeypatch):
    """回归（#8）：series 标签与行分桶都必须按 REPORT_TZ 当地日。

    修复前标签写 UTC 日期、行按 UTC 日期分桶：Asia/Shanghai 下 UTC 日期
    等于"今天"的行（北京当天 08:00-24:00）落进不存在的桶被整段丢弃，
    趋势图最后一天恒为 0——"今天没数据"是最危险的误判形态。
    """
    from app.models import new_id

    monkeypatch.setattr(monitor, "REPORT_TZ", "Asia/Shanghai", raising=False)
    local_today = datetime.now(monitor.report_tz()).date()
    day = local_today.strftime("%Y-%m-%d")
    prev = (local_today - timedelta(days=1)).strftime("%Y-%m-%d")

    def utc_of(local_naive: datetime) -> datetime:
        """北京当地 naive → UTC naive（固定 +08:00，中国无夏令时）。"""
        return local_naive - timedelta(hours=8)

    midnight = datetime.combine(local_today, datetime.min.time())
    rows = [
        utc_of(midnight + timedelta(minutes=30)),            # 北京今天 00:30
        utc_of(midnight + timedelta(hours=23, minutes=30)),  # 北京今天 23:30
        utc_of(midnight + timedelta(hours=4)),               # 北京今天 04:00
        midnight + timedelta(hours=16, minutes=30),          # 北京明天 00:30 → 窗外
        utc_of(midnight - timedelta(hours=12)),              # 北京昨天 12:00
    ]
    for ts in rows:
        db.add(AuditLog(id=new_id(), ts=ts, action="chat",
                        decision="deny", username="u"))
    db.flush()

    t = metrics.trend(db, days=3)
    assert [r["date"] for r in t["series"]] == [
        (local_today - timedelta(days=2)).strftime("%Y-%m-%d"), prev, day]
    by_day = {r["date"]: r for r in t["series"]}
    assert by_day[day]["total"] == 3          # 今天三行（00:30 / 04:00 / 23:30）
    assert by_day[day]["blocked"] == 3
    assert by_day[prev]["total"] == 1         # 昨天中午那一行
    assert by_day[(local_today - timedelta(days=2)).strftime("%Y-%m-%d")]["total"] == 0
    assert t["range"]["end"] == day
    assert t["range"]["start"] == (local_today - timedelta(days=2)).strftime(
        "%Y-%m-%d")
    assert t["range"]["tz"] == "Asia/Shanghai"


@pytest.mark.parametrize(
    "days,expected",
    # 注意 days=0 走的是 `days or DEFAULT` 的 or 惯用法：0 视作"未传"→ 回落 14，
    # 而不是被 clamp 到 1。行为已钉住；若要 0 → 1 得改成显式 None 判断。
    [(1, 1), (0, 14), (-5, 1), (None, 14), (3, 3), (14, 14),
     (99999, metrics.MAX_TREND_DAYS), (365, 365), (367, metrics.MAX_TREND_DAYS)],
)
def test_trend_days_is_clamped(cfg, db, days, expected):
    """上限防止 ?days=100000 把整张审计表扫穿；下限防止除零与空区间。"""
    t = metrics.trend(db, days)
    assert t["days"] == expected
    assert len(t["series"]) == expected


# ------------------------------------------------------------------ 分桶与 block_rate


def test_trend_buckets_rows_into_days(cfg, db):
    _audit_rows(db, _day(0), total=10, blocked=4)
    _audit_rows(db, _day(1), total=8, blocked=1)
    series = {r["date"]: r for r in metrics.trend(db, days=3)["series"]}

    assert series[_day(0)]["total"] == 10
    assert series[_day(0)]["blocked"] == 4
    assert series[_day(1)]["total"] == 8
    assert series[_day(1)]["blocked"] == 1
    assert series[_day(2)]["total"] == 0


def test_trend_ignores_rows_outside_window(cfg, db):
    """窗口外的行不能漏进任何一天（否则历史攻击会把今天的率撑高）。"""
    _audit_rows(db, _day(30), total=50, blocked=50)
    series = {r["date"]: r for r in metrics.trend(db, days=7)["series"]}
    assert all(r["total"] == 0 for r in series.values())


def test_trend_block_rate_is_rounded_ratio(cfg, db):
    _audit_rows(db, _day(0), total=20, blocked=7)
    row = {r["date"]: r for r in metrics.trend(db, days=1)["series"]}[_day(0)]
    assert row["block_rate"] == round(7 / 20, 4) == 0.35


def test_trend_block_rate_zero_on_empty_day(cfg, db):
    """无动作记 0（不是 NaN、不是 1）——除零必须被挡在判定之前。"""
    row = {r["date"]: r for r in metrics.trend(db, days=1)["series"]}[_day(0)]
    assert row["total"] == 0
    assert row["block_rate"] == 0.0


def test_trend_decision_buckets_are_exclusive(cfg, db):
    """blocked / throttled / flagged 是 elif 互斥的：一行只能进一个桶。
    mask 既不是拦截也不是限流/标记，只进 total。"""
    _audit_rows(db, _day(0), total=10, blocked=3, throttled=2, flagged=1)
    row = {r["date"]: r for r in metrics.trend(db, days=1)["series"]}[_day(0)]
    assert row["blocked"] == 3
    assert row["throttled"] == 2
    assert row["flagged"] == 1
    assert 3 + 2 + 1 < row["total"] == 10     # 剩下 4 行是 allow/mask


def test_trend_mask_is_not_blocked(cfg, db):
    """mask（脱敏放行）不算拦截：否则正常脱敏链路会被算成安全事件。"""
    from app.models import new_id

    for i in range(20):
        db.add(AuditLog(id=new_id(), ts=_t(day=_day(0), hour=i % 24),
                        action="chat", decision="mask", username="u"))
    db.flush()
    row = {r["date"]: r for r in metrics.trend(db, days=1)["series"]}[_day(0)]
    assert row["total"] == 20
    assert row["blocked"] == 0
    assert row["block_rate"] == 0.0
    assert metrics.trend(db, days=1)["alerts"] == []


# ------------------------------------------------------------------ 告警判定


def test_alert_when_rate_exceeds_threshold_with_enough_samples(cfg, db):
    _audit_rows(db, _day(0), total=20, blocked=8)      # 0.40 > 0.30
    t = metrics.trend(db, days=1)

    assert len(t["alerts"]) == 1
    a = t["alerts"][0]
    assert a["date"] == _day(0)
    assert a["block_rate"] == 0.4
    assert a["threshold"] == 0.30
    assert a["blocked"] == 8
    assert a["total"] == 20


def test_no_alert_at_exact_threshold(cfg, db):
    """判定用严格大于：正好压在阈值上不算异常，否则阈值天天响。"""
    _audit_rows(db, _day(0), total=20, blocked=6)      # 0.30 == 阈值
    assert metrics.trend(db, days=1)["alerts"] == []


def test_no_alert_when_sample_too_small(cfg, db):
    """样本量不足不判定：某天只有 5 条且全被拦，拦截率 1.0 会误报。"""
    _audit_rows(db, _day(0), total=5, blocked=5)
    t = metrics.trend(db, days=1)
    assert t["series"][0]["block_rate"] == 1.0        # 率确实很高
    assert t["alerts"] == []                            # 但样本不够，不判定


def test_alert_when_sample_exactly_at_minimum(cfg, db):
    """>= ALERT_MIN_ACTIONS：正好踩线就参与判定。"""
    _audit_rows(db, _day(0), total=20, blocked=7)
    assert len(metrics.trend(db, days=1)["alerts"]) == 1


def test_no_alert_when_sample_one_below_minimum(cfg, db):
    _audit_rows(db, _day(0), total=19, blocked=19)
    assert metrics.trend(db, days=1)["alerts"] == []


def test_alert_reads_block_rate_lazily(cfg, db, monkeypatch):
    """证明 ALERT_BLOCK_RATE 是惰性读：改 config 立即改变判定结果。"""
    _audit_rows(db, _day(0), total=20, blocked=8)      # 0.40
    assert len(metrics.trend(db, days=1)["alerts"]) == 1

    monkeypatch.setattr(metrics.config, "ALERT_BLOCK_RATE", 0.50, raising=False)
    assert metrics.trend(db, days=1)["alerts"] == []


def test_alert_reads_min_actions_lazily(cfg, db, monkeypatch):
    """ALERT_MIN_ACTIONS 同样是惰性读。"""
    _audit_rows(db, _day(0), total=8, blocked=8)
    assert metrics.trend(db, days=1)["alerts"] == []      # 8 < 20

    monkeypatch.setattr(metrics.config, "ALERT_MIN_ACTIONS", 5, raising=False)
    assert len(metrics.trend(db, days=1)["alerts"]) == 1


def test_alerts_are_isolated_per_day(cfg, db):
    _audit_rows(db, _day(0), total=20, blocked=10)
    _audit_rows(db, _day(1), total=20, blocked=2)
    t = metrics.trend(db, days=2)
    assert [a["date"] for a in t["alerts"]] == [_day(0)]


# ------------------------------------------------------------------ render_markdown


def test_render_markdown_contains_structure(cfg):
    rep = {
        "date": DAY, "totals": {"actions": 12, "alerts": 3},
        "intercept": {"blocked": 2, "throttled": 1, "flagged": 0},
        "injection": {"hits": 4, "docs_flagged": 1, "chat_flags": 1},
        "pii": {"hits": 6, "docs_hit": 2},
        "approvals_pending": 1,
        "high_risk": {"threshold": 3, "count": 1,
                      "accounts": [{"username": "bad", "risk": 4}]},
        "inventory": {"docs_total": 9, "users_total": 7, "docs_new_today": 1},
        "top_users": [{"username": "u1", "alerts": 2, "actions": 5}],
        "top_docs": [{"doc_id": "d", "title": "文档甲", "hits": 3, "alerts": 1}],
        "generated_at": "2024-03-05 10:00:00",
    }
    md = metrics.render_markdown(rep)
    assert md.startswith(f"# fin-rag 运维日报 {DAY}")
    assert "| u1 | 2 | 5 |" in md
    assert "| 《文档甲》 | 3 | 1 |" in md
    assert "bad（有效风险分 4）" in md
    assert "只读聚合" in md
    assert "2024-03-05 10:00:00" in md


def test_render_markdown_empty_does_not_raise(cfg):
    """空 dict 不能 KeyError：接口不能因为"今天什么都没发生"而 500。"""
    md = metrics.render_markdown({})
    assert "# fin-rag 运维日报" in md
    assert "| （无） | 0 | 0 |" in md


def test_render_markdown_none_does_not_raise(cfg):
    assert "fin-rag" in metrics.render_markdown(None)


# ------------------------------------------------------------------ 落盘开关


def test_write_markdown_disabled_returns_none_and_creates_nothing(cfg, db, tmp_path):
    """默认关：一个字节都不写，连 reports/ 目录都不该凭空出现。"""
    target = tmp_path / "reports"
    assert metrics.write_markdown({"date": DAY}, base_dir=target) is None
    assert not target.exists()
    assert not any(tmp_path.iterdir())


def test_write_markdown_enabled_writes_file(cfg, db, tmp_path, monkeypatch):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    target = tmp_path / "reports"
    path = metrics.write_markdown(
        {"date": DAY, "totals": {"actions": 1, "alerts": 0}}, base_dir=target)

    assert path is not None
    assert path == str(target / f"{DAY}.md")
    assert target.is_dir()
    assert DAY in open(path, encoding="utf-8").read()


def test_write_markdown_uses_date_from_report(cfg, db, tmp_path, monkeypatch):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    metrics.write_markdown({"date": "2020-01-02"}, base_dir=tmp_path)
    assert (tmp_path / "2020-01-02.md").is_file()


def test_write_markdown_defaults_to_today_when_no_date(cfg, db, tmp_path,
                                                       monkeypatch):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    metrics.write_markdown({}, base_dir=tmp_path)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    assert (tmp_path / f"{today}.md").is_file()


def test_write_markdown_is_idempotent(cfg, db, tmp_path, monkeypatch):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    p1 = metrics.write_markdown({"date": DAY}, base_dir=tmp_path)
    p2 = metrics.write_markdown({"date": DAY}, base_dir=tmp_path)
    assert p1 == p2
    assert len(list(tmp_path.iterdir())) == 1


# ------------------------------------------------------------------ webhook


def test_send_alert_skips_when_url_unset(cfg):
    out = metrics.send_alert([_alert()])
    assert out == {"sent": False, "reason": "未配置 ALERT_WEBHOOK_URL，跳过告警推送"}


def test_send_alert_skips_when_no_alerts(cfg, monkeypatch):
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://127.0.0.1:9/hook", raising=False)
    assert metrics.send_alert([])["sent"] is False
    assert "无异常日" in metrics.send_alert([])["reason"]


def test_send_alert_success(cfg, monkeypatch):
    seen = {}

    def fake_post(url, json=None, timeout=None):
        seen["url"] = url
        seen["json"] = json
        return _Resp(200)

    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://hook.local/x", raising=False)
    monkeypatch.setattr(httpx, "post", fake_post)

    out = metrics.send_alert([_alert(date=DAY, block_rate=0.4, blocked=8, total=20)])
    assert out == {"sent": True, "status": 200}
    assert seen["url"] == "http://hook.local/x"
    assert seen["json"]["source"] == "fin-rag-metrics"
    assert seen["json"]["alert_count"] == 1
    assert "拦截率" in seen["json"]["summary"]
    assert seen["json"]["date"] == DAY          # 未显式传 date 时取首条告警


@pytest.mark.parametrize("code", [400, 401, 429, 500, 503])
def test_send_alert_non_2xx_is_failure(cfg, monkeypatch, code):
    """非 2xx 同样按失败处理——回 4xx/5xx 说明告警没能送达。"""
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://hook.local/x", raising=False)
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(code))

    out = metrics.send_alert([_alert()])
    assert out["sent"] is False
    assert f"HTTP {code}" in out["reason"]


def test_send_alert_connection_error_does_not_raise(cfg, monkeypatch):
    """连不上：只 warn，绝不向上抛——看板不能因为告警通道挂了而打不开。"""
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://127.0.0.1:9/hook", raising=False)

    def boom(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", boom)

    with pytest.warns(UserWarning, match="告警推送失败"):
        out = metrics.send_alert([_alert()])
    assert out["sent"] is False
    assert "推送失败" in out["reason"]


def test_send_alert_timeout_does_not_raise(cfg, monkeypatch):
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://hook.local/x", raising=False)

    def boom(*a, **k):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx, "post", boom)

    with pytest.warns(UserWarning):
        assert metrics.send_alert([_alert()])["sent"] is False


def test_send_alert_unreachable_url_is_caught(cfg, monkeypatch):
    """畸形/不支持的协议也在 HTTPError 家族内，同样不能漏出去。"""
    for url in ("not-a-url", "ftp://x/y"):
        monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL", url, raising=False)
        with pytest.warns(UserWarning):
            assert metrics.send_alert([_alert()])["sent"] is False


# ------------------------------------------------------------------ build_metrics


def test_build_metrics_disabled_short_circuits(cfg, db, tmp_path, monkeypatch):
    """未启用：不落盘、不推送，也不返回 webhook 键（避免前端误以为推送过）。"""
    monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
    out = metrics.build_metrics(db)

    assert out["enabled"] is False
    assert out["markdown_path"] == ""
    assert "webhook" not in out
    assert not any(tmp_path.iterdir())


def test_build_metrics_enabled_writes_and_pushes(cfg, db, tmp_path, monkeypatch):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://hook.local/x", raising=False)
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(200))

    _audit_rows(db, _day(0), total=20, blocked=10)
    out = metrics.build_metrics(db, days=3)

    assert out["enabled"] is True
    assert out["markdown_path"]
    assert out["markdown_path"].endswith(f"{_day(0)}.md")
    assert out["webhook"] == {"sent": True, "status": 200}
    assert any(tmp_path.iterdir())


def test_build_metrics_enabled_but_no_alerts(cfg, db, tmp_path, monkeypatch):
    """启用了但没有异常日：照样落盘，推送只回报"无需推送"。"""
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
    monkeypatch.setattr(metrics.config, "ALERT_WEBHOOK_URL",
                        "http://hook.local/x", raising=False)
    _audit_rows(db, _day(0), total=20, blocked=1)

    out = metrics.build_metrics(db)
    assert out["alerts"] == []
    assert out["markdown_path"]
    assert out["webhook"]["sent"] is False
    assert "无异常日" in out["webhook"]["reason"]


def test_build_metrics_default_enabled_is_false(cfg, db, tmp_path, monkeypatch):
    """默认口径必须是关着的（没动过配置时）。"""
    monkeypatch.undo()
    monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
    out = metrics.build_metrics(db)
    assert out["enabled"] is METRICS_ENABLED
    assert not any(tmp_path.iterdir())


# ------------------------------------------------------------------ 只读性


def test_trend_is_read_only(cfg, db):
    _audit_rows(db, _day(0), total=20, blocked=10)
    db.commit()
    before = db.execute(select(func.count()).select_from(AuditLog)).scalar()
    sig = {tuple(r) for r in db.execute(
        select(AuditLog.id, AuditLog.ts, AuditLog.decision)).all()}

    metrics.trend(db, days=3)
    metrics.build_metrics(db, days=3)

    db.rollback()
    assert db.execute(select(func.count()).select_from(AuditLog)).scalar() == before
    assert {tuple(r) for r in db.execute(
        select(AuditLog.id, AuditLog.ts, AuditLog.decision)).all()} == sig


# ------------------------------------------------------------------ 清理过期日报（#6 保留矩阵）


def _touch(directory: Path, name: str) -> Path:
    p = directory / name
    p.write_text("x", encoding="utf-8")
    return p


def test_cleanup_deletes_only_expired(cfg, tmp_path):
    """按文件名日期判定：过期的删、窗口内的留、名字解析不了的一律不动。"""
    today = datetime.utcnow().date()
    _touch(tmp_path, f"{today - timedelta(days=100)}.md")   # 过期
    _touch(tmp_path, f"{today - timedelta(days=29)}.md")    # 窗口内
    _touch(tmp_path, f"{today}.md")                          # 当天
    _touch(tmp_path, "README.md")                            # 解析不了 → 不动

    out = metrics.cleanup_old_reports(days=30, reports_dir=tmp_path)
    assert out["deleted"] == [f"{today - timedelta(days=100)}.md"]
    assert out["kept"] == 2
    assert out["unparsable"] == 1
    assert not (tmp_path / f"{today - timedelta(days=100)}.md").exists()
    assert (tmp_path / "README.md").is_file()


def test_cleanup_missing_dir_returns_empty_without_creating(cfg, tmp_path):
    """目录不存在：返回空结果且**不创建目录**——清理不该为清理而造目录
    （与 write_markdown"关着时连 reports/ 都不该出现"的同一条哲学）。"""
    target = tmp_path / "reports"
    out = metrics.cleanup_old_reports(days=30, reports_dir=target)
    assert out == {"days": 30, "deleted": [], "kept": 0, "unparsable": 0}
    assert not target.exists()
    assert not any(tmp_path.iterdir())


def test_cleanup_days_is_clamped(cfg, tmp_path):
    """days 夹到 [1, 3650]：负数 → 1，超大 → 3650（防呆参数直接穿透到底层）。"""
    lo = metrics.cleanup_old_reports(days=-5, reports_dir=tmp_path / "nope")
    hi = metrics.cleanup_old_reports(days=10 ** 9, reports_dir=tmp_path / "nope")
    assert lo["days"] == 1
    assert hi["days"] == 3650


def test_cleanup_default_days_from_config(cfg, tmp_path, monkeypatch):
    """days 缺省取 METRICS_RETENTION_DAYS（惰性读 config）。"""
    monkeypatch.setattr(metrics.config, "METRICS_RETENTION_DAYS", 7, raising=False)
    out = metrics.cleanup_old_reports(reports_dir=tmp_path / "nope")
    assert out["days"] == 7


# ------------------------------------------------------------------ 路由层


def test_metrics_api_returns_503_when_disabled(cfg, db, user_factory, monkeypatch):
    """"没开监控"和"开了但今天没异常"必须能一眼区分，否则空列表会被当成平安无事。"""
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", False, raising=False)
    admin = user_factory("boss", clearance=3, roles=["admin"])

    with pytest.raises(HTTPException) as exc:
        admin_router_metrics()(days=14, _=admin, db=db)
    assert exc.value.status_code == 503
    assert "METRICS_ENABLED" in exc.value.detail


def test_metrics_api_returns_payload_when_enabled(cfg, db, user_factory,
                                                  monkeypatch, tmp_path):
    monkeypatch.setattr(metrics.config, "METRICS_ENABLED", True, raising=False)
    monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
    admin = user_factory("boss", clearance=3, roles=["admin"])

    out = admin_router_metrics()(days=3, _=admin, db=db)
    assert out["enabled"] is True
    assert len(out["series"]) == 3


def test_daily_report_api_rejects_bad_date(cfg, db, user_factory):
    admin = user_factory("boss", clearance=3, roles=["admin"])
    with pytest.raises(HTTPException) as exc:
        admin_router_report()(date="2024/03/05", _=admin, db=db)
    assert exc.value.status_code == 400


def test_daily_report_api_returns_text_by_default(cfg, db, user_factory):
    from app.models import new_id

    admin = user_factory("boss", clearance=3, roles=["admin"])
    db.add(AuditLog(id=new_id(), ts=_t(day=_day(0)), action="chat",
                    decision="deny", username="u"))
    db.flush()

    out = admin_router_report()(date=_day(0), _=admin, db=db)
    assert out["date"] == _day(0)
    assert "text" in out and "请求量" in out["text"]


def test_daily_report_api_omits_text_when_configured(cfg, db, user_factory,
                                                    monkeypatch):
    """REPORT_INCLUDE_TEXT=false 时大库下省带宽（monitor 侧按值读入）。"""
    from app import monitor

    monkeypatch.setattr(monitor, "REPORT_INCLUDE_TEXT", False, raising=False)
    admin = user_factory("boss", clearance=3, roles=["admin"])
    out = admin_router_report()(date=_day(0), _=admin, db=db)
    assert "text" not in out


def admin_router_metrics():
    """延迟取路由函数：避免模块级 import 把整个 app 拉起来。"""
    from app.routers.admin import metrics_api

    return metrics_api


def admin_router_report():
    from app.routers.admin import daily_report_api

    return daily_report_api
