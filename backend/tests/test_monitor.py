# SPDX-License-Identifier: AGPL-3.0-only
"""monitor.py —— 运维监控日报单元测试（P2-12）。

日报的核心契约是**只读**：它自己也写一行审计的话，明天的"拦截数"里就多一条
噪音，还会让"审计链被改过"和"有人刷了看板"混成同一件事。所以这里除了各类
计数口径，专门有一条只读性用例（调用前后审计行数、内容都不能变）。

注意：monitor.py 是用 `from .config import REPORT_TOP_N` 在**导入时**拷值的，
NOT 惰性读。要改口径必须 patch `app.monitor.X`，patch `app.config.X` 无效
（metrics.py 才是惰性读，两个模块别用同一套打法）。

时区口径（#8）：REPORT_TZ 默认 Asia/Shanghai，本文件除"时区口径"小节外
全部经 `_pin_utc`  autouse 夹具钉死 UTC——自然日边界用例若不钉时区，
会随跑测试的当地时间漂移（北京时间 0-8 点跑，"今天"的 UTC 区间起始于昨天
16:00）。时区小节内的用例在函数体内自行 patch，优先级高于 autouse 夹具。
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app import monitor
from app.config import REPORT_TZ as CONFIG_REPORT_TZ
from app.models import ApprovalRequest, AuditLog, Document, User

DAY = "2024-03-05"


def _t(hour=10, minute=0, second=0, day=DAY):
    return datetime.strptime(day, "%Y-%m-%d") + timedelta(
        hours=hour, minutes=minute, seconds=second)


@pytest.fixture(autouse=True)
def _pin_utc(monkeypatch):
    """除时区专测外，本文件全部按 UTC 口径钉死（见模块 docstring）。"""
    monkeypatch.setattr(monitor, "REPORT_TZ", "UTC", raising=False)


def _doc(db, title, created_at, *, inject_risk=0, pii_hits=0):
    from app.models import new_id

    d = Document(id=new_id(), title=title, created_at=created_at,
                 inject_risk=inject_risk, pii_hits=pii_hits)
    db.add(d)
    db.flush()
    return d


# ------------------------------------------------------------------ parse_day


def test_parse_day_explicit_date_boundaries():
    start, end = monitor.parse_day(DAY)
    assert start == datetime(2024, 3, 5, 0, 0, 0)
    assert end == datetime(2024, 3, 6, 0, 0, 0)


def test_parse_day_defaults_to_today_utc():
    start, end = monitor.parse_day()
    now = datetime.utcnow()
    assert start <= now < end
    assert (end - start) == timedelta(days=1)
    assert (start.hour, start.minute, start.second, start.microsecond) == (0, 0, 0, 0)


def test_parse_day_rejects_bad_format():
    """格式错误必须抛 ValueError 由路由转 400 —— 静默吞掉会算出一张空表，
    运营会误判成"今天没有风险事件"。"""
    for bad in ("2024/03/05", "yesterday", "2024-13-01", "2024-03-32", "20240305"):
        with pytest.raises(ValueError, match="日期格式应为"):
            monitor.parse_day(bad)


def test_parse_day_rejects_non_zero_padded():
    """非补零写法必须拒绝（monitor.py:45 的 _DAY_RE）。

    strptime 本身会放行 '2024-3-5'，但放行会让"同一天"出现两种 key
    （2024-03-05 与 2024-3-5），趋势图上就是两条线。这条用例就是钉那个修复。
    """
    for bad in ("2024-3-5", "2024-03-5", "24-03-05", "2024-3-05"):
        with pytest.raises(ValueError, match="日期格式应为"):
            monitor.parse_day(bad)


def test_parse_day_accepts_only_zero_padded_full_date():
    """补零的完整日期（含被前后空白包裹）应正常通过。"""
    assert monitor.parse_day("2024-03-05")[0] == datetime(2024, 3, 5)
    assert monitor.parse_day(" 2024-03-05 ")[0] == datetime(2024, 3, 5)


def test_parse_day_truncates_time_part():
    """带时间的入参取前 10 位，幂等处理，避免路由层多传一串就 500。"""
    start, end = monitor.parse_day("2024-03-05 13:45:00")
    assert start == datetime(2024, 3, 5)
    assert end == datetime(2024, 3, 6)


def test_parse_day_strips_whitespace():
    assert monitor.parse_day("  2024-03-05  ")[0] == datetime(2024, 3, 5)


# ------------------------------------------------------------------ 时间窗边界


def test_report_uses_left_closed_right_open_window(db, audit_factory):
    """>= start 且 < end：整点边界必须落在正确的一天，不能跨日重复计数。"""
    start, end = monitor.parse_day(DAY)
    audit_factory(ts=start, decision="deny")                 # 含起点
    audit_factory(ts=end - timedelta(seconds=1), decision="deny")   # 含终点前一秒
    audit_factory(ts=start - timedelta(seconds=1), decision="deny")  # 前一天
    audit_factory(ts=end, decision="deny")                   # 后一天

    rep = monitor.daily_report(db, date=DAY)
    assert rep["totals"]["actions"] == 2
    assert rep["decisions"]["deny"] == 2


def test_report_empty_day_is_all_zero(db):
    rep = monitor.daily_report(db, date=DAY)
    assert rep["totals"] == {"actions": 0, "alerts": 0}
    assert rep["intercept"] == {"blocked": 0, "throttled": 0, "flagged": 0}
    assert rep["top_users"] == []
    assert rep["top_docs"] == []
    assert rep["injection"] == {"docs_flagged": 0, "hits": 0, "chat_flags": 0}
    assert rep["pii"] == {"docs_hit": 0, "hits": 0}
    assert rep["approvals_pending"] == 0
    assert rep["high_risk"] == {"threshold": monitor.JIGSAW_RISK_READONLY,
                                "count": 0, "accounts": []}
    assert rep["inventory"] == {"docs_total": 0, "users_total": 0, "docs_new_today": 0}
    assert rep["date"] == DAY
    assert rep["range"]["tz"] == "UTC"


# ------------------------------------------------------------------ 决策口径


def test_decision_buckets(db, audit_factory):
    """把每个 decision 落进哪个桶钉死。

    注意这里有一处**口径不对称**（已入报告观察项）：abstain 计入
    intercept.blocked，却不计入 totals.alerts。疑似疏漏，但也可能是有意为之；
    本用例只钉住现状，改口径前请先看报告里的说明。
    """
    kinds = ["allow", "deny", "throttle", "flag", "block", "degrade", "mask", "abstain"]
    for i, d in enumerate(kinds):
        audit_factory(ts=_t(hour=i), decision=d)

    rep = monitor.daily_report(db, date=DAY)
    assert rep["totals"]["actions"] == 8
    # ALERT_DECISIONS 六类：deny/throttle/flag/block/degrade/mask（不含 allow、abstain）
    assert rep["totals"]["alerts"] == 6
    # BLOCK_DECISIONS 四类：deny/abstain/block/degrade（不含 throttle/flag/mask）
    assert rep["intercept"]["blocked"] == 4
    assert rep["intercept"]["throttled"] == 1
    assert rep["intercept"]["flagged"] == 1
    assert rep["decisions"]["allow"] == 1
    assert rep["decisions"]["mask"] == 1


def test_actions_top_counts_by_action(db, audit_factory):
    for _ in range(3):
        audit_factory(ts=_t(hour=1), action="chat")
    for _ in range(2):
        audit_factory(ts=_t(hour=2), action="view")
    audit_factory(ts=_t(hour=3), action="upload")

    rep = monitor.daily_report(db, date=DAY, top_n=5)
    top = {row["action"]: row["count"] for row in rep["actions_top"]}
    assert top == {"chat": 3, "view": 2, "upload": 1}
    assert [row["count"] for row in rep["actions_top"]] == sorted(
        [r["count"] for r in rep["actions_top"]], reverse=True)


# ------------------------------------------------------------------ Top 用户榜


def test_top_users_sorted_by_alert_count(db, audit_factory):
    """运营看的是"被处置次数"，放行再多也不该上榜。"""
    for i in range(4):
        audit_factory(ts=_t(hour=i), username="bad_guy", decision="deny")
    for i in range(2):
        audit_factory(ts=_t(hour=i), username="mid_guy", decision="throttle")
    for i in range(20):
        audit_factory(ts=_t(hour=0, minute=i), username="busy_guy", decision="allow")

    rep = monitor.daily_report(db, date=DAY, top_n=5)
    names = [u["username"] for u in rep["top_users"]]

    assert names[0] == "bad_guy"
    assert names[1] == "mid_guy"
    assert "busy_guy" not in names          # 20 次放行，0 次处置 → 不上榜
    first = rep["top_users"][0]
    assert first == {"username": "bad_guy", "alerts": 4, "actions": 4}


def test_top_users_respects_top_n(db, audit_factory, monkeypatch):
    monkeypatch.setattr(monitor, "REPORT_TOP_N", 1, raising=False)
    for i in range(3):
        audit_factory(ts=_t(hour=i), username="a", decision="deny")
    for i in range(2):
        audit_factory(ts=_t(hour=i), username="b", decision="deny")
    assert len(monitor.daily_report(db, date=DAY)["top_users"]) == 1


def test_top_users_explicit_top_n_overrides_config(db, audit_factory, monkeypatch):
    monkeypatch.setattr(monitor, "REPORT_TOP_N", 1, raising=False)
    audit_factory(ts=_t(hour=1), username="a", decision="deny")
    audit_factory(ts=_t(hour=2), username="b", decision="deny")
    assert len(monitor.daily_report(db, date=DAY, top_n=2)["top_users"]) == 2


def test_rows_without_username_are_skipped(db, audit_factory):
    """空 username 的行必须跳过：否则「anonymous/空串」会凭空登顶。"""
    audit_factory(ts=_t(hour=1), username="real_user", decision="deny")
    audit_factory(ts=_t(hour=2), username="", decision="deny")
    audit_factory(ts=_t(hour=3), username="", decision="deny")

    rep = monitor.daily_report(db, date=DAY)
    assert [u["username"] for u in rep["top_users"]] == ["real_user"]
    assert rep["totals"]["actions"] == 3      # 仍然计入总动作数


# ------------------------------------------------------------------ Top 文档榜


def test_top_docs_only_counts_document_actions(db, audit_factory, doc_factory):
    """只有 chat/view/search/upload/... 算「文档被访问」。

    刻意排除 login/create_user 等：它们也带 target_id（那是用户 id），
    混进来会让「热门文档」榜首变成一个用户名。
    """
    doc = doc_factory("真文档")
    other = doc_factory("被撞名的东西")
    for i in range(3):
        audit_factory(ts=_t(hour=i), action="chat", target_id=doc.id, decision="allow")
    for i in range(5):
        audit_factory(ts=_t(hour=i), action="login", target_id=other.id,
                      decision="allow")

    rep = monitor.daily_report(db, date=DAY, top_n=5)
    ids = [d["doc_id"] for d in rep["top_docs"]]

    assert ids == [doc.id]
    assert other.id not in ids


def test_top_docs_counts_alerts_separately(db, audit_factory, doc_factory):
    doc = doc_factory("涉密文档")
    for i in range(4):
        audit_factory(ts=_t(hour=i), action="view", target_id=doc.id, decision="allow")
    for i in range(2):
        audit_factory(ts=_t(hour=i), action="chat", target_id=doc.id, decision="deny")

    entry = monitor.daily_report(db, date=DAY)["top_docs"][0]
    assert entry["hits"] == 6
    assert entry["alerts"] == 2
    assert entry["title"] == "涉密文档"


def test_top_docs_deleted_document_falls_back_to_label(db, audit_factory):
    """文档被删后仍要显示当天的访问热度，标题退回标签，不能整条消失。"""
    audit_factory(ts=_t(hour=1), action="view", target_id="gone-doc",
                  target_label="旧标题备份", decision="allow")
    entry = monitor.daily_report(db, date=DAY)["top_docs"][0]
    assert entry["title"] == "旧标题备份"


def test_top_docs_deleted_document_without_label(db, audit_factory):
    audit_factory(ts=_t(hour=1), action="view", target_id="gone-doc",
                  target_label="", decision="allow")
    assert monitor.daily_report(db, date=DAY)["top_docs"][0]["title"] == "(已删除)"


def test_rows_without_target_id_are_skipped(db, audit_factory, doc_factory):
    doc = doc_factory("真文档")
    audit_factory(ts=_t(hour=1), action="chat", target_id=doc.id)
    audit_factory(ts=_t(hour=2), action="search", target_id="")
    assert len(monitor.daily_report(db, date=DAY)["top_docs"]) == 1


# ------------------------------------------------------------------ 注入 / PII


def test_injection_counts_docs_created_that_day(db, doc_factory):
    start, end = monitor.parse_day(DAY)
    _doc(db, "含注入样本", start + timedelta(hours=1), inject_risk=3)
    _doc(db, "干净文档", start + timedelta(hours=2), inject_risk=0)
    _doc(db, "隔天的注入文档", end + timedelta(hours=1), inject_risk=9)

    rep = monitor.daily_report(db, date=DAY)
    assert rep["injection"]["docs_flagged"] == 1
    assert rep["injection"]["hits"] == 3
    assert rep["inventory"]["docs_new_today"] == 2


def test_pii_counts_docs_created_that_day(db, doc_factory):
    start, _ = monitor.parse_day(DAY)
    _doc(db, "含身份证", start + timedelta(hours=1), pii_hits=5)
    _doc(db, "含手机号", start + timedelta(hours=2), pii_hits=2)
    _doc(db, "干净", start + timedelta(hours=3), pii_hits=0)

    rep = monitor.daily_report(db, date=DAY)
    assert rep["pii"]["docs_hit"] == 2
    assert rep["pii"]["hits"] == 7


def test_chat_injection_flags_need_flag_decision_and_keyword(db, audit_factory):
    """chat_flags 只统计 decision=flag 且 reason 含「注入」的行。"""
    audit_factory(ts=_t(hour=1), decision="flag", reason="检出疑似提示注入")
    audit_factory(ts=_t(hour=2), decision="flag", reason="检出敏感信息")   # 关键词不符
    audit_factory(ts=_t(hour=3), decision="deny", reason="检出疑似提示注入")  # 决策不符

    assert monitor.daily_report(db, date=DAY)["injection"]["chat_flags"] == 1


# ------------------------------------------------------------------ 待审批 / 风险账号


def test_pending_approvals_counted(db, user_factory, doc_factory):
    from app import approval

    user = user_factory("u", clearance=3)
    d1 = doc_factory("1", clearance=3)
    d2 = doc_factory("2", clearance=3)
    approval.request_clearance_change(db, user, d1, 1)
    approval.request_clearance_change(db, user, d2, 1)
    db.flush()

    assert monitor.daily_report(db, date=DAY)["approvals_pending"] == 2


def test_pending_approvals_ignores_decided(db, user_factory, doc_factory):
    from app import approval

    user = user_factory("u", clearance=3)
    boss = user_factory("boss", clearance=3)
    d = doc_factory("d", clearance=3)
    req, _ = approval.request_clearance_change(db, user, d, 1)
    db.flush()
    approval.decide(db, boss, req.id, approve=True)
    db.flush()

    assert monitor.daily_report(db, date=DAY)["approvals_pending"] == 0


def test_high_risk_accounts_use_decayed_score(db, user_factory, monkeypatch):
    """日报必须走惰性衰减后的有效风险分：三个月前撞过三次的分析师，
    今天不该还挂在「待人工审核」名单里。"""
    monkeypatch.setattr(monitor, "JIGSAW_RISK_READONLY", 3, raising=False)
    stale = user_factory("stale", clearance=1)
    stale.risk_score = 3
    stale.last_risk_ts = datetime.utcnow() - timedelta(days=90)
    fresh = user_factory("fresh", clearance=1)
    fresh.risk_score = 3
    fresh.last_risk_ts = datetime.utcnow()
    db.flush()

    high = monitor.daily_report(db, date=DAY)["high_risk"]
    assert high["threshold"] == 3
    assert high["count"] == 1
    assert [a["username"] for a in high["accounts"]] == ["fresh"]


def test_high_risk_accounts_below_threshold_not_listed(db, user_factory, monkeypatch):
    monkeypatch.setattr(monitor, "JIGSAW_RISK_READONLY", 5, raising=False)
    u = user_factory("u", clearance=1)
    u.risk_score = 4
    u.last_risk_ts = datetime.utcnow()
    db.flush()
    assert monitor.daily_report(db, date=DAY)["high_risk"]["count"] == 0


# ------------------------------------------------------------------ 库存 / 渲染


def test_inventory_counts_whole_library(db, user_factory, doc_factory):
    for i in range(3):
        doc_factory(f"doc{i}", created_at=_t(hour=i))
    user_factory("u1")
    user_factory("u2")

    rep = monitor.daily_report(db, date=DAY)
    assert rep["inventory"]["docs_total"] == 3
    assert rep["inventory"]["users_total"] == 2
    assert rep["inventory"]["docs_new_today"] == 3


def test_render_report_contains_key_numbers(db, audit_factory, doc_factory):
    audit_factory(ts=_t(hour=1), username="bad", decision="deny")
    text = monitor.daily_report_text(db, date=DAY)

    assert isinstance(text, str)
    assert DAY in text
    assert "请求量 1 条" in text
    assert "拦截 1 " in text
    assert "bad（1 次）" in text
    assert "UTC" in text


def test_render_report_handles_empty_lists():
    """空榜不能 KeyError，也不能渲染成一片空白让运营以为日报坏了。"""
    empty = {
        "date": DAY, "range": {"tz": "UTC"},
        "totals": {"actions": 0, "alerts": 0},
        "intercept": {"blocked": 0, "throttled": 0, "flagged": 0},
        "injection": {"hits": 0, "docs_flagged": 0, "chat_flags": 0},
        "pii": {"hits": 0, "docs_hit": 0},
        "approvals_pending": 0,
        "high_risk": {"threshold": 3, "count": 0, "accounts": []},
        "inventory": {"docs_total": 0, "users_total": 0, "docs_new_today": 0},
        "top_users": [], "top_docs": [],
    }
    text = monitor.render_report(empty)
    assert "触发最多的账号：无" in text
    assert "被访问最多的文档：无" in text


def test_daily_report_text_equals_render_of_dict(db, audit_factory):
    audit_factory(ts=_t(hour=1), decision="deny")
    rep = monitor.daily_report(db, date=DAY)
    assert monitor.daily_report_text(db, date=DAY) == monitor.render_report(rep)


def test_include_text_switch(monkeypatch):
    """REPORT_INCLUDE_TEXT 用于大库关掉文本省带宽（monitor 侧按值读入）。"""
    monkeypatch.setattr(monitor, "REPORT_INCLUDE_TEXT", False, raising=False)
    assert monitor.include_text() is False
    monkeypatch.setattr(monitor, "REPORT_INCLUDE_TEXT", True, raising=False)
    assert monitor.include_text() is True


# ------------------------------------------------------------------ 只读性（核心契约）


def test_daily_report_is_read_only(db, audit_factory, doc_factory, user_factory):
    """日报绝不能往审计链里写东西，否则明天的数据里就混进了今天刷看板的噪音。"""
    doc = doc_factory("文档")
    user_factory("u1")
    for i in range(5):
        audit_factory(ts=_t(hour=i), username="u1", target_id=doc.id,
                      action="chat", decision="deny")
    db.commit()

    before = db.execute(select(func.count()).select_from(AuditLog)).scalar()
    signatures = {
        tuple(r) for r in
        db.execute(select(AuditLog.id, AuditLog.ts, AuditLog.row_hash)).all()
    }
    docs_before = db.execute(select(func.count()).select_from(Document)).scalar()
    users_before = db.execute(select(func.count()).select_from(User)).scalar()
    approvals_before = db.execute(
        select(func.count()).select_from(ApprovalRequest)).scalar()

    monitor.daily_report(db, date=DAY)
    monitor.daily_report_text(db, date=DAY)

    db.rollback()
    assert db.execute(select(func.count()).select_from(AuditLog)).scalar() == before
    assert {
        tuple(r) for r in
        db.execute(select(AuditLog.id, AuditLog.ts, AuditLog.row_hash)).all()
    } == signatures
    assert db.execute(select(func.count()).select_from(Document)).scalar() == docs_before
    assert db.execute(select(func.count()).select_from(User)).scalar() == users_before
    assert db.execute(
        select(func.count()).select_from(ApprovalRequest)).scalar() == approvals_before


# ------------------------------------------------------------------ 时区口径（#8 REPORT_TZ）


def test_default_report_tz_is_shanghai():
    """默认 REPORT_TZ=Asia/Shanghai：中国运营看"今天"不能错位成昨天。

    模块级 import 在收集期完成绑定，不受 _pin_utc autouse 夹具影响。
    """
    assert CONFIG_REPORT_TZ == "Asia/Shanghai"


def test_parse_day_shanghai_midnight_is_previous_day_16utc(monkeypatch):
    """Asia/Shanghai 当地 0 点 = UTC 前一天 16:00（+08:00 边界平移）。"""
    monkeypatch.setattr(monitor, "REPORT_TZ", "Asia/Shanghai", raising=False)
    start, end = monitor.parse_day(DAY)
    assert start == datetime(2024, 3, 4, 16, 0, 0)
    assert end == datetime(2024, 3, 5, 16, 0, 0)


def test_parse_day_shanghai_defaults_to_local_today(monkeypatch):
    """date 留空 = REPORT_TZ 的"今天"：当地时间当日 0 点起，必然包住当前瞬间。"""
    monkeypatch.setattr(monitor, "REPORT_TZ", "Asia/Shanghai", raising=False)
    start, end = monitor.parse_day()
    now = datetime.utcnow()
    assert start <= now < end
    assert (end - start) == timedelta(days=1)
    assert (start.hour, start.minute, start.second) == (16, 0, 0)


def test_report_tz_invalid_falls_back_to_utc(monkeypatch):
    """配错时区字符串：告警 + 回落 UTC（口径回到旧行为），但不静默。"""
    monkeypatch.setattr(monitor, "REPORT_TZ", "Mars/Olympus", raising=False)
    with pytest.warns(RuntimeWarning, match="无法识别"):
        assert monitor.report_tz() == timezone.utc
    # 兜底后 parse_day 照常工作（UTC 恒等变换），日报链路不炸
    assert monitor.parse_day(DAY)[0] == datetime(2024, 3, 5)


def test_daily_report_buckets_by_local_day(db, audit_factory, monkeypatch):
    """同一 UTC 时刻属于哪个"当地日"由 REPORT_TZ 决定，与存储的 naive UTC 无关。"""
    monkeypatch.setattr(monitor, "REPORT_TZ", "Asia/Shanghai", raising=False)
    audit_factory(ts=datetime(2024, 3, 4, 16, 30), decision="deny")   # 北京 3/5 00:30
    audit_factory(ts=datetime(2024, 3, 5, 15, 30), decision="deny")   # 北京 3/5 23:30
    audit_factory(ts=datetime(2024, 3, 5, 16, 30), decision="deny")   # 北京 3/6 00:30 → 排除
    audit_factory(ts=datetime(2024, 3, 4, 15, 30), decision="deny")   # 北京 3/4 23:30 → 排除

    rep = monitor.daily_report(db, date=DAY)
    assert rep["totals"]["actions"] == 2
    # 标题必须是当地日：start 是 UTC 瞬时（3/4 16:00），直接 strftime 会标成 3/4
    assert rep["date"] == DAY
    assert rep["range"] == {
        "start": "2024-03-04 16:00:00", "end": "2024-03-05 16:00:00",
        "tz": "Asia/Shanghai",
    }
