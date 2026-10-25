# SPDX-License-Identifier: AGPL-3.0-only
"""jigsaw.py —— 防拼图（Jigsaw / Salami Slicing）引擎单元测试。

威胁模型决定了测试重点：攻击者每**一次**提问都合法，单次策略判定必然放行。
所以这里不验证"单次是否放行"，而是验证**累积暴露账本**是否按设计收敛：
L1 覆盖率闸 / L1b 重复提问豁免 / L2 配额 / L2b 单轮上限 /
L3 窗口总闸 / L5 长周期闸，以及风险分的惰性衰减。
"""
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app import jigsaw
from app.models import ExposureLedger


@dataclass
class FakeHit:
    """evaluate() 只消费 .doc_id / .chunk_id / .doc_title / .content 四个属性。"""

    doc_id: str
    chunk_id: str
    doc_title: str = "测试报告"
    content: str = "这是一段用于计字符的正文内容，长度足够触发累计。"


@pytest.fixture
def jcfg(monkeypatch):
    """把各处阈值收敛到便于推理的小整数，避免依赖 .env / 部署配置。"""
    cfg = {
        "JIGSAW_ENABLED": True,
        "JIGSAW_ADMIN_EXEMPT": False,
        "JIGSAW_WINDOW_HOURS": 24,
        "JIGSAW_MIN_DOC_CHUNKS": 5,
        "JIGSAW_DOC_COVER_WARN": 0.5,
        "JIGSAW_DOC_COVER_STOP": 0.8,
        "JIGSAW_MAX_CHUNKS_PER_DOC": 10,
        "JIGSAW_MAX_PER_TURN": 2,
        "JIGSAW_USER_DOC_LIMIT": 50,
        "JIGSAW_USER_CHAR_LIMIT": 10 ** 9,
        "JIGSAW_LONG_WINDOW_DAYS": 7,
        "JIGSAW_LONG_USER_CHAR": 10 ** 9,
        "JIGSAW_LONG_DOC_CHAR": 10 ** 9,
        "JIGSAW_RISK_READONLY": 3,
        "JIGSAW_FULLREAD_LIMIT": 3,
    }
    for k, v in cfg.items():
        monkeypatch.setattr(jigsaw, k, v, raising=False)
    return cfg


def _seed(db, user, doc_id, seen_ids=(), *, char_total=0, query_count=0,
          full_read_count=0, window_key=None):
    row = ExposureLedger(
        user_id=user.id, doc_id=doc_id,
        window_key=window_key or jigsaw.current_window_key(),
        seen_chunks=json.dumps(sorted(seen_ids)),
        seen_count=len(seen_ids), char_total=char_total,
        query_count=query_count, full_read_count=full_read_count,
    )
    db.add(row)
    db.flush()
    return row


def _make_chunks(db, doc_id, n):
    ids = []
    for i in range(n):
        from app.models import Chunk, new_id

        c = Chunk(id=new_id(), doc_id=doc_id, seq=i, content=f"第{i}段正文",
                  content_len=5)
        db.add(c)
        db.flush()
        ids.append(c.id)
    return ids


# ------------------------------------------------------------ 风险分惰性衰减

_BASE = datetime(2024, 1, 1)


@pytest.mark.parametrize(
    "score,age_days,expected",
    [
        (5, 0, 5),      # 刚记的账不衰减
        (5, 29, 5),     # 未满 30 天不衰减
        (5, 30, 4),     # 每满 30 天 -1
        (5, 59, 4),
        (5, 60, 3),
        (5, 150, 0),    # 150 // 30 = 5 → 归零
        (5, 10_000, 0),
        (1, 30, 0),
    ],
)
def test_effective_risk_decays_every_30_days(score, age_days, expected):
    ts = _BASE - timedelta(days=age_days)
    assert jigsaw.effective_risk(score, ts, now=_BASE) == expected


def test_effective_risk_without_timestamp_is_zero():
    """没打过时间戳（从未触发）→ 一律按 0 处理，不能把 None 当 genesis。"""
    assert jigsaw.effective_risk(3, None) == 0
    assert jigsaw.effective_risk(0, None) == 0


def test_effective_risk_is_monotonic_non_increasing():
    ts = _BASE - timedelta(days=10)
    prev = None
    for d in range(0, 200, 10):
        cur = jigsaw.effective_risk(9, ts, now=_BASE + timedelta(days=d))
        assert prev is None or cur <= prev
        prev = cur


def test_effective_risk_never_negative():
    assert jigsaw.effective_risk(1, _BASE - timedelta(days=3650), now=_BASE) == 0


# ------------------------------------------------------------ 高危判定


def test_is_high_risk_at_threshold(db, user_factory, jcfg):
    user = user_factory("u", clearance=1)
    user.risk_score = 3
    user.last_risk_ts = datetime.utcnow()
    assert jigsaw.is_high_risk(user) is True

    user.risk_score = 2
    assert jigsaw.is_high_risk(user) is False


def test_is_high_risk_respects_decay(db, user_factory, jcfg):
    user = user_factory("u", clearance=1)
    user.risk_score = 3
    user.last_risk_ts = datetime.utcnow() - timedelta(days=90)
    assert jigsaw.is_high_risk(user) is False


def test_is_high_risk_admin_exempt(db, user_factory, jcfg, monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_ADMIN_EXEMPT", True, raising=False)
    admin = user_factory("boss", clearance=3, roles=["admin"])
    admin.risk_score = 10
    admin.last_risk_ts = datetime.utcnow()
    assert jigsaw.is_high_risk(admin) is False


def test_is_high_risk_disabled_when_threshold_zero(db, user_factory, jcfg,
                                                   monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_RISK_READONLY", 0, raising=False)
    user = user_factory("u", clearance=1)
    user.risk_score = 99
    user.last_risk_ts = datetime.utcnow()
    assert jigsaw.is_high_risk(user) is False


# ------------------------------------------------------------ 滚动窗口键


def test_long_window_keys_counts_days(jcfg):
    keys = jigsaw.long_window_keys(7)
    assert len(keys) == 7
    assert keys == sorted(set(keys), reverse=False)[::-1]
    assert keys[0] == jigsaw.current_window_key()


def test_long_window_keys_hourly_span(jcfg, monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_WINDOW_HOURS", 1, raising=False)
    assert len(jigsaw.long_window_keys(7)) == 168


def test_long_window_keys_at_least_one(jcfg):
    assert len(jigsaw.long_window_keys(0)) == 1


def test_window_key_is_stable_within_bucket(jcfg):
    assert jigsaw.current_window_key() == jigsaw.current_window_key()
    assert jigsaw.current_window_key().startswith("w")


# ------------------------------------------------------------ 长周期聚合


def test_long_period_totals_sums_across_windows(db, user_factory, doc_factory, jcfg):
    user = user_factory("u", clearance=1)
    d1 = doc_factory("A")
    d2 = doc_factory("B")
    keys = jigsaw.long_window_keys(7)
    _seed(db, user, d1.id, char_total=100, window_key=keys[0])
    _seed(db, user, d1.id, char_total=50, window_key=keys[1])
    _seed(db, user, d2.id, char_total=25, window_key=keys[2])

    total, per_doc = jigsaw.long_period_totals(db, user)
    assert total == 175
    assert per_doc[d1.id] == 150
    assert per_doc[d2.id] == 25


def test_long_period_totals_ignores_other_users(db, user_factory, jcfg):
    me = user_factory("me", clearance=1)
    other = user_factory("other", clearance=1)
    _seed(db, me, "d1", char_total=10)
    _seed(db, other, "d2", char_total=999)
    total, per_doc = jigsaw.long_period_totals(db, me)
    assert total == 10
    assert set(per_doc) == {"d1"}


# ------------------------------------------------------------ evaluate：单轮上限


def test_evaluate_caps_new_slices_per_turn(db, user_factory, doc_factory, jcfg):
    """L2b：一篇 10 段的文档，即便覆盖率只有 0%，单轮也不许一次搬空。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("年度报告")
    ids = _make_chunks(db, doc.id, 10)

    hits = [FakeHit(doc.id, cid) for cid in ids]
    allowed, report = jigsaw.evaluate(db, user, hits)

    assert len(allowed) == jcfg["JIGSAW_MAX_PER_TURN"] == 2
    assert report["level"] == "none"
    assert report["docs"][0]["delivered"] == 2
    assert report["docs"][0]["coverage"] == 0.0


def test_evaluate_records_delivered_into_ledger(db, user_factory, doc_factory, jcfg):
    user = user_factory("u", clearance=1)
    doc = doc_factory("年度报告")
    ids = _make_chunks(db, doc.id, 10)

    jigsaw.evaluate(db, user, [FakeHit(doc.id, cid) for cid in ids])
    row = db.execute(
        select(ExposureLedger).where(ExposureLedger.user_id == user.id)
    ).scalars().first()

    assert row is not None
    assert set(json.loads(row.seen_chunks)) == set(ids[:2])
    assert row.seen_count == 2
    assert row.query_count == 1
    assert row.char_total > 0


# ------------------------------------------------------------ evaluate：覆盖率闸


def test_evaluate_warn_level_throttles_to_one(db, user_factory, doc_factory, jcfg):
    """覆盖率 >= WARN → 每轮最多再给 1 段。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("年度报告")
    ids = _make_chunks(db, doc.id, 10)
    _seed(db, user, doc.id, ids[:6])

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    assert report["level"] == "warn"
    assert len(allowed) == 1
    assert report["docs"][0]["capped"] is True
    assert report["docs"][0]["coverage"] == 0.6
    assert "限流" in report["message"]


def test_evaluate_stop_level_blocks_doc(db, user_factory, doc_factory, jcfg):
    """覆盖率 >= STOP → 本轮起不再供给该文档的新切片。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("年度报告")
    ids = _make_chunks(db, doc.id, 10)
    _seed(db, user, doc.id, ids[:8])

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    assert allowed == []
    assert report["level"] == "restrict"
    assert "停机阈值" in report["message"]


def test_evaluate_short_doc_skips_coverage_gate(db, user_factory, doc_factory,
                                                jcfg):
    """短文档（段数 < MIN_DOC_CHUNKS）不启用覆盖率闸 —— 问两句就 100% 的
    小文档本身没有可拼的空间，启用只会把正常用户锁死。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("短备忘")
    real = _make_chunks(db, doc.id, 3)
    _seed(db, user, doc.id, real[:2])

    fresh = [FakeHit(doc.id, f"other-{i}") for i in range(5)]
    allowed, report = jigsaw.evaluate(db, user, fresh)

    assert report["docs"][0]["coverage"] == 0.0
    assert report["level"] == "none"
    # 未被限流：拿到的是 MAX_PER_TURN(2) 段，而不是 warn 后的 1 段
    assert len(allowed) == 2


def test_evaluate_long_doc_same_ratio_is_throttled(db, user_factory, doc_factory,
                                                   jcfg, monkeypatch):
    """对照组：同样 ~66% 的已披露比例，长文档命中 WARN → 只给 1 段。"""
    monkeypatch.setattr(jigsaw, "JIGSAW_MIN_DOC_CHUNKS", 1, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("短备忘")
    real = _make_chunks(db, doc.id, 3)
    _seed(db, user, doc.id, real[:2])

    fresh = [FakeHit(doc.id, f"other-{i}") for i in range(5)]
    allowed, report = jigsaw.evaluate(db, user, fresh)

    assert report["level"] == "warn"
    assert len(allowed) == 1


# ------------------------------------------------------------ evaluate：重复提问豁免


def test_evaluate_replay_is_not_capped(db, user_factory, doc_factory, jcfg):
    """候选全是已见切片 → 没有新增泄漏，允许重放，且不能标记为限流。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("年度报告")
    ids = _make_chunks(db, doc.id, 6)
    _seed(db, user, doc.id, ids)

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])
    entry = report["docs"][0]

    assert report["level"] == "none"
    assert entry["capped"] is False
    assert entry["delivered"] == 0
    assert entry["replayed"] == 2
    assert len(allowed) == 2


# ------------------------------------------------------------ evaluate：L3 / L5 总闸


def test_evaluate_window_doc_limit_blocks(db, user_factory, doc_factory, jcfg,
                                          monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_USER_DOC_LIMIT", 1, raising=False)
    user = user_factory("u", clearance=1)
    other = doc_factory("别的文档")
    _seed(db, user, other.id, char_total=10)
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 4)
    # 先提交让本会话的写入落库：断言随后读风险分，取的是已提交状态。
    # （bump_risk 走 savepoint 提交，落在调用方事务上，不再另起连接。）
    db.commit()

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    assert allowed == []
    assert report["level"] == "block"
    assert "本时间窗" in report["message"]


def test_evaluate_long_period_user_gate_blocks(db, user_factory, doc_factory, jcfg,
                                               monkeypatch):
    """L5：短窗口滚过去就清零，必须靠长周期口径堵住慢速渗透。"""
    monkeypatch.setattr(jigsaw, "JIGSAW_LONG_USER_CHAR", 100, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    _seed(db, user, doc.id, char_total=200)
    ids = _make_chunks(db, doc.id, 4)
    db.commit()   # 同上：先提交，让 evaluate 读到已落库的状态

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    assert allowed == []
    assert report["level"] == "block"
    assert "长期防批量拉取阈值" in report["message"]


def test_evaluate_long_period_per_doc_gate_blocks(db, user_factory, doc_factory,
                                                  jcfg, monkeypatch):
    """L5b：单文档每天取一点点，短窗口覆盖率闸看不到全貌，靠字符量累积识别。"""
    monkeypatch.setattr(jigsaw, "JIGSAW_LONG_DOC_CHAR", 100, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    _seed(db, user, doc.id, char_total=200)
    ids = _make_chunks(db, doc.id, 4)

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    assert allowed == []
    assert report["level"] == "restrict"
    assert "长期累计上限" in report["message"]


def test_evaluate_blocks_bump_user_risk(db, user_factory, doc_factory, jcfg,
                                        monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_USER_CHAR_LIMIT", 10, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    _seed(db, user, doc.id, char_total=50)
    ids = _make_chunks(db, doc.id, 4)
    db.commit()   # 同上：先提交，让 bump_risk 的 savepoint 提交落在干净事务上

    jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])

    db.refresh(user)
    assert user.risk_score >= 1
    assert user.last_risk_ts is not None


def test_evaluate_no_risk_bump_on_single_doc_stop(db, user_factory, doc_factory,
                                                  jcfg):
    """单文档停机阈值不算风险：认真啃同一份材料的分析师不该被记一笔。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 10)
    _seed(db, user, doc.id, ids[:9])
    db.commit()   # 同上：避免单文档停机不算风险这条断言反过来依赖未提交事务

    jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])
    db.refresh(user)
    assert user.risk_score == 0


# ------------------------------------------------------------ evaluate：开关与豁免


def test_evaluate_bypass_when_disabled(db, user_factory, doc_factory, jcfg,
                                       monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_ENABLED", False, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 4)
    hits = [FakeHit(doc.id, c) for c in ids]

    allowed, report = jigsaw.evaluate(db, user, hits)
    assert allowed == hits
    assert report["level"] == "none"


def test_evaluate_admin_exempt(db, user_factory, doc_factory, jcfg, monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_ADMIN_EXEMPT", True, raising=False)
    admin = user_factory("boss", clearance=3, roles=["admin"])
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 4)
    hits = [FakeHit(doc.id, c) for c in ids]

    allowed, report = jigsaw.evaluate(db, admin, hits)
    assert allowed == hits
    assert report["level"] == "none"


def test_evaluate_empty_hits_short_circuit(db, user_factory, jcfg):
    user = user_factory("u", clearance=1)
    allowed, report = jigsaw.evaluate(db, user, [])
    assert allowed == []
    assert report["level"] == "none"


# ------------------------------------------------------------ 全篇直读闸


def test_full_read_limit_blocks_after_limit(db, user_factory, doc_factory, jcfg,
                                            monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_FULLREAD_LIMIT", 1, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    chunks = []
    for i in range(3):
        from app.models import Chunk, new_id

        c = Chunk(id=new_id(), doc_id=doc.id, seq=i, content=f"正文{i}")
        db.add(c)
        chunks.append(c)
    db.flush()

    ok, msg = jigsaw.check_full_read(db, user, doc)
    assert (ok, msg) == (True, "")

    jigsaw.record_full_read(db, user, doc, chunks)
    ok, msg = jigsaw.check_full_read(db, user, doc)
    assert ok is False
    assert "达到上限" in msg


def test_full_read_marks_chunks_as_seen(db, user_factory, doc_factory, jcfg):
    """全文读过就不能再用问答把同样的切片当成「新碎片」再拿一遍。"""
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 4)

    from app.models import Chunk

    chunks = db.execute(
        select(Chunk).where(Chunk.doc_id == doc.id)
    ).scalars().all()
    jigsaw.record_full_read(db, user, doc, chunks)

    allowed, report = jigsaw.evaluate(db, user, [FakeHit(doc.id, c) for c in ids])
    entry = report["docs"][0]
    assert entry["delivered"] == 0
    assert entry["capped"] is False


def test_full_read_counts_chars(db, user_factory, doc_factory, jcfg):
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    ids = _make_chunks(db, doc.id, 3)

    from app.models import Chunk

    chunks = db.execute(
        select(Chunk).where(Chunk.doc_id == doc.id)
    ).scalars().all()
    jigsaw.record_full_read(db, user, doc, chunks)

    row = db.execute(
        select(ExposureLedger).where(ExposureLedger.user_id == user.id)
    ).scalars().first()
    assert row.char_total == sum(len(c.content) for c in chunks)
    assert row.full_read_count == 1
    assert set(json.loads(row.seen_chunks)) == set(ids)


def test_full_read_bypass_when_disabled(db, user_factory, doc_factory, jcfg,
                                        monkeypatch):
    monkeypatch.setattr(jigsaw, "JIGSAW_ENABLED", False, raising=False)
    user = user_factory("u", clearance=1)
    doc = doc_factory("目标文档")
    jigsaw.record_full_read(db, user, doc, [])
    ok, msg = jigsaw.check_full_read(db, user, doc)
    assert (ok, msg) == (True, "")


# ------------------------------------------------------------ 风险榜


def test_risk_board_flags_high_coverage_only(db, user_factory, doc_factory, jcfg):
    user = user_factory("u", clearance=1)
    risky = doc_factory("长文档")
    _make_chunks(db, risky.id, 10)
    _seed(db, user, risky.id, seen_ids=["x"] * 9, char_total=0)

    calm = doc_factory("普通文档")
    _make_chunks(db, calm.id, 10)
    _seed(db, user, calm.id, seen_ids=["y"] * 2, char_total=0)

    board = jigsaw.risk_board(db)
    flagged = {row["doc_id"] for row in board}
    assert risky.id in flagged
    assert calm.id not in flagged
    entry = next(r for r in board if r["doc_id"] == risky.id)
    assert entry["risk"] == "high"
    assert entry["coverage"] == 0.9


def test_risk_board_excludes_short_docs(db, user_factory, doc_factory, jcfg):
    """短文档 100% 也在体表外：噪声会淹没真实信号。"""
    user = user_factory("u", clearance=1)
    short = doc_factory("两段备忘录")
    _make_chunks(db, short.id, 2)
    _seed(db, user, short.id, seen_ids=["a", "b"], char_total=0)

    board = jigsaw.risk_board(db)
    assert all(row["doc_id"] != short.id for row in board)
