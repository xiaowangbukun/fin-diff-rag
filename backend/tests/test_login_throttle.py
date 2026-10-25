# SPDX-License-Identifier: AGPL-3.0-only
"""登录防爆破单测（#11）：窗口计数 / 锁定 / 自愈 / 隔离 / 审计留痕。

口径要点（与实现一一对应）：
  · 第 LOGIN_MAX_FAILS 次失败本身返回 401——锁定从这一刻生效；
  · 第 N+1 次起（哪怕口令正确）429 + Retry-After；
  · 计数按用户名归一化（strip）后归并；锁定到期惰性清除。
时钟：monkeypatch loginthrottle._now 注入假单调时钟，窗口/锁定时效
无需真实 sleep。
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import loginthrottle
from app.audit import flush_audit
from app.config import (
    LOGIN_LOCK_MINUTES, LOGIN_MAX_FAILS, LOGIN_WINDOW_MINUTES,
)
from app.main import app
from app.models import AuditLog
from app.security import hash_password

client = TestClient(app)   # 不走 lifespan：只测路由与 throttle 接线

GOOD_PWD = "Passw0rd!"


class _Clock:
    """假单调时钟（time.monotonic 替身）：只增不减，测试全权控制。"""

    def __init__(self, start: float = 10_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture(autouse=True)
def _reset_throttle():
    """进程内计数跨用例会串味——每条用例前后全清。"""
    loginthrottle.reset()
    yield
    loginthrottle.reset()


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(loginthrottle, "_now", c)
    return c


@pytest.fixture
def real_user(db, user_factory):
    """真实口令用户。

    user_factory 默认 pwd_hash="x" 永远登不进（口令比对必败），
    这里造真实哈希；且必须 db.commit()——user_factory 只 flush 不 commit，
    TestClient 的请求走新 session，看不到未提交数据。
    """
    u = user_factory("throttle01")
    u.pwd_hash, u.salt = hash_password(GOOD_PWD)
    db.commit()
    return u


def _login(username: str, password: str):
    return client.post("/api/v1/auth/login",
                       json={"username": username, "password": password})


# ---------------------------------------------------------------------------
# ① 锁定主路径：第 N 次失败仍 401，第 N+1 次起 429（口令正确也锁）
# ---------------------------------------------------------------------------


def test_lock_after_max_fails_even_correct_password_gets_429(db, real_user, clock):
    for _ in range(LOGIN_MAX_FAILS):
        r = _login("throttle01", "wrong-pass")
        assert r.status_code == 401
        assert r.json()["detail"] == "用户名或密码错误"   # 防枚举：同文案
    # 第 N+1 次：口令正确也进不去
    r = _login("throttle01", GOOD_PWD)
    assert r.status_code == 429
    assert r.headers["Retry-After"] == str(LOGIN_LOCK_MINUTES * 60)
    assert "锁定" in r.json()["detail"]


# ---------------------------------------------------------------------------
# ② 锁定时效：推进 LOGIN_LOCK_MINUTES 后正确口令恢复
# ---------------------------------------------------------------------------


def test_lock_expires_after_configured_minutes(db, real_user, clock):
    for _ in range(LOGIN_MAX_FAILS):
        assert _login("throttle01", "wrong").status_code == 401
    assert _login("throttle01", GOOD_PWD).status_code == 429
    clock.advance(LOGIN_LOCK_MINUTES * 60)
    r = _login("throttle01", GOOD_PWD)
    assert r.status_code == 200
    assert r.json()["token"]


# ---------------------------------------------------------------------------
# ③ 窗口外失败不累计：旧失败滚出窗口后重新计
# ---------------------------------------------------------------------------


def test_failures_outside_window_do_not_accumulate(db, real_user, clock):
    assert _login("throttle01", "wrong").status_code == 401
    clock.advance(LOGIN_WINDOW_MINUTES * 60)          # 旧失败全部滚出窗口
    for _ in range(LOGIN_MAX_FAILS - 1):              # 差一次，不锁
        assert _login("throttle01", "wrong").status_code == 401
    assert loginthrottle.is_locked("throttle01") == 0
    assert _login("throttle01", GOOD_PWD).status_code == 200


# ---------------------------------------------------------------------------
# ④ 成功清零：失败 N-1 次后成功一次，计数归零
# ---------------------------------------------------------------------------


def test_success_clears_failure_count(db, real_user, clock):
    for _ in range(LOGIN_MAX_FAILS - 1):
        assert _login("throttle01", "wrong").status_code == 401
    assert _login("throttle01", GOOD_PWD).status_code == 200
    for _ in range(LOGIN_MAX_FAILS - 1):              # 重新计，差一次不锁
        assert _login("throttle01", "wrong").status_code == 401
    assert loginthrottle.is_locked("throttle01") == 0
    assert _login("throttle01", GOOD_PWD).status_code == 200


# ---------------------------------------------------------------------------
# ⑤ 多用户隔离
# ---------------------------------------------------------------------------


def test_users_are_isolated(db, user_factory, clock):
    u1 = user_factory("iso_a")
    u1.pwd_hash, u1.salt = hash_password(GOOD_PWD)
    u2 = user_factory("iso_b")
    u2.pwd_hash, u2.salt = hash_password(GOOD_PWD)
    db.commit()
    for _ in range(LOGIN_MAX_FAILS):
        assert _login("iso_a", "wrong").status_code == 401
    assert _login("iso_a", GOOD_PWD).status_code == 429
    # b 完全不受 a 的爆破影响
    r = _login("iso_b", GOOD_PWD)
    assert r.status_code == 200
    assert loginthrottle.is_locked("iso_b") == 0


# ---------------------------------------------------------------------------
# ⑥ 429 路径有审计行（deny + reason 含"锁定"）
# ---------------------------------------------------------------------------


def test_locked_attempt_writes_audit(db, real_user, clock):
    for _ in range(LOGIN_MAX_FAILS):
        _login("throttle01", "wrong")
    assert _login("throttle01", GOOD_PWD).status_code == 429
    flush_audit(timeout=2.0)   # write_log 默认异进入队，断言前先排空
    rows = db.execute(
        select(AuditLog).where(
            AuditLog.action == "login", AuditLog.decision == "deny"
        )
    ).scalars().all()
    locked = [x for x in rows if "锁定" in (x.reason or "")]
    assert len(locked) == 1
    assert locked[0].target_label == "throttle01"


# ---------------------------------------------------------------------------
# ⑦ 配置默认值（从 app.config 读，证明读的是配置不是硬编码）
# ---------------------------------------------------------------------------


def test_config_defaults():
    assert LOGIN_MAX_FAILS == 5
    assert LOGIN_WINDOW_MINUTES == 5
    assert LOGIN_LOCK_MINUTES == 15


# ---------------------------------------------------------------------------
# ⑧ 陌生用户 / 空用户名不锁
# ---------------------------------------------------------------------------


def test_is_locked_unknown_user_returns_zero():
    assert loginthrottle.is_locked("never-seen") == 0


def test_is_locked_blank_username_returns_zero():
    assert loginthrottle.is_locked("") == 0
    assert loginthrottle.is_locked("   ") == 0


# ---------------------------------------------------------------------------
# 单元级：is_locked 向上取整 / 惰性过期 / 归一化 / record_success 清锁
# ---------------------------------------------------------------------------


def test_is_locked_rounds_up_and_expires_lazily(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(loginthrottle, "_now", c)
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("u1")
    assert loginthrottle.is_locked("u1") == LOGIN_LOCK_MINUTES * 60
    c.advance(LOGIN_LOCK_MINUTES * 60 - 0.5)      # 剩 0.5s → 向上取整 1
    assert loginthrottle.is_locked("u1") == 1
    c.advance(0.5)                                 # 到期 → 惰性清除
    assert loginthrottle.is_locked("u1") == 0


def test_username_is_normalized_before_counting(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(loginthrottle, "_now", c)
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("  bob  ")
    assert loginthrottle.is_locked("bob") > 0      # 与 auth.py 查库同口径


def test_record_success_clears_lock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(loginthrottle, "_now", c)
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("bob")
    assert loginthrottle.is_locked("bob") > 0
    loginthrottle.record_success("  bob  ")
    assert loginthrottle.is_locked("bob") == 0
