# SPDX-License-Identifier: AGPL-3.0-only
"""登录失败计数的跨 worker 共享（LOGIN_THROTTLE_BACKEND=db）。

要解决的边界：进程内计数在多 worker 部署下是**各计各的**——攻击者把
LOGIN_MAX_FAILS 次失败分散到 N 个 worker 上，就能拿到 N 倍尝试次数。
db 后端把所有 worker 收敛到同一张 `login_attempts` 表，单行 UPDATE +
`SELECT ... FOR UPDATE` 让"读计数 → 判定 → 置锁定"跨进程串行。

本文件的口径：
  · 表格共享：直接写库（模拟另一个 worker 的写入），本进程内存为空也能读到；
  · 并发安全：多线程同时 record_failure，最终计数不丢、锁定恰好在阈值生效；
  · 故障回落：计数存储不可用时退回进程内（登录入口不能整体不可用），
    且降频重试而不是每次登录都等一次连接超时；
  · memory 后端仍可按配置强制启用（单 worker 部署/离线诊断）。
"""
import json
import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, loginthrottle
from app.config import LOGIN_LOCK_MINUTES, LOGIN_MAX_FAILS, LOGIN_WINDOW_MINUTES
from app.main import app
from app.security import hash_password

client = TestClient(app)
GOOD_PWD = "Passw0rd!"


@pytest.fixture(autouse=True)
def _force_db_backend(monkeypatch):
    """本文件专测 db 后端；用完复原并清掉两种后端的残留状态。"""
    monkeypatch.setattr(config, "LOGIN_THROTTLE_BACKEND", "db")
    loginthrottle.reset()
    yield
    loginthrottle.reset()


@pytest.fixture
def clear_memory():
    """模拟"另一个 worker"：进程内字典清空，但不动数据库。"""
    def _clear():
        loginthrottle._ATTEMPTS.clear()   # noqa: SLF001  测试直捣内部状态
        loginthrottle._LOCKED.clear()     # noqa: SLF001
    return _clear


def _login(username: str, password: str):
    return client.post("/api/v1/auth/login",
                       json={"username": username, "password": password})


def _db_row(db, key: str):
    from app.models import LoginAttempt
    return db.execute(select(LoginAttempt).where(LoginAttempt.key == key)).scalar_one_or_none()


# ---------------------------------------------------------------- 共享口径

def test_backend_is_db_when_configured():
    assert loginthrottle.backend() == "db"


def test_counters_written_by_another_worker_are_visible(db, clear_memory):
    """防：多 worker 各计各的——攻击者分散尝试即可绕过单进程阈值。"""
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("shared01")
    row = _db_row(db, "shared01")
    assert row is not None and row.fails == LOGIN_MAX_FAILS
    assert row.locked_until is not None

    clear_memory()      # 换到另一个 worker（内存空）
    assert loginthrottle.is_locked("shared01") > 0


def test_login_reflects_lock_set_by_another_worker(db, user_factory, clear_memory):
    u = user_factory("shared02")
    u.pwd_hash, u.salt = hash_password(GOOD_PWD)
    db.commit()

    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("shared02")   # 另一 worker 记的失败
    clear_memory()
    r = _login("shared02", GOOD_PWD)
    assert r.status_code == 429
    assert "锁定" in r.json()["detail"]


def test_locked_attempt_does_not_increment_counter(db, clear_memory):
    """已锁定期间的尝试不再累加（否则每次重试都把锁定时刻往后推，变相永久封号）。"""
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("shared03")
    before = _db_row(db, "shared03").locked_until
    r = _login("shared03", "wrong")            # 命中 429 分支，不调 record_failure
    assert r.status_code == 429
    db.expire_all()
    after = _db_row(db, "shared03").locked_until
    assert after == before


def test_window_expiry_resets_counter(db, clear_memory, monkeypatch):
    clock = {"t": 10_000.0}
    monkeypatch.setattr(loginthrottle, "_now", lambda: clock["t"])
    for _ in range(LOGIN_MAX_FAILS - 1):
        loginthrottle.record_failure("shared04")
    clock["t"] += LOGIN_WINDOW_MINUTES * 60 + 1
    loginthrottle.record_failure("shared04")
    db.expire_all()
    row = _db_row(db, "shared04")
    assert row.fails == 1, "窗口外的旧失败必须滚出，否则慢慢试也能凑到阈值"
    assert row.locked_until is None


def test_lock_expiry_clears_row(db, clear_memory, monkeypatch):
    clock = {"t": 10_000.0}
    monkeypatch.setattr(loginthrottle, "_now", lambda: clock["t"])
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("shared05")
    assert loginthrottle.is_locked("shared05") == LOGIN_LOCK_MINUTES * 60
    clock["t"] += LOGIN_LOCK_MINUTES * 60 + 0.5
    clear_memory()
    assert loginthrottle.is_locked("shared05") == 0
    db.expire_all()
    assert _db_row(db, "shared05") is None, "到期行应惰性删除，表不随用户名无限增长"


def test_success_clears_shared_counter(db, clear_memory):
    for _ in range(LOGIN_MAX_FAILS - 1):
        loginthrottle.record_failure("shared06")
    loginthrottle.record_success("shared06")
    assert _db_row(db, "shared06") is None
    clear_memory()
    assert loginthrottle.is_locked("shared06") == 0


def test_concurrent_failures_do_not_lose_counts(db, clear_memory):
    """防：并发"读-改-写"丢计数——20 线程同时失败，最终计数必须是 20。"""
    workers = 20
    barrier = threading.Barrier(workers)
    errors: list[Exception] = []

    def _one():
        try:
            barrier.wait(timeout=10)
            loginthrottle.record_failure("burst01")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_one) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert not errors, errors
    db.expire_all()
    row = _db_row(db, "burst01")
    assert row.fails == workers
    assert row.locked_until is not None


# ---------------------------------------------------------------- 故障回落

def test_db_outage_falls_back_to_memory_without_failing_login(
        db, user_factory, monkeypatch):
    """防：计数存储故障把登录入口整体打挂（可用性劣于保密性的正确取舍方向）。"""
    u = user_factory("shared07")
    u.pwd_hash, u.salt = hash_password(GOOD_PWD)
    db.commit()

    def _boom():
        raise __import__("sqlalchemy").exc.OperationalError("stmt", {}, Exception("down"))

    monkeypatch.setattr(loginthrottle, "_session", _boom)
    for _ in range(LOGIN_MAX_FAILS):
        assert _login("shared07", "wrong").status_code == 401
    # 回落进程内后仍然锁定（不是"敞开无限试"）
    r = _login("shared07", GOOD_PWD)
    assert r.status_code == 429
    assert loginthrottle.backend() == "memory"


def test_memory_backend_ignores_database(db, clear_memory, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_THROTTLE_BACKEND", "memory")
    assert loginthrottle.backend() == "memory"
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("shared08")
    assert _db_row(db, "shared08") is None
    memory_before = loginthrottle.is_locked("shared08")
    assert memory_before > 0
    clear_memory()      # 单 worker 部署下"内存清空"等价于进程重启
    assert loginthrottle.is_locked("shared08") == 0


def test_username_key_is_capped_to_column_width(db):
    """防：超长用户名撞 VARCHAR(160) 主键 → 登录 500（StringDataRightTruncation）。"""
    long_name = "u" * 300
    loginthrottle.record_failure(long_name)
    row = _db_row(db, long_name[:160])
    assert row is not None and row.fails == 1


def test_second_factor_counter_is_separate(db):
    """"用户名#mfa" 与 "用户名" 是两条独立计数：口令错不该提前锁死验证码通道。"""
    for _ in range(LOGIN_MAX_FAILS):
        loginthrottle.record_failure("alice#mfa")
    assert loginthrottle.is_locked("alice#mfa") > 0
    assert loginthrottle.is_locked("alice") == 0
    keys = [r.key for r in db.execute(
        select(__import__("app.models", fromlist=["LoginAttempt"]).LoginAttempt)
    ).scalars().all()]
    assert keys == ["alice#mfa"]


def test_counters_have_no_plaintext_secrets(db):
    """计数表只该有用户名与时间：不能顺手存口令/口令哈希（合规最小化）。"""
    loginthrottle.record_failure("shared09")
    row = _db_row(db, "shared09")
    columns = {c.name for c in row.__table__.columns}
    assert columns == {"key", "fails", "first_ts", "locked_until", "updated_at"}
    dumped = json.dumps({c: str(getattr(row, c)) for c in columns if c != "fails"},
                        ensure_ascii=False)
    assert GOOD_PWD not in dumped


def test_locked_until_is_bounded(db):
    """锁定时长必须等于配置值：太长=可用性事故，太短=防爆破失效。"""
    loginthrottle.record_failure("shared10")
    db.expire_all()
    row = _db_row(db, "shared10")
    assert row.fails == 1 and row.locked_until is None
    for _ in range(LOGIN_MAX_FAILS - 1):
        loginthrottle.record_failure("shared10")
    db.expire_all()
    row = _db_row(db, "shared10")
    delta = row.locked_until - loginthrottle._utcnow()   # noqa: SLF001
    assert timedelta(0) < delta <= timedelta(minutes=LOGIN_LOCK_MINUTES)
