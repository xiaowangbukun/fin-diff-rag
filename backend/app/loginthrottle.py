# SPDX-License-Identifier: Apache-2.0
"""登录防爆破：按 key（用户名 / "用户名#mfa"）的失败计数 + 锁定。

pbkdf2 600k 迭代只能压慢爆破，不能阻止——在线猜解的成本上限不在哈希算力上，
而在"允许猜多少次"。这里把"无限试"变成"试 LOGIN_MAX_FAILS 次等
LOGIN_LOCK_MINUTES 分钟"。

两种后端（LOGIN_THROTTLE_BACKEND = auto | memory | db）：
  · memory：进程内字典，零依赖、零延迟。单 worker 够用，但多 worker 各计
    各的——攻击者把失败分散到不同 worker 就能绕过单进程阈值（历史边界）。
  · db：PostgreSQL 单表 `login_attempts`，所有 worker 读同一份计数。行级
    `SELECT ... FOR UPDATE` 把"读计数 → 判定 → 写锁定"串行化，跨进程不会
    出现"两边都以为还没到阈值"的竞态。auto（默认）在有 DATABASE_URL 时选
    db；db 连不上时单次自动回落 memory 并降频重试，审计/登录不因计数存储
    故障而整体不可用（可用性与保密性的取舍：回落期爆破成本仍被单进程阈值
    抬高，而不是完全敞开）。

其余取舍与历史实现一致：
  · 锁定 = 用可用性换保密性的标准取舍：拒绝服务化风险由攻击者故意输错
    口令触发，靠 LOGIN_LOCK_MINUTES 自愈 + 运维侧重置缓解。
  · 无清理线程：窗口裁剪与锁定到期都是惰性的（读取/记录时顺带算），
    空闲期零成本，不养常驻线程。
"""
import logging
import math
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError

from . import config as cfg
from .config import (
    LOGIN_LOCK_MINUTES, LOGIN_MAX_FAILS, LOGIN_WINDOW_MINUTES,
)

logger = logging.getLogger("finrag.loginthrottle")

# ---------------- memory 后端 ----------------

_ATTEMPTS: dict[str, list[float]] = {}   # key -> 窗口内失败时间戳（单调时钟）
_LOCKED: dict[str, float] = {}           # key -> 锁定到期时刻（单调时钟）
_lock = threading.Lock()


def _now() -> float:
    """单调时钟：不受系统时间调整影响（锁定时长必须是真实流逝的时间）。"""
    return time.monotonic()


# 墙上时间 = 进程启动时刻的 UTC + 单调时钟走过的时长。锁定期与窗口都以
# "真实流逝的时间"为准，而不是 datetime.utcnow()：后者在 NTP 回拨/人工改表
# 时会让锁定提前失效（时钟倒退 = locked_until 永远不到期或瞬间到期）。
# 单调时钟 + 固定偏移同时让测试可以整体注入假时钟（monkeypatch _now）。
_BOOT_MONO = time.monotonic()
_BOOT_UTC = datetime.utcnow()


def _utcnow() -> datetime:
    return _BOOT_UTC + timedelta(seconds=_now() - _BOOT_MONO)


def _key(username: str) -> str:
    """归一化口径与 auth.py 查库一致（strip），避免 "  bob  " 绕过计数。

    截到 160 与 login_attempts.key 列宽一致：超长用户名在内存后端无害，
    但进 DB 主键会撞 StringDataRightTruncation。
    """
    return (username or "").strip()[:160]


def _mem_is_locked(key: str) -> int:
    if not key:
        return 0
    with _lock:
        until = _LOCKED.get(key)
        if until is None:
            return 0
        remaining = until - _now()
        if remaining <= 0:
            del _LOCKED[key]      # 惰性过期：读取即清理，无需后台线程
            return 0
        return int(math.ceil(remaining))


def _mem_record_failure(key: str) -> None:
    if not key:
        return
    now = _now()
    window = LOGIN_WINDOW_MINUTES * 60
    with _lock:
        attempts = _ATTEMPTS.setdefault(key, [])
        attempts[:] = [t for t in attempts if now - t < window]
        attempts.append(now)
        if len(attempts) >= LOGIN_MAX_FAILS:
            _LOCKED[key] = now + LOGIN_LOCK_MINUTES * 60


def _mem_record_success(key: str) -> None:
    if not key:
        return
    with _lock:
        _ATTEMPTS.pop(key, None)
        _LOCKED.pop(key, None)


# ---------------- db 后端（跨 worker 共享）----------------

# db 后端故障后的降频重试：连续失败时不要让每次登录都去等一次连接超时。
_DB_RETRY_AFTER = 30.0
_db_broken_until = 0.0
_db_lock = threading.Lock()


def _db_usable() -> bool:
    if cfg.LOGIN_THROTTLE_BACKEND == "memory":
        return False
    if not cfg.DATABASE_URL:
        return False
    return time.monotonic() >= _db_broken_until


def _mark_db_broken(exc: Exception) -> None:
    global _db_broken_until
    with _db_lock:
        first = time.monotonic() >= _db_broken_until
        _db_broken_until = time.monotonic() + _DB_RETRY_AFTER
    if first:   # 只告警一次，避免连接故障时刷屏
        logger.warning("登录失败计数改为进程内（数据库不可用，%s 秒后重试）：%s",
                       int(_DB_RETRY_AFTER), exc)


def _session():
    from .db import SessionLocal
    return SessionLocal()


def _db_is_locked(key: str) -> int:
    now = _utcnow()
    db = _session()
    try:
        row = db.execute(
            select(_model().locked_until, _model().first_ts)
            .where(_model().key == key)
        ).first()
        if row is None:
            return 0
        locked_until, first_ts = row[0], row[1]
        if locked_until is not None:
            if locked_until <= now:
                # 锁定到期：清标记，并把窗口起点重置（等价于"重新开始计数"）
                db.execute(delete(_model()).where(_model().key == key))
                db.commit()
                return 0
            return int(math.ceil((locked_until - now).total_seconds()))
        # 没在锁定中，但窗口已过：顺手清掉陈旧行，避免表随用户名无限增长
        if first_ts and now - first_ts >= timedelta(minutes=LOGIN_WINDOW_MINUTES):
            db.execute(delete(_model()).where(_model().key == key))
            db.commit()
        return 0
    finally:
        db.close()


def _db_record_failure(key: str) -> None:
    now = _utcnow()
    window = timedelta(minutes=LOGIN_WINDOW_MINUTES)
    db = _session()
    try:
        model = _model()
        # 先插空行（并发首插不报错），再对单行加锁读改写：跨 worker 串行化
        db.execute(pg_insert(model).values(
            key=key, fails=0, first_ts=now, updated_at=now,
        ).on_conflict_do_nothing(index_elements=[model.key]))
        row = db.execute(
            select(model).where(model.key == key).with_for_update()
        ).scalar_one()
        # 窗口口径必须与内存后端一致：恰好等于窗口长度的旧失败已滚出
        # （内存侧是 "now - t < window" 保留，等于 0 的那条被丢弃）。
        if now - (row.first_ts or now) >= window:
            row.fails = 0
            row.first_ts = now
        row.fails = int(row.fails or 0) + 1
        row.updated_at = now
        if row.fails >= LOGIN_MAX_FAILS:
            row.locked_until = now + timedelta(minutes=LOGIN_LOCK_MINUTES)
        db.commit()
    finally:
        db.close()


def _db_record_success(key: str) -> None:
    db = _session()
    try:
        db.execute(delete(_model()).where(_model().key == key))
        db.commit()
    finally:
        db.close()


def _model():
    from .models import LoginAttempt
    return LoginAttempt


# ---------------- 对外 API（调用方口径不变）----------------

def backend() -> str:
    """当前生效的后端名（诊断/测试用）：memory | db。"""
    return "db" if _db_usable() else "memory"


def is_locked(username: str) -> int:
    """剩余锁定秒数（向上取整，至少 1）；0 = 未锁定。到期惰性清除。"""
    key = _key(username)
    if not key:
        return 0
    if _db_usable():
        try:
            return _db_is_locked(key)
        except SQLAlchemyError as exc:   # 计数存储故障不能把登录入口打挂
            _mark_db_broken(exc)
    return _mem_is_locked(key)


def record_failure(username: str) -> None:
    """记一次失败；窗口内失败数达到上限即置锁定（自此刻起算锁定时长）。"""
    key = _key(username)
    if not key:
        return
    if _db_usable():
        try:
            _db_record_failure(key)
            return
        except SQLAlchemyError as exc:
            _mark_db_broken(exc)
    _mem_record_failure(key)


def record_success(username: str) -> None:
    """登录成功：清零失败记录与锁定（口令正确即证明持有凭证）。"""
    key = _key(username)
    if not key:
        return
    if _db_usable():
        try:
            _db_record_success(key)
            return
        except SQLAlchemyError as exc:
            _mark_db_broken(exc)
    _mem_record_success(key)


def reset(key: str | None = None) -> None:
    """清零（测试隔离；运维侧无入口——锁定只等自愈或进程重启）。

    给了 key 只清该 key（含 db 行）；不给则全清，并把 db 故障标记复位。
    """
    global _db_broken_until
    with _lock:
        if key is None:
            _ATTEMPTS.clear()
            _LOCKED.clear()
        else:
            _ATTEMPTS.pop(key, None)
            _LOCKED.pop(key, None)
    with _db_lock:
        _db_broken_until = 0.0
    if not cfg.DATABASE_URL:
        return
    try:
        db = _session()
        try:
            stmt = delete(_model())
            if key is not None:
                stmt = stmt.where(_model().key == key)
            db.execute(stmt)
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001 宽口径：清理失败不该让调用方（测试/运维）中断
        logger.debug("清理登录失败计数失败：%s", exc)

