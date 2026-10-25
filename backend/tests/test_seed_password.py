# SPDX-License-Identifier: AGPL-3.0-only
"""C2：出厂口令风险的可观测与可选强闸（seed.default_password_users + 启动闸）。

事故形态：seed.py 为保证演示可跑，给 admin（密级 3，可见绝密）与业务角色
注入固定口令，且 ensure_seed 幂等重复执行。生产部署若漏改口令，内网任何人
都能用 admin 登录看全库——这是"开箱即用"最大的单点风险。

本文件分两层钉住防线：
  1. **检出逻辑**（seed.default_password_users）：未改密命中 / 已改密不命中 /
     非种子账号不受影响——判据错一次，要么天天误报、要么永不告警；
  2. **启动闸**（main.lifespan）：默认只告警不拦（冒烟链要能登录），
     ENFORCE_PASSWORD_CHANGE=true 时检出即拒绝启动。

口令一律从 `seed.USERS` 读取，测试里不落任何口令字面量。
"""
import asyncio

import pytest

from app.main import app as real_app
from app.models import User, new_id
from app.seed import USERS, default_password_users
from app.security import hash_password


ADMIN_USERNAME = USERS[0][0]          # 种子里的管理员账号名
ADMIN_FACTORY_PWD = USERS[0][5]       # 出厂口令（从代码读，不落字面量）
CHANGED_PWD = "qa-rotated-marker-password"


def _seed_user(db, username=ADMIN_USERNAME, password=ADMIN_FACTORY_PWD,
               clearance=3, roles='["admin"]'):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=roles, pwd_hash=pwd_hash, salt=salt,
             status=True)
    db.add(u)
    db.commit()
    return u


# ------------------------------------------------------------------ 检出逻辑


def test_detects_admin_still_using_factory_password(db):
    """防：出厂口令未改却无人知晓——admin（密级 3）对内网敞开。"""
    _seed_user(db)
    assert default_password_users(db) == [ADMIN_USERNAME]


def test_changed_password_is_not_flagged(db):
    """防：改过密仍被反复告警，运维习惯性忽略后真告警也被淹没。"""
    _seed_user(db, password=CHANGED_PWD)
    assert default_password_users(db) == []


def test_flags_every_unrotated_seed_account(db):
    """防：只检 admin 一个账号，业务角色（密级 2）漏在告警之外。"""
    for username, _n, _d, _r, _c, pwd in USERS:
        pwd_hash, salt = hash_password(pwd)
        db.add(User(id=new_id(), username=username, display_name=username,
                    clearance=1, roles="[]", pwd_hash=pwd_hash, salt=salt,
                    status=True))
    db.commit()

    flagged = default_password_users(db)
    assert sorted(flagged) == sorted(u[0] for u in USERS)


def test_partial_rotation_reports_only_stale_ones(db):
    """防：部分账号已改密时被整体判成"全部安全"，掩盖剩余风险。"""
    _seed_user(db, username=USERS[0][0], password=CHANGED_PWD)
    _seed_user(db, username=USERS[1][0], password=USERS[1][5])
    assert default_password_users(db) == [USERS[1][0]]


def test_non_seed_account_with_same_password_is_ignored(db):
    """防：把自建账号也纳入判定，产出与出厂口令无关的噪音告警。"""
    _seed_user(db, username="ops自建账号", password=ADMIN_FACTORY_PWD)
    assert default_password_users(db) == []


def test_no_users_returns_empty(db):
    """防：空库（尚未 seed）时判定逻辑抛异常，启动闸连带崩溃。"""
    assert default_password_users(db) == []


def test_detection_is_read_only(db):
    """防：检出动作顺手写库（例如强制改密），把只读信号变成副作用。"""
    u = _seed_user(db)
    before = (u.pwd_hash, u.salt)
    default_password_users(db)
    db.refresh(u)
    assert (u.pwd_hash, u.salt) == before


# ------------------------------------------------------------------ 启动闸


def _run_lifespan(monkeypatch, stale: list[str], enforce: bool):
    """驱动 main.lifespan 的启动段（不起服务、不建库、不播种）。

    只保留"口令闸"这一段真实执行，其余副作用（建表/种子/向量索引/审计链）
    全部替换成空操作——既跑到了真实的闸代码，又不拖慢用例、不写真实数据。
    """
    from app import main as main_mod

    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_schema", lambda: [])
    monkeypatch.setattr(main_mod, "ensure_seed", lambda *a, **kw: None)
    monkeypatch.setattr(main_mod, "resume_chain", lambda db: None)
    monkeypatch.setattr(main_mod, "ensure_vector_index", lambda db: {})
    monkeypatch.setattr(main_mod, "check_dimension_consistency", lambda db: None)
    monkeypatch.setattr(main_mod, "shutdown_audit", lambda: None)
    monkeypatch.setattr(main_mod, "default_password_users", lambda db: list(stale))
    monkeypatch.setattr(main_mod, "ENFORCE_PASSWORD_CHANGE", enforce)

    async def _run():
        async with main_mod.lifespan(real_app):
            pass

    asyncio.run(_run())


def test_gate_warns_without_blocking_by_default(monkeypatch, capsys):
    """防：默认就拒绝启动 → 演示与冒烟链（要用 admin 登录）直接跑不起来。

    口径是"默认可观测、可选强闸"：默认必须只告警，且告警要进 stderr
    让日志采集能收到。
    """
    _run_lifespan(monkeypatch, stale=[ADMIN_USERNAME], enforce=False)
    err = capsys.readouterr().err
    assert "[SECURITY]" in err
    assert ADMIN_USERNAME in err


def test_gate_refuses_startup_when_enforced(monkeypatch):
    """防：开了强闸却拦不住——生产环境带着出厂口令照常上线。"""
    with pytest.raises(RuntimeError) as exc:
        _run_lifespan(monkeypatch, stale=[ADMIN_USERNAME], enforce=True)
    assert ADMIN_USERNAME in str(exc.value)
    assert "拒绝启动" in str(exc.value)


def test_gate_stays_silent_when_all_rotated(monkeypatch, capsys):
    """防：全员已改密仍刷告警，噪音会让人忽略真正的 [SECURITY] 行。"""
    _run_lifespan(monkeypatch, stale=[], enforce=True)  # 强闸也不该误拦
    assert "[SECURITY]" not in capsys.readouterr().err


def test_flag_defaults_to_false():
    """防：默认口径漂移成"强制改密"，无声无息改变部署行为。"""
    from app import config

    assert config.ENFORCE_PASSWORD_CHANGE is False
