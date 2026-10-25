# SPDX-License-Identifier: AGPL-3.0-only
"""IdP claim → 本地角色/密级同步（app/idp_sync.py）。

安全口径（每条都有对应用例）：
  · 默认关闭：不开开关时任何 claim 都不写库；
  · 白名单：claim 值不在映射表里 → 默认忽略（不动本地权限），
    严格模式（OIDC_CLAIM_SYNC_UNKNOWN=deny）→ 直接拒绝登录；
  · 密级上限：IdP 标 secret 也只能到 OIDC_CLAIM_SYNC_MAX_CLEARANCE，
    绝密必须由本地管理员授；
  · admin 例外：映射到 admin 但未开 OIDC_CLAIM_SYNC_ALLOW_ADMIN → 忽略；
    本地已授的 admin 不会被同步抹掉（防把唯一管理员锁在门外）；
  · claim 缺失 ≠ 收权：IdP 没发这个 claim 时完全不动本地角色；
    只有 claim 存在时才按映射表对齐（这才是 IdP 表达"收回"的方式）。
"""
import json

import pytest

from app import config, idp_sync
from app.models import User, new_id


@pytest.fixture
def user(db):
    u = User(id=new_id(), username="alice", display_name="alice",
             clearance=1, roles=json.dumps(["research"]),
             pwd_hash="x", salt="y", status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def sync_on(monkeypatch):
    """基线：开启同步 + 一张最小的白名单映射。"""
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC", True)
    monkeypatch.setattr(config, "OIDC_ROLE_CLAIM", "roles")
    monkeypatch.setattr(config, "OIDC_ROLE_MAP",
                        "fin_research:research,fin_risk:risk,fin_admin:admin")
    monkeypatch.setattr(config, "OIDC_CLEARANCE_CLAIM", "clearance")
    monkeypatch.setattr(config, "OIDC_CLEARANCE_MAP",
                        "public:0,internal:1,confidential:2,secret:3")
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_MAX_CLEARANCE", 1)
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_ALLOW_ADMIN", False)
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_UNKNOWN", "ignore")
    return None


def _roles(u):
    return sorted(u.role_list())


# ---------------------------------------------------------------- 开关

def test_disabled_by_default_never_touches_user(db, user):
    """防：IdP 侧一次误配置就改写本地权限——默认必须是关的。"""
    assert config.OIDC_CLAIM_SYNC is False
    out = idp_sync.apply(db, user, {"roles": ["fin_admin"], "clearance": "secret"})
    assert out == {"enabled": False, "changed": False}
    db.refresh(user)
    assert _roles(user) == ["research"] and user.clearance == 1


def test_no_change_produces_no_diff(db, user, sync_on):
    out = idp_sync.apply(db, user, {"roles": ["fin_research"], "clearance": "internal"})
    assert out["enabled"] is True and out["changed"] is False
    assert out["roles_added"] == [] and out["roles_removed"] == []


# ---------------------------------------------------------------- 角色

def test_whitelisted_role_is_granted(db, user, sync_on):
    out = idp_sync.apply(db, user, {"roles": ["fin_research", "fin_risk"]})
    assert out["changed"] is True
    assert out["roles_added"] == ["risk"]
    db.refresh(user)
    assert _roles(user) == ["research", "risk"]


def test_unknown_claim_value_ignored_by_default(db, user, sync_on):
    """防：IdP 自创的角色名被当成权限写进库（应只认白名单）。"""
    out = idp_sync.apply(db, user, {"roles": ["fin_research", "superuser"]})
    assert out["changed"] is False
    db.refresh(user)
    assert _roles(user) == ["research"]


def test_unknown_claim_value_can_reject_login(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_UNKNOWN", "deny")
    from app.oidc import OidcError
    with pytest.raises(OidcError) as exc:
        idp_sync.apply(db, user, {"roles": ["superuser"]})
    assert exc.value.code == "claim_sync_rejected"
    db.refresh(user)
    assert _roles(user) == ["research"]      # 拒绝时不改库


def test_role_claim_present_aligns_and_revokes(db, user, sync_on):
    """claim 存在即权威：IdP 只发 fin_risk → research 被收回。"""
    out = idp_sync.apply(db, user, {"roles": ["fin_risk"]})
    assert out["roles_added"] == ["risk"] and out["roles_removed"] == ["research"]
    db.refresh(user)
    assert _roles(user) == ["risk"]


def test_missing_role_claim_does_not_revoke(db, user, sync_on):
    """防：IdP 没发 claim（scope 未授权/字段改名）被当成"全部收回"。"""
    out = idp_sync.apply(db, user, {"clearance": "internal"})
    assert out["changed"] is False
    db.refresh(user)
    assert _roles(user) == ["research"]


def test_empty_role_claim_revokes_all(db, user, sync_on):
    """claim 存在但为空 = IdP 明确表达"此人无任何角色"。"""
    out = idp_sync.apply(db, user, {"roles": []})
    assert out["roles_removed"] == ["research"]
    db.refresh(user)
    assert _roles(user) == []


def test_role_claim_accepts_string_and_list(db, user, sync_on):
    out = idp_sync.apply(db, user, {"roles": "fin_risk, fin_research"})
    # research 本地已有 → 只新增 risk；两种写法都要能解析出两个角色
    assert out["changed"] is True and out["roles_added"] == ["risk"]
    db.refresh(user)
    assert _roles(user) == ["research", "risk"]


# ---------------------------------------------------------------- admin 例外

def test_admin_not_granted_unless_explicitly_allowed(db, user, sync_on):
    """防：IdP 把某人标成 fin_admin 就获得本地管理员（默认必须拒绝）。"""
    out = idp_sync.apply(db, user, {"roles": ["fin_admin"]})
    assert out["changed"] is True          # 只收回 research，不授予 admin
    db.refresh(user)
    assert _roles(user) == []


def test_admin_granted_when_switch_on(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_ALLOW_ADMIN", True)
    out = idp_sync.apply(db, user, {"roles": ["fin_admin"]})
    assert "admin" in out["roles_added"]
    db.refresh(user)
    assert "admin" in _roles(user)


def test_locally_granted_admin_is_never_revoked_by_claims(db, user, sync_on):
    """防：IdP 少发一个角色就把唯一管理员锁在门外。"""
    user.roles = json.dumps(["admin", "research"])
    db.commit()
    out = idp_sync.apply(db, user, {"roles": ["fin_risk"]})
    db.refresh(user)
    assert "admin" in _roles(user)
    assert out["roles_removed"] == ["research"]


# ---------------------------------------------------------------- 密级

def test_clearance_capped_by_hard_limit(db, user, sync_on):
    """防：IdP 标 secret 直接获得绝密可见性（cap 默认 1=内部）。"""
    out = idp_sync.apply(db, user, {"clearance": "secret"})
    assert out["clearance_to"] == config.OIDC_CLAIM_SYNC_MAX_CLEARANCE == 1
    db.refresh(user)
    assert user.clearance == 1        # 本地本来就是 1 → 无变化
    assert out["changed"] is False


def test_clearance_can_rise_within_cap(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_MAX_CLEARANCE", 2)
    out = idp_sync.apply(db, user, {"clearance": "confidential"})
    assert out["clearance_from"] == 1 and out["clearance_to"] == 2
    db.refresh(user)
    assert user.clearance == 2


def test_clearance_never_lowered_by_claims(db, user, sync_on, monkeypatch):
    """防：IdP 发 public 就把本地授的机密降级（同步只增不降）。"""
    user.clearance = 2
    db.commit()
    out = idp_sync.apply(db, user, {"clearance": "public"})
    assert out["changed"] is False
    db.refresh(user)
    assert user.clearance == 2


def test_unmapped_clearance_value_ignored(db, user, sync_on):
    out = idp_sync.apply(db, user, {"clearance": "top-secret-lol"})
    assert out["changed"] is False
    db.refresh(user)
    assert user.clearance == 1


def test_missing_clearance_claim_does_not_change_level(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_MAX_CLEARANCE", 3)
    out = idp_sync.apply(db, user, {"roles": ["fin_research"]})
    assert out["changed"] is False
    db.refresh(user)
    assert user.clearance == 1


def test_clearance_claim_disabled_by_empty_config(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_CLEARANCE_CLAIM", "")
    out = idp_sync.apply(db, user, {"clearance": "secret", "roles": ["fin_research"]})
    assert out["clearance_to"] == 1 and out["changed"] is False


# ---------------------------------------------------------------- 映射解析

def test_malformed_map_entries_are_skipped_not_crashed(monkeypatch):
    """防：映射表写错一个逗号 → 启动后每次 SSO 登录 500。"""
    monkeypatch.setattr(config, "OIDC_ROLE_MAP", "a:b,,c,d:e,:f,g:")
    parsed = idp_sync._parse_map(config.OIDC_ROLE_MAP)
    assert parsed == {"a": "b", "d": "e"}


def test_empty_maps_mean_no_grants(db, user, sync_on, monkeypatch):
    monkeypatch.setattr(config, "OIDC_ROLE_MAP", "")
    out = idp_sync.apply(db, user, {"roles": ["research", "fin_risk"]})
    assert out["roles_added"] == []
    db.refresh(user)
    assert _roles(user) == []      # claim 存在 + 映射为空 → 全部收回（配置自担）


def test_plan_is_pure_and_reports_claim_values(db, user, sync_on):
    """plan() 不写库：调用方（审计）需要先看到"IdP 说了什么"再落库。"""
    before = json.loads(user.roles)
    result = idp_sync.plan({"roles": ["fin_risk"]}, user)
    assert result["roles"] == ["risk"]
    assert json.loads(user.roles) == before
