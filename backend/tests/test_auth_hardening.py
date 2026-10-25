# SPDX-License-Identifier: AGPL-3.0-only
"""认证强度闭环（闭环项 3）：首登强制改密、会话吊销、哈希升级、口令策略。

事故口径：
  · 管理员建号时设定初始口令 → 管理员永久掌握该账号可用凭证；
  · 口令泄露后改密，若旧 JWT 仍有效，攻击者照样在线；
  · 口令哈希停留在 120k、且格式不带参数，后续升级只能全员重置。
这三条都不靠"前端自觉"，必须在服务端有硬闸。

演示种子账号刻意**不**置 must_change_password（用户明确要求保留 demo 口令），
本文件用显式 flag 验证"只有管理员建的账号被强制"。
"""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app as real_app
from app.models import User, new_id
from app.security import hash_password

API = "/api/v1"
STRONG = "Str0ng-Passw0rd!2026"


@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username, password, clearance=1, roles=None,
             must_change=False):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles or []),
             pwd_hash=pwd_hash, salt=salt, status=True,
             must_change_password=must_change, token_version=0)
    db.add(u)
    db.commit()
    return u


def _login(client, username, password):
    return client.post(f"{API}/auth/login",
                       json={"username": username, "password": password})


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def _admin(db, username="root"):
    return _mk_user(db, username, "Adm1n-Passw0rd!2026", clearance=3, roles=["admin"])


def test_admin_created_user_must_change_password_before_use(db, client):
    """管理员建号 → 首登拿到受限会话，除改密外一律 403。"""
    admin = _admin(db)
    created = client.post(f"{API}/admin/users", headers=_hdr(_login(
        client, admin.username, "Adm1n-Passw0rd!2026").json()["token"]),
        json={"username": "newbie", "password": "Init-Passw0rd!2026",
              "clearance": 1, "roles": []})
    assert created.status_code == 201
    assert created.json()["must_change_password"] is True

    login = _login(client, "newbie", "Init-Passw0rd!2026")
    assert login.status_code == 200
    token = login.json()["token"]
    assert login.json()["must_change_password"] is True

    # 硬闸：文档列表不可用（不能靠前端弹窗兜）
    blocked = client.get(f"{API}/docs", headers=_hdr(token))
    assert blocked.status_code == 403
    assert "修改初始口令" in blocked.json()["detail"]
    # 头必须活着送到客户端：main.py 的 SPA 回退处理器会重建 HTTPException
    # 响应，历史上曾把 Retry-After 吃掉；这里钉住"重建不丢头"。
    assert blocked.headers.get("X-Must-Change-Password") == "1"
    # /auth/me 仍可用，否则前端连"我是谁"都取不到
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).status_code == 200

    changed = client.post(f"{API}/auth/change-password", headers=_hdr(token),
                          json={"old_password": "Init-Passw0rd!2026",
                                "new_password": STRONG})
    assert changed.status_code == 200
    new_token = changed.json()["token"]
    assert changed.json()["must_change_password"] is False
    assert client.get(f"{API}/docs", headers=_hdr(new_token)).status_code == 200


def test_old_token_dies_immediately_after_password_change(db, client):
    """改密的目的是止血：改密前签发的令牌必须立即 401，而不是等 12 小时。"""
    _mk_user(db, "alice", "Old-Passw0rd!2026")
    old_token = _login(client, "alice", "Old-Passw0rd!2026").json()["token"]

    changed = client.post(f"{API}/auth/change-password", headers=_hdr(old_token),
                          json={"old_password": "Old-Passw0rd!2026",
                                "new_password": STRONG})
    assert changed.status_code == 200

    assert client.get(f"{API}/auth/me", headers=_hdr(old_token)).status_code == 401
    assert client.get(f"{API}/auth/me",
                      headers=_hdr(changed.json()["token"])).status_code == 200
    # 新旧口令互斥：旧口令不能再登录
    assert _login(client, "alice", "Old-Passw0rd!2026").status_code == 401
    assert _login(client, "alice", STRONG).status_code == 200


def test_wrong_old_password_cannot_reset(db, client):
    """只有持有当前口令的人才能改密，否则拿到令牌就能直接接管。"""
    _mk_user(db, "bob", "Bob-Passw0rd!2026")
    token = _login(client, "bob", "Bob-Passw0rd!2026").json()["token"]

    r = client.post(f"{API}/auth/change-password", headers=_hdr(token),
                    json={"old_password": "guess-Passw0rd!2026",
                          "new_password": STRONG})
    assert r.status_code == 401
    assert _login(client, "bob", "Bob-Passw0rd!2026").status_code == 200


def test_logout_revokes_token(db, client):
    _mk_user(db, "carol", "Carol-Passw0rd!2026")
    token = _login(client, "carol", "Carol-Passw0rd!2026").json()["token"]
    assert client.post(f"{API}/auth/logout", headers=_hdr(token)).status_code == 200
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).status_code == 401


@pytest.mark.parametrize("weak,why", [
    ("Short1!", "至少 12 位"),
    ("alllowercaseonly", "至少三类"),
    ("onlylettersanddigits", "至少三类"),  # 12+ 位但只有两类
    ("Str0ng-Passw0rd!2026", None),      # 基线：合法
])
def test_password_policy(client, db, weak, why):
    from app.password_policy import PasswordPolicyError, validate_password

    if why is None:
        validate_password(weak, "someone")
        return
    with pytest.raises(PasswordPolicyError) as exc:
        validate_password(weak, "someone")
    assert why in str(exc.value)


def test_policy_rejects_username_and_common_password():
    from app.password_policy import PasswordPolicyError, validate_password

    with pytest.raises(PasswordPolicyError):
        validate_password("Alice-Passw0rd!2026", "alice")
    with pytest.raises(PasswordPolicyError):
        validate_password("Admin@123456", "someone")
    with pytest.raises(PasswordPolicyError):
        validate_password("Aa1!Aa1!Aa1!", "someone")   # 字符种类过少


def test_policy_change_endpoint_rejects_weak_and_keeps_old(db, client):
    _mk_user(db, "dave", "Dave-Passw0rd!2026")
    token = _login(client, "dave", "Dave-Passw0rd!2026").json()["token"]

    r = client.post(f"{API}/auth/change-password", headers=_hdr(token),
                    json={"old_password": "Dave-Passw0rd!2026",
                          "new_password": "short1!"})
    assert r.status_code == 400
    assert "至少 12 位" in r.json()["detail"]
    # 失败不换代次：当前会话还能用
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).status_code == 200


def test_legacy_120k_hash_still_works_and_is_upgraded(db, client):
    """存量 120k 纯 hex 哈希必须能在登录时验证并透明升级到 600k。"""
    salt = "legacysalt123456"
    legacy = hashlib.pbkdf2_hmac(
        "sha256", b"Legacy-Passw0rd!2026", salt.encode(), 120_000).hex()
    u = User(id=new_id(), username="legacy", display_name="legacy",
             clearance=1, roles="[]", pwd_hash=legacy, salt=salt, status=True)
    db.add(u)
    db.commit()

    login = _login(client, "legacy", "Legacy-Passw0rd!2026")
    assert login.status_code == 200

    db.expire_all()
    stored = db.get(User, u.id).pwd_hash
    assert stored.startswith("pbkdf2_sha256$600000$"), stored
    # 升级后仍能用同一口令登录
    assert _login(client, "legacy", "Legacy-Passw0rd!2026").status_code == 200


def test_demo_account_without_flag_is_not_blocked(db, client):
    """演示/既有账号（must_change_password=false）不被强制改密挡住。"""
    _mk_user(db, "demo01", "Admin@123", clearance=3, roles=["admin"],
             must_change=False)
    r = _login(client, "demo01", "Admin@123")
    assert r.status_code == 200
    assert r.json()["must_change_password"] is False
    assert client.get(f"{API}/docs", headers=_hdr(r.json()["token"])).status_code == 200


def test_admin_password_reset_forces_change_and_kills_sessions(db, client):
    """管理员重置口令 = 他知道新口令 → 本人下次登录必须改，且旧会话立刻失效。"""
    admin = _admin(db, "root2")
    victim = _mk_user(db, "erin", "Erin-Passw0rd!2026")
    victim_token = _login(client, "erin", "Erin-Passw0rd!2026").json()["token"]

    admin_token = _login(client, "root2", "Adm1n-Passw0rd!2026").json()["token"]
    r = client.patch(f"{API}/admin/users/{victim.id}", headers=_hdr(admin_token),
                     json={"username": "erin", "password": "Reset-Passw0rd!2026",
                           "clearance": 1, "roles": []})
    assert r.status_code == 200
    assert r.json()["must_change_password"] is True

    # 旧会话被踢下线
    assert client.get(f"{API}/auth/me", headers=_hdr(victim_token)).status_code == 401
    login = _login(client, "erin", "Reset-Passw0rd!2026")
    assert login.status_code == 200
    assert login.json()["must_change_password"] is True
    assert client.get(f"{API}/docs",
                      headers=_hdr(login.json()["token"])).status_code == 403


def test_disabled_user_token_rejected(db, client):
    _mk_user(db, "frank", "Frank-Passw0rd!2026")
    token = _login(client, "frank", "Frank-Passw0rd!2026").json()["token"]
    u = db.query(User).filter(User.username == "frank").one()
    u.status = False
    db.commit()
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).status_code == 401
