# SPDX-License-Identifier: AGPL-3.0-only
"""会话生命周期（P0-4）：空闲超时、单端吊销、全端吊销、Cookie + CSRF。

威胁模型（纯 JWT 的固有缺口）：
  · 令牌签发后 12 小时内，离开工位 / 笔记本被拿走 → 会话一直有效；
  · "退出登录"只是前端删掉 localStorage，服务端毫不知情，旧令牌照样能用；
  · 令牌存在 localStorage 时，任何 XSS 都能把它带走。

本文件钉住：服务端会话表是事实来源（sid 进令牌），吊销/超时即 401；
Cookie 模式下令牌不可被 JS 读取，写操作必须带双提交 CSRF 头。
"""
import json
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import config, security
from app.main import app as real_app
from app.models import AuthSession, User, new_id
from app.security import hash_password

API = "/api/v1"
STRONG = "Str0ng-Passw0rd!2026"


@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username="sess-user", password="Adm1n-Passw0rd!2026",
             clearance=1, roles=None, token_version=0):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles or []),
             pwd_hash=pwd_hash, salt=salt, status=True,
             token_version=token_version)
    db.add(u)
    db.commit()
    return u


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- 纯单元


def test_open_session_registers_row(db, user_factory):
    u = user_factory("alice")
    db.flush()
    sess = security.open_session(db, u, ip="10.0.0.8", ua="pytest/1.0")

    row = db.get(AuthSession, sess.sid)
    assert row is not None
    assert row.user_id == u.id and row.username == "alice"
    assert row.revoked_at is None
    assert row.ip == "10.0.0.8" and row.user_agent == "pytest/1.0"
    # 会话表只存元数据，不存令牌本身（DB 泄露不等于拿到可用凭据）
    assert not hasattr(row, "token")


def test_check_session_passes_and_touches(db, user_factory):
    u = user_factory("alice")
    db.flush()
    sess = security.open_session(db, u)
    assert security.check_session(db, {"sid": sess.sid}, None) == sess.sid


def test_token_without_sid_is_compatible(db, user_factory):
    """历史令牌（无 sid）不一次性踢光；返回 None 表示"无服务端会话"。"""
    u = user_factory("alice")
    db.flush()
    assert security.check_session(db, {}, None) is None


def test_revoked_session_is_rejected(db, user_factory):
    u = user_factory("alice")
    db.flush()
    sess = security.open_session(db, u)
    assert security.revoke_session(db, sess.sid, reason="logout") is True
    assert security.revoke_session(db, sess.sid) is False   # 幂等

    with pytest.raises(HTTPException) as exc:
        security.check_session(db, {"sid": sess.sid}, None)
    assert exc.value.status_code == 401
    assert "会话已失效" in exc.value.detail


def test_idle_timeout_revokes_and_reports(db, user_factory, monkeypatch):
    monkeypatch.setattr(config, "SESSION_IDLE_MINUTES", 30)
    u = user_factory("alice")
    db.flush()
    sess = security.open_session(db, u)
    row = db.get(AuthSession, sess.sid)
    row.last_seen_at = datetime.utcnow() - timedelta(minutes=31)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        security.check_session(db, {"sid": sess.sid}, None)
    assert exc.value.status_code == 401
    assert "长时间未操作" in exc.value.detail
    # 超时判定要落库（否则每次请求都要重算，且运维看不到"为什么掉线"）
    assert db.get(AuthSession, sess.sid).revoked_reason == "idle_timeout"


def test_idle_timeout_disabled_by_zero(db, user_factory, monkeypatch):
    monkeypatch.setattr(config, "SESSION_IDLE_MINUTES", 0)
    u = user_factory("alice")
    db.flush()
    sess = security.open_session(db, u)
    row = db.get(AuthSession, sess.sid)
    row.last_seen_at = datetime.utcnow() - timedelta(days=30)
    db.commit()
    assert security.check_session(db, {"sid": sess.sid}, None) == sess.sid


def test_revoke_user_sessions_keeps_current_sid(db, user_factory):
    u = user_factory("alice")
    db.flush()
    keep = security.open_session(db, u)
    other = security.open_session(db, u)

    n = security.revoke_user_sessions(db, u.id, reason="password_change",
                                     keep_sid=keep.sid)
    assert n == 1
    assert db.get(AuthSession, keep.sid).revoked_at is None
    assert db.get(AuthSession, other.sid).revoked_reason == "password_change"


def test_active_sessions_hides_revoked_and_idle(db, user_factory, monkeypatch):
    monkeypatch.setattr(config, "SESSION_IDLE_MINUTES", 30)
    u = user_factory("alice")
    db.flush()
    fresh = security.open_session(db, u)
    stale = security.open_session(db, u)
    dead = security.open_session(db, u)
    db.get(AuthSession, stale.sid).last_seen_at = (
        datetime.utcnow() - timedelta(hours=2))
    db.commit()
    security.revoke_session(db, dead.sid, reason="user_revoked")

    ids = [s.sid for s in security.active_sessions(db, u)]
    assert ids == [fresh.sid]


# ---------------------------------------------------------------- HTTP：bearer 模式


def test_login_token_carries_sid_and_logout_revokes_only_one(client, db):
    u = _mk_user(db)
    first = client.post(f"{API}/auth/login",
                        json={"username": "sess-user",
                              "password": "Adm1n-Passw0rd!2026"}).json()
    second = client.post(f"{API}/auth/login",
                         json={"username": "sess-user",
                               "password": "Adm1n-Passw0rd!2026"}).json()
    assert first["token"] and second["token"]
    assert first["session_id"] and second["session_id"]

    # 两台设备都在线
    assert client.get(f"{API}/auth/sessions",
                      headers=_hdr(first["token"])).status_code == 200

    assert client.post(f"{API}/auth/logout",
                       headers=_hdr(first["token"])).status_code == 200
    # 登出的那台失效，另一台不受影响（单端语义）
    assert client.get(f"{API}/auth/me",
                      headers=_hdr(first["token"])).status_code == 401
    assert client.get(f"{API}/auth/me",
                      headers=_hdr(second["token"])).status_code == 200


def test_admin_can_kick_user_sessions(client, db):
    admin = _mk_user(db, "root", "Adm1n-Passw0rd!2026", clearance=3,
                     roles=["admin"])
    victim = _mk_user(db, "victim", "Adm1n-Passw0rd!2026")
    at = client.post(f"{API}/auth/login", json={
        "username": "root", "password": "Adm1n-Passw0rd!2026"}).json()["token"]
    vt = client.post(f"{API}/auth/login", json={
        "username": "victim", "password": "Adm1n-Passw0rd!2026"}).json()["token"]

    kicked = client.post(f"{API}/admin/users/{victim.id}/revoke-sessions",
                         headers=_hdr(at))
    assert kicked.status_code == 200 and kicked.json()["revoked"] == 1
    assert client.get(f"{API}/auth/me", headers=_hdr(vt)).status_code == 401
    # 管理员自己不能被这个接口踢（防误点自断）
    me = client.get(f"{API}/auth/me", headers=_hdr(at)).json()
    self_kick = client.post(f"{API}/admin/users/{me['id']}/revoke-sessions",
                            headers=_hdr(at))
    assert self_kick.status_code == 400


def test_logout_all_bumps_token_version(client, db):
    u = _mk_user(db)
    tok = client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"}).json()["token"]

    assert client.post(f"{API}/auth/logout/all",
                       headers=_hdr(tok)).status_code == 200
    # 换代次：即使会话行被清掉，旧令牌也因 ver 不符而 401
    db.expire_all()
    assert db.get(User, u.id).token_version == 1
    assert client.get(f"{API}/auth/me", headers=_hdr(tok)).status_code == 401


# ---------------------------------------------------------------- HTTP：Cookie 模式


@pytest.fixture
def cookie_mode(monkeypatch):
    monkeypatch.setattr(config, "AUTH_COOKIE_MODE", True)
    monkeypatch.setattr(config, "AUTH_COOKIE_SECURE", "auto")
    yield
    monkeypatch.setattr(config, "AUTH_COOKIE_MODE", False)


def test_cookie_login_sets_httponly_and_csrf(client, db, cookie_mode):
    _mk_user(db)
    res = client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    assert res.status_code == 200
    body = res.json()
    # 令牌不进响应体：JS 拿不到，只能靠 HttpOnly Cookie
    assert body["token"] is None and body["csrf_required"] is True
    assert res.headers.get("X-CSRF-Token")

    cookie_names = {c.name for c in client.cookies.jar}
    assert config.AUTH_COOKIE_NAME in cookie_names
    assert config.CSRF_COOKIE_NAME in cookie_names
    raw = res.headers.get_list("set-cookie")
    session_cookie = [c for c in raw if c.startswith(config.AUTH_COOKIE_NAME)][0]
    assert "HttpOnly" in session_cookie
    assert "SameSite=lax" in session_cookie.replace("samesite=lax", "SameSite=lax")


def test_cookie_session_reads_work_without_header(client, db, cookie_mode):
    _mk_user(db)
    client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    # TestClient 自动带 Cookie：GET 不需要 CSRF
    assert client.get(f"{API}/auth/me").status_code == 200


def test_cookie_write_without_csrf_is_403(client, db, cookie_mode):
    _mk_user(db)
    client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    blocked = client.post(f"{API}/auth/logout")
    assert blocked.status_code == 403
    assert "CSRF" in blocked.json()["detail"]


def test_cookie_write_with_csrf_header_succeeds(client, db, cookie_mode):
    _mk_user(db)
    client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    csrf = client.cookies.get(config.CSRF_COOKIE_NAME)
    ok = client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200
    assert client.get(f"{API}/auth/me").status_code == 401


def test_cookie_write_with_wrong_csrf_is_403(client, db, cookie_mode):
    _mk_user(db)
    client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    bad = client.post(f"{API}/auth/logout",
                      headers={"X-CSRF-Token": "forged-value"})
    assert bad.status_code == 403


def test_cookie_gets_secure_flag_behind_tls_terminating_proxy(
        client, db, cookie_mode, monkeypatch):
    """反代终止 TLS 时会话 Cookie 必须仍带 Secure。

    典型金融部署：TLS 在 Nginx/F5 终止，应用只监听内网明文口。此时
    request.url.scheme 是 http，只看它会让 Secure 漏发——Cookie 可能随
    一次明文请求回传，浏览器也不会拦。必须认反代传入的 X-Forwarded-Proto。
    """
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    _mk_user(db)
    res = client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"},
        headers={"X-Forwarded-Proto": "https"})
    assert res.status_code == 200
    cookie = [c for c in res.headers.get_list("set-cookie")
              if c.startswith(config.AUTH_COOKIE_NAME)][0]
    assert "Secure" in cookie


def test_cookie_has_no_secure_flag_when_forwarded_header_untrusted(
        client, db, cookie_mode, monkeypatch):
    """不信任转发头时，伪造 X-Forwarded-Proto 不能把 Cookie 抬成 Secure。

    Secure 只影响"浏览器是否在明文连接上回传"，伪造它没有安全收益，但口径
    必须可预测：判定来源只允许是 TRUST_PROXY_HEADERS 开关。
    """
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", False)
    _mk_user(db)
    res = client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"},
        headers={"X-Forwarded-Proto": "https"})
    assert res.status_code == 200
    cookie = [c for c in res.headers.get_list("set-cookie")
              if c.startswith(config.AUTH_COOKIE_NAME)][0]
    assert "Secure" not in cookie


def test_cookie_mode_logout_clears_cookies(client, db, cookie_mode):
    _mk_user(db)
    client.post(f"{API}/auth/login", json={
        "username": "sess-user", "password": "Adm1n-Passw0rd!2026"})
    csrf = client.cookies.get(config.CSRF_COOKIE_NAME)
    res = client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf})
    set_cookie = " ".join(res.headers.get_list("set-cookie"))
    assert config.AUTH_COOKIE_NAME in set_cookie
    # 清 Cookie 用 Max-Age=0 / expires 过去时间
    assert "Max-Age=0" in set_cookie or "expires=" in set_cookie.lower()
