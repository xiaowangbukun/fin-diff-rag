# SPDX-License-Identifier: Apache-2.0
"""闭环项 3 · S3：TOTP 双因子登录 + OIDC 单点登录（双适配）。

覆盖口径：
  · 已绑定账号登录必须两步（口令只换到挑战票据，拿不到访问令牌）；
  · 挑战票据、OIDC 交接票据都不能当访问令牌（用途隔离）；
  · 绑定/解绑都要求口令再验（防"偷到会话就换/关第二因子"）；
  · 重放同一动态口令失败；错码计入账号级锁定；
  · 强制绑定闸门（MFA_ENFORCE_ADMIN / ALL）在服务端生效；
  · OIDC 回调的 state/cookie 绑定、id_token 校验（iss/aud/nonce/alg）、
    账号映射与即时建号开关、审计留痕。

OIDC 部分不连真实 IdP：用 RSA 密钥自签 id_token，monkeypatch 掉
discovery/jwks 与 token 交换，协议路径（state、PKCE 传递、验签、映射）
仍然逐行执行。
"""
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import config, oidc, totp
from app.main import app as real_app
from app.models import User, new_id
from app.routers.auth import OIDC_HANDOFF_COOKIE, OIDC_STATE_COOKIE
from app.security import hash_password

API = "/api/v1"
PWD = "Str0ng-Passw0rd!2026"


@pytest.fixture
def client():
    return TestClient(real_app)


@pytest.fixture(autouse=True)
def _reset_throttle():
    """登录/动态口令失败计数是进程级状态，跨用例会互相污染。

    本文件有专门的"锁定"与"重放"用例，会把 username 打满阈值；
    不清零的话后续用例全都会撞上 429（`_isolate_between_tests` 只管
    DB 与部门缓存，不碰 throttle）。
    """
    from app import loginthrottle
    loginthrottle.reset()
    yield
    loginthrottle.reset()


def _mk_user(db, username="alice", password=PWD, clearance=1, roles=None,
             enrolled=False, oidc_subject=""):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles or []),
             pwd_hash=pwd_hash, salt=salt, status=True,
             must_change_password=False, token_version=0,
             oidc_subject=oidc_subject)
    if enrolled:
        u.totp_secret = totp.seal(totp.generate_secret())
        u.totp_confirmed_at = datetime.utcnow()
    db.add(u)
    db.commit()
    return u


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


def _login(client, username="alice", password=PWD):
    return client.post(f"{API}/auth/login",
                       json={"username": username, "password": password})


# ---------------------------------------------------------------- 能力探测

def test_providers_reports_capabilities_without_config_leak(client):
    r = client.get(f"{API}/auth/providers")
    assert r.status_code == 200
    body = r.json()
    assert body["password"] is True
    assert body["mfa"]["digits"] == config.TOTP_DIGITS
    # 不泄漏 issuer/client_id/secret 等配置细节
    assert "client_id" not in json.dumps(body)
    assert "secret" not in json.dumps(body)


# ---------------------------------------------------------------- 两步登录

def test_enrolled_user_login_requires_second_factor(db, client):
    u = _mk_user(db, enrolled=True)
    step1 = _login(client)
    assert step1.status_code == 200
    body = step1.json()
    # 关键：口令对了也不给会话令牌，只给 5 分钟的挑战票据
    assert body["mfa_required"] is True
    assert "token" not in body
    assert body["expires_in"] == config.MFA_CHALLENGE_MINUTES * 60

    # 挑战票据不能当访问令牌：它不是 access（typ=mfa）
    assert client.get(f"{API}/docs", headers=_hdr(body["challenge"])).status_code == 401

    secret = totp.unseal(u.totp_secret)
    step2 = client.post(f"{API}/auth/login/mfa",
                        json={"challenge": body["challenge"],
                              "code": totp.code_at(secret)})
    assert step2.status_code == 200
    assert step2.json()["token"]
    ok = client.get(f"{API}/docs", headers=_hdr(step2.json()["token"]))
    assert ok.status_code == 200


def test_wrong_code_rejected_and_step_not_consumed(db, client):
    u = _mk_user(db, enrolled=True)
    challenge = _login(client).json()["challenge"]
    bad = client.post(f"{API}/auth/login/mfa",
                      json={"challenge": challenge, "code": "000000"})
    assert bad.status_code == 401
    secret = totp.unseal(u.totp_secret)
    good = client.post(f"{API}/auth/login/mfa",
                       json={"challenge": challenge, "code": totp.code_at(secret)})
    assert good.status_code == 200


def test_code_replay_within_window_is_rejected(db, client):
    u = _mk_user(db, enrolled=True)
    secret = totp.unseal(u.totp_secret)
    code = totp.code_at(secret)
    c1 = _login(client).json()["challenge"]
    assert client.post(f"{API}/auth/login/mfa",
                       json={"challenge": c1, "code": code}).status_code == 200
    # 同一口令第二次用（新挑战票据也一样）必须失败：一次性凭证不能重放
    c2 = _login(client).json()["challenge"]
    assert client.post(f"{API}/auth/login/mfa",
                       json={"challenge": c2, "code": code}).status_code == 401


def test_unenrolled_user_logs_in_with_password_only(db, client):
    _mk_user(db)
    body = _login(client).json()
    assert body.get("mfa_required") is not True
    assert client.get(f"{API}/docs", headers=_hdr(body["token"])).status_code == 200


def test_mfa_off_means_single_factor(db, client, monkeypatch):
    _mk_user(db, enrolled=True)
    monkeypatch.setattr(config, "MFA_ENABLED", False)
    body = _login(client).json()
    assert body.get("mfa_required") is not True
    assert body["token"]


def test_invalid_challenge_token_rejected(db, client):
    _mk_user(db, enrolled=True)
    assert client.post(f"{API}/auth/login/mfa",
                       json={"challenge": "this-is-not-a-jwt-at-all", "code": "123456"}
                       ).status_code == 401


def test_mfa_lockout_after_repeated_wrong_codes(db, client):
    _mk_user(db, enrolled=True)
    challenge = _login(client).json()["challenge"]
    for _ in range(5):
        client.post(f"{API}/auth/login/mfa",
                    json={"challenge": challenge, "code": "000000"})
    r = client.post(f"{API}/auth/login/mfa",
                    json={"challenge": challenge, "code": "000000"})
    assert r.status_code == 429
    assert r.headers.get("Retry-After")


# ---------------------------------------------------------------- 绑定/解绑

def test_setup_requires_password_and_seals_secret(db, client):
    u = _mk_user(db)
    token = _login(client).json()["token"]
    wrong = client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                        json={"password": "Wr0ng-Passw0rd!"})
    assert wrong.status_code == 401

    ok = client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                     json={"password": PWD})
    assert ok.status_code == 200
    body = ok.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    db.expire_all()
    stored = db.get(User, u.id).totp_secret
    # 密钥必须密文入库，不能与响应里的明文相同
    assert stored.startswith("enc:v1:")
    assert body["secret"] not in stored
    # 未验码前不算绑定
    assert db.get(User, u.id).totp_confirmed_at is None


def test_confirm_marks_enrolled_and_then_login_needs_two_steps(db, client):
    u = _mk_user(db)
    token = _login(client).json()["token"]
    setup = client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                        json={"password": PWD}).json()
    bad = client.post(f"{API}/auth/totp/confirm", headers=_hdr(token),
                      json={"code": "000000"})
    assert bad.status_code == 400
    ok = client.post(f"{API}/auth/totp/confirm", headers=_hdr(token),
                     json={"code": totp.code_at(setup["secret"])})
    assert ok.status_code == 200
    assert ok.json()["mfa_enabled"] is True
    db.expire_all()
    assert db.get(User, u.id).totp_confirmed_at is not None
    assert _login(client).json()["mfa_required"] is True


def test_confirm_without_setup_rejected(db, client):
    _mk_user(db)
    token = _login(client).json()["token"]
    r = client.post(f"{API}/auth/totp/confirm", headers=_hdr(token),
                    json={"code": "123456"})
    assert r.status_code == 400


def test_disable_requires_password(db, client):
    _mk_user(db, enrolled=True)
    challenge = _login(client).json()["challenge"]
    secret = totp.unseal(db.query(User).one().totp_secret)
    token = client.post(f"{API}/auth/login/mfa",
                        json={"challenge": challenge,
                              "code": totp.code_at(secret)}).json()["token"]
    assert client.post(f"{API}/auth/totp/disable", headers=_hdr(token),
                       json={"password": "nope"}).status_code == 401
    ok = client.post(f"{API}/auth/totp/disable", headers=_hdr(token),
                     json={"password": PWD})
    assert ok.status_code == 200
    assert ok.json()["mfa_enabled"] is False


def test_challenge_token_cannot_bind_totp(db, client):
    _mk_user(db, enrolled=True)
    challenge = _login(client).json()["challenge"]
    # 未完成的挑战票据不是会话：绑定接口走 current_user，必须 401
    r = client.post(f"{API}/auth/totp/setup", headers=_hdr(challenge),
                    json={"password": PWD})
    assert r.status_code == 401


# ---------------------------------------------------------------- 强制绑定闸门

def test_enforce_admin_blocks_unenrolled_admin(db, client, monkeypatch):
    monkeypatch.setattr(config, "MFA_ENFORCE_ADMIN", True)
    _mk_user(db, username="boss", roles=["admin"], clearance=3)
    token = _login(client, "boss").json()["token"]
    blocked = client.get(f"{API}/docs", headers=_hdr(token))
    assert blocked.status_code == 403
    assert blocked.headers.get("X-MFA-Setup-Required") == "1"
    # 绑定相关接口必须放行，否则用户被永久卡死
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).status_code == 200
    assert client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                       json={"password": PWD}).status_code == 200


def test_enforce_all_applies_to_non_admin(db, client, monkeypatch):
    monkeypatch.setattr(config, "MFA_ENFORCE_ALL", True)
    _mk_user(db, username="clerk", roles=["research"])
    token = _login(client, "clerk").json()["token"]
    assert client.get(f"{API}/docs", headers=_hdr(token)).status_code == 403


def test_enforce_does_not_apply_when_mfa_disabled(db, client, monkeypatch):
    monkeypatch.setattr(config, "MFA_ENFORCE_ALL", True)
    monkeypatch.setattr(config, "MFA_ENABLED", False)
    _mk_user(db, username="clerk2", roles=["research"])
    token = _login(client, "clerk2").json()["token"]
    assert client.get(f"{API}/docs", headers=_hdr(token)).status_code == 200


def test_admin_reset_mfa_clears_secret_and_kills_sessions(db, client):
    admin = _mk_user(db, username="root", roles=["admin"], clearance=3,
                     password="Adm1n-Passw0rd!2026")
    victim = _mk_user(db, username="bob", enrolled=True)
    admin_token = _login(client, "root", "Adm1n-Passw0rd!2026").json()["token"]
    r = client.post(f"{API}/admin/users/{victim.id}/mfa-reset",
                    headers=_hdr(admin_token))
    assert r.status_code == 200
    assert r.json()["was_enrolled"] is True
    db.expire_all()
    v = db.get(User, victim.id)
    assert v.totp_secret == "" and v.totp_confirmed_at is None
    # 重置同时换会话代次：旧令牌立即失效
    assert int(v.token_version) >= 1
    # 重置后仅口令即可登录（不再要求第二因子）
    assert _login(client, "bob").json().get("mfa_required") is not True


# ---------------------------------------------------------------- OIDC

@pytest.fixture
def idp(monkeypatch):
    """本机假 IdP：RSA 密钥 + 固定 discovery/jwks + token 交换桩。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub))
    jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})

    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", "finrag-client")
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", "s3cr3t")
    monkeypatch.setattr(config, "OIDC_REDIRECT_URI",
                        "https://rag.example.com/api/auth/oidc/callback")
    monkeypatch.setattr(config, "OIDC_USERNAME_CLAIM", "preferred_username")
    oidc.clear_cache()

    doc = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
    }
    monkeypatch.setattr(oidc, "discovery", lambda: doc)
    monkeypatch.setattr(oidc, "jwks", lambda: [jwk])

    captured: dict = {}

    def _fake_exchange(code, verifier, uri):
        captured["code"] = code
        captured["verifier"] = verifier
        captured["uri"] = uri
        # 用例若已通过 captured["id_token"] 预置（含负向用例的坏令牌），
        # 就以预置为准；否则按默认 claims 现签一个（happy path）。
        token = captured.get("id_token") or _make_id_token(key)
        captured["id_token"] = token
        return {"id_token": token, "access_token": "at"}

    def _make_id_token(sign_key=None, **overrides):
        now = datetime.now(timezone.utc)
        claims = {
            "iss": "https://idp.example.com",
            "aud": "finrag-client",
            "sub": "idp-user-0001",
            "preferred_username": "alice",
            "name": "Alice A",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "nonce": captured.get("nonce", ""),
        }
        claims.update(overrides)
        return jwt.encode(claims, sign_key or key, algorithm="RS256",
                          headers={"kid": "test-key"})

    monkeypatch.setattr(oidc, "exchange_code", _fake_exchange)
    yield {"key": key, "captured": captured, "make": _make_id_token,
           "set_nonce": lambda n: captured.__setitem__("nonce", n)}
    oidc.clear_cache()


def _start_sso(client):
    """走 /oidc/start，拿到 state（cookie）与授权 URL 里的 nonce/code_challenge。"""
    r = client.get(f"{API}/auth/oidc/start", follow_redirects=False)
    assert r.status_code == 302
    state = r.cookies.get(OIDC_STATE_COOKIE)
    assert state
    from urllib.parse import parse_qs, urlparse
    qs = parse_qs(urlparse(r.headers["location"]).query)
    return state, qs


def _callback(client, state, idp, **claim_overrides):
    idp["set_nonce"](jwt.decode(state, options={"verify_signature": False})["nonce"])
    idp["captured"]["id_token"] = idp["make"](**claim_overrides)
    return client.get(f"{API}/auth/oidc/callback",
                      params={"code": "authcode", "state": state},
                      follow_redirects=False)


def test_oidc_start_redirects_with_pkce_and_binds_state_cookie(client, idp):
    state, qs = _start_sso(client)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == ["finrag-client"]
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["code_challenge"][0]
    # state 里存 verifier/nonce，但不该出现 client_secret
    claims = jwt.decode(state, options={"verify_signature": False})
    assert claims["typ"] == "oidc_state" and claims["verifier"]
    assert "s3cr3t" not in json.dumps(claims)


def test_oidc_callback_rejects_state_without_cookie(client, idp):
    state, _ = _start_sso(client)
    client.cookies.clear()   # 模拟登录 CSRF：攻击者构造回调但拿不到受害者 cookie
    r = client.get(f"{API}/auth/oidc/callback",
                   params={"code": "authcode", "state": state},
                   follow_redirects=False)
    assert r.status_code == 302
    assert "sso_error=state_mismatch" in r.headers["location"]


def test_oidc_callback_rejects_mismatched_state(client, idp):
    _start_sso(client)
    r = client.get(f"{API}/auth/oidc/callback",
                   params={"code": "authcode", "state": "forged"},
                   follow_redirects=False)
    assert "sso_error=state_mismatch" in r.headers["location"]


def test_oidc_callback_rejects_bad_nonce(client, idp, db):
    _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    idp["set_nonce"]("totally-different")
    idp["captured"]["id_token"] = idp["make"]()
    r = client.get(f"{API}/auth/oidc/callback",
                   params={"code": "authcode", "state": state},
                   follow_redirects=False)
    assert "sso_error=id_token_invalid" in r.headers["location"]


def test_oidc_callback_rejects_wrong_audience(client, idp, db):
    _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    idp["set_nonce"](jwt.decode(state, options={"verify_signature": False})["nonce"])
    idp["captured"]["id_token"] = idp["make"](aud="someone-else")
    r = client.get(f"{API}/auth/oidc/callback",
                   params={"code": "authcode", "state": state},
                   follow_redirects=False)
    assert "sso_error=id_token_invalid" in r.headers["location"]


def test_oidc_callback_rejects_hs256_algorithm_confusion(client, idp, db):
    """算法混淆：用 client_secret 当 HMAC 密钥签 HS256 必须被拒。"""
    _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    nonce = jwt.decode(state, options={"verify_signature": False})["nonce"]
    forged = jwt.encode({"iss": "https://idp.example.com", "aud": "finrag-client",
                         "sub": "idp-user-0001", "nonce": nonce,
                         "preferred_username": "alice",
                         "iat": datetime.now(timezone.utc),
                         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
                        "s3cr3t", algorithm="HS256")
    idp["captured"]["id_token"] = forged
    r = client.get(f"{API}/auth/oidc/callback",
                   params={"code": "authcode", "state": state},
                   follow_redirects=False)
    assert "sso_error=id_token_invalid" in r.headers["location"]


def test_oidc_happy_path_issues_handoff_and_session(client, idp, db):
    u = _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    r = _callback(client, state, idp)
    assert r.status_code == 302
    assert r.headers["location"].endswith("/#/sso")
    handoff = r.cookies.get(OIDC_HANDOFF_COOKIE)
    assert handoff
    # 交接票据同样不能当访问令牌（typ=sso_handoff）
    assert client.get(f"{API}/docs", headers=_hdr(handoff)).status_code == 401

    sess = client.post(f"{API}/auth/oidc/session")
    assert sess.status_code == 200
    token = sess.json()["token"]
    assert client.get(f"{API}/docs", headers=_hdr(token)).status_code == 200
    db.expire_all()
    # 首次 SSO 登录把 sub 绑到本地账号，后续按 sub 匹配
    assert db.get(User, u.id).oidc_subject == "idp-user-0001"


def test_oidc_session_without_cookie_rejected(client, idp):
    assert client.post(f"{API}/auth/oidc/session").status_code == 401


def test_oidc_unknown_user_not_provisioned_by_default(client, idp, db):
    _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    r = _callback(client, state, idp, preferred_username="stranger",
                  sub="idp-stranger")
    assert "sso_error=account_not_provisioned" in r.headers["location"]


def test_oidc_jit_provision_creates_user_with_defaults(client, idp, db,
                                                       monkeypatch):
    monkeypatch.setattr(config, "OIDC_JIT_PROVISION", True)
    monkeypatch.setattr(config, "OIDC_DEFAULT_CLEARANCE", 1)
    monkeypatch.setattr(config, "OIDC_DEFAULT_ROLES", "research")
    state, _ = _start_sso(client)
    r = _callback(client, state, idp, preferred_username="newhire",
                  sub="idp-newhire")
    assert r.headers["location"].endswith("/#/sso")
    created = db.query(User).filter(User.username == "newhire").one()
    assert created.clearance == 1
    assert created.role_list() == ["research"]
    # SSO 建号没有本地口令，不能走口令登录
    assert _login(client, "newhire", "").status_code in (401, 422)


def test_oidc_disabled_user_rejected(client, idp, db):
    u = _mk_user(db, username="alice")
    u.status = False
    db.commit()
    state, _ = _start_sso(client)
    r = _callback(client, state, idp)
    assert "sso_error=user_disabled" in r.headers["location"]


def test_oidc_subject_conflict_rejected(client, idp, db):
    _mk_user(db, username="alice", oidc_subject="someone-else")
    state, _ = _start_sso(client)
    r = _callback(client, state, idp)
    assert "sso_error=subject_conflict" in r.headers["location"]


def test_oidc_endpoints_404_when_disabled(client, monkeypatch):
    monkeypatch.setattr(config, "OIDC_ENABLED", False)
    assert client.get(f"{API}/auth/oidc/start",
                      follow_redirects=False).status_code == 404
    assert client.get(f"{API}/auth/oidc/callback",
                      follow_redirects=False).status_code == 404


def test_oidc_require_config_refuses_half_config(monkeypatch):
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", "")
    with pytest.raises(RuntimeError):
        oidc.require_config()


def test_trusted_idp_mfa_skips_local_totp_enforcement(db, monkeypatch):
    """SSO 账号且信任 IdP 做 MFA 时，不再要求本地绑定 TOTP。"""
    monkeypatch.setattr(config, "MFA_ENFORCE_ALL", True)
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    u = _mk_user(db, username="sso-user", roles=["admin"], oidc_subject="sub-1")
    from app.security import mfa_setup_required
    assert mfa_setup_required(u) is False
    monkeypatch.setattr(config, "OIDC_TRUST_IDP_MFA", False)
    assert mfa_setup_required(u) is True


def test_oidc_failure_is_audited(db, client, idp):
    _mk_user(db, username="alice")
    state, _ = _start_sso(client)
    _callback(client, state, idp, preferred_username="ghost", sub="idp-ghost")
    from app.audit import flush_audit
    from app.models import AuditLog
    flush_audit()
    rows = db.query(AuditLog).filter(AuditLog.action.in_(["login_sso", "mfa_setup"])).all()
    sso = [r for r in rows if r.action == "login_sso"]
    assert sso and any(r.decision == "deny" for r in sso)
