# SPDX-License-Identifier: AGPL-3.0-only
"""OIDC 对接的**真实 HTTP** 集成测试（不打桩协议函数）。

与 test_mfa_auth.py 的分工：
  · test_mfa_auth 用假 discovery/jwks/exchange_code 覆盖校验分支（快、准）；
  · 本文件起一个真的 HTTP OIDC Provider（tests/idp_stub.py），让被测代码
    自己发 HTTP 请求去拉发现文档、JWKS、换 token——任何"参数名拼错、
    issuer 少个斜杠、PKCE 传递错位、表单编码不对"的问题只有真联调才暴露。

覆盖口径：
  · 完整授权码 + PKCE 流程（授权页 → 登录表单 → 回调 → 交接票据 → 会话）；
  · 断言 IdP 侧 hits 计数，证明网络 I/O 真的发生了（不是内存里过的）；
  · 负向：discovery issuer 不符、nonce 被篡改、PKCE 被拒、授权码重放、
    IdP 侧口令错误、本地账号不存在（JIT 关）、账号停用、IdP 不可达。
"""
import json
import re
import urllib.parse

import httpx
import pytest
from fastapi.testclient import TestClient

from app import config, oidc
from app.main import app as real_app
from app.models import User, new_id
from app.routers.auth import OIDC_HANDOFF_COOKIE
from app.security import hash_password

from idp_stub import StubIdp

API = "/api/v1"
PWD = "Str0ng-Passw0rd!2026"
# 与 IdP 侧登记一致的绝对回调地址：TestClient 的 base_url 是 http://testserver
REDIRECT_URI = "http://testserver/api/v1/auth/oidc/callback"


@pytest.fixture
def client():
    return TestClient(real_app)


@pytest.fixture
def idp(monkeypatch):
    """起真实 HTTP Provider，并把 app 配置指过去（端点全部走真实网络）。"""
    stub = StubIdp().start()
    monkeypatch.setattr(config, "OIDC_ENABLED", True)
    monkeypatch.setattr(config, "OIDC_ISSUER", stub.issuer)
    monkeypatch.setattr(config, "OIDC_CLIENT_ID", stub.client_id)
    monkeypatch.setattr(config, "OIDC_CLIENT_SECRET", stub.client_secret)
    monkeypatch.setattr(config, "OIDC_REDIRECT_URI", REDIRECT_URI)
    monkeypatch.setattr(config, "OIDC_USERNAME_CLAIM", "preferred_username")
    monkeypatch.setattr(config, "OIDC_HTTP_TIMEOUT", 5)
    oidc.clear_cache()
    try:
        yield stub
    finally:
        stub.stop()
        oidc.clear_cache()


def _mk_user(db, username="alice", password=PWD, clearance=1, roles=None):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles or []),
             pwd_hash=pwd_hash, salt=salt, status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.commit()
    return u


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- 浏览器动作

def _start(client):
    """第一步：调 /oidc/start，拿到 state（cookie）与 IdP 授权 URL。"""
    r = client.get(f"{API}/auth/oidc/start", follow_redirects=False)
    assert r.status_code == 302, r.text
    state = r.cookies.get("finrag_oidc_state")
    assert state, "state 必须同时写进 HttpOnly cookie"
    return state, r.headers["location"]


def _authorize(stub, authorize_url, username="alice", password=None):
    """用真 HTTP 客户端扮演浏览器：GET 授权页 → POST 登录表单。"""
    with httpx.Client(follow_redirects=False, timeout=5, trust_env=False) as browser:
        page = browser.get(authorize_url)
        assert page.status_code == 200, page.text
        rid = re.search(r'name="rid" value="([^"]+)"', page.text)
        assert rid, f"授权页应带 rid 隐藏字段：{page.text[:200]}"
        assert 'name="username"' in page.text and 'name="password"' in page.text
        return browser.post(
            stub.issuer + "/authorize/login",
            data={"rid": rid.group(1), "username": username,
                  "password": stub.password if password is None else password},
        )


def _callback(client, stub, username="alice", password=None):
    """跑完整浏览器流程，返回 (回调响应, 授权码)。"""
    state, url = _start(client)
    submit = _authorize(stub, url, username, password)
    assert submit.status_code == 302, f"IdP 应 302 回 redirect_uri：{submit.text[:200]}"
    qs = urllib.parse.parse_qs(
        urllib.parse.urlparse(submit.headers["location"]).query)
    assert qs["state"][0] == state, "IdP 必须原样回传 state"
    code = qs["code"][0]
    resp = client.get(f"{API}/auth/oidc/callback",
                      params={"code": code, "state": qs["state"][0]},
                      follow_redirects=False)
    return resp, code


# ---------------------------------------------------------------- happy path

def test_full_flow_over_real_http_idp(db, client, idp):
    """端到端：真发现文档 → 真 JWKS → 真 PKCE → 真 token 交换 → 会话。"""
    u = _mk_user(db, username="alice")
    resp, _code = _callback(client, idp)

    assert resp.status_code == 302
    assert resp.headers["location"].endswith("/#/sso")
    # 令牌不进 URL（不进历史记录/Referer/访问日志）
    assert "token" not in resp.headers["location"]
    handoff = resp.cookies.get(OIDC_HANDOFF_COOKIE)
    assert handoff
    # 交接票据不能当访问令牌（typ=sso_handoff）
    assert client.get(f"{API}/docs", headers=_hdr(handoff)).status_code == 401

    # 每个协议端点都被真实调用了一次：证明没打桩
    assert idp.hits == {"discovery": 1, "jwks": 1, "authorize": 1,
                        "login": 1, "token": 1}, idp.hits

    sess = client.post(f"{API}/auth/oidc/session")
    assert sess.status_code == 200, sess.text
    token = sess.json()["token"]
    assert client.get(f"{API}/docs", headers=_hdr(token)).status_code == 200
    assert client.get(f"{API}/auth/me", headers=_hdr(token)).json()["username"] == "alice"

    db.expire_all()
    # 首次 SSO 登录把 IdP 的 sub 绑到本地账号
    assert db.get(User, u.id).oidc_subject == "stub-alice"


def test_repeat_sso_login_matches_by_subject_without_password(db, client, idp):
    """第二次登录按 sub 匹配（IdP 侧改名也不影响本地账号归属）。"""
    _mk_user(db, username="alice")
    first, _ = _callback(client, idp)
    assert first.headers["location"].endswith("/#/sso")
    # 换掉交接票据（会话接口会删 cookie），再走一遍完整流程
    assert client.post(f"{API}/auth/oidc/session").status_code == 200
    assert client.cookies.get(OIDC_HANDOFF_COOKIE) is None

    resp, _ = _callback(client, idp)
    assert resp.headers["location"].endswith("/#/sso")
    sess = client.post(f"{API}/auth/oidc/session")
    assert sess.status_code == 200
    assert sess.json()["user"]["username"] == "alice"


# ---------------------------------------------------------------- 协议负向

def test_discovery_issuer_mismatch_refused_before_authorize(client, idp):
    """防：发现文档指向别的租户（issuer 与本配置不一致）——必须拒。"""
    idp.force_issuer = "http://other-tenant.example"
    r = client.get(f"{API}/auth/oidc/start", follow_redirects=False)
    assert r.status_code == 503
    assert "单点登录暂不可用" in r.json()["detail"]
    # 只拉了发现文档，没有把用户送去授权
    assert idp.hits["discovery"] == 1 and idp.hits["authorize"] == 0


def test_nonce_tampered_by_idp_is_rejected(db, client, idp):
    """防：IdP 回传的 nonce 与请求不一致（重放/错配）——必须拒。"""
    _mk_user(db, username="alice")
    idp.force_nonce = "not-the-nonce-we-sent"
    resp, _ = _callback(client, idp)
    assert "sso_error=id_token_invalid" in resp.headers["location"]
    # 走到了 token 交换与验签（jwks 被真拉取）
    assert idp.hits["token"] == 1 and idp.hits["jwks"] == 1


def test_pkce_rejected_by_idp_surfaces_as_token_exchange_failure(db, client, idp):
    """防：verifier 没正确传递/编码错——IdP 侧 PKCE 校验失败必须变成明确错误。"""
    _mk_user(db, username="alice")
    idp.reject_pkce = True
    resp, _ = _callback(client, idp)
    assert "sso_error=token_exchange_failed" in resp.headers["location"]
    assert idp.hits["token"] == 1


def test_authorization_code_replay_rejected_by_idp(db, client, idp):
    """防：授权码可重放——IdP 侧一次性语义必须生效，重放拿不到会话。"""
    _mk_user(db, username="alice")
    first, code = _callback(client, idp)
    assert first.headers["location"].endswith("/#/sso")

    state, _url = _start(client)     # 新的 state/cookie
    replay = client.get(f"{API}/auth/oidc/callback",
                        params={"code": code, "state": state},
                        follow_redirects=False)
    assert "sso_error=token_exchange_failed" in replay.headers["location"]
    assert idp.hits["token"] == 2


def test_wrong_idp_password_never_reaches_local_account(db, client, idp):
    """防：IdP 侧认证失败被当成成功（登录失败页被误判为 302 回调）。"""
    _mk_user(db, username="alice")
    _state, url = _start(client)
    submit = _authorize(idp, url, password="Wrong#2026")
    assert submit.status_code == 200
    assert "登录失败" in submit.text
    assert idp.hits["login"] == 1 and idp.hits["token"] == 0
    # 没有 code 被签发，本地账号也没被绑定
    assert not idp.codes


def test_unknown_account_not_provisioned_by_default(db, client, idp):
    """默认口径：本地账号必须先由管理员建好，SSO 只做认证。"""
    resp, _ = _callback(client, idp, username="stranger")
    assert "sso_error=account_not_provisioned" in resp.headers["location"]


def test_jit_provision_creates_local_user(db, client, idp, monkeypatch):
    monkeypatch.setattr(config, "OIDC_JIT_PROVISION", True)
    monkeypatch.setattr(config, "OIDC_DEFAULT_CLEARANCE", 1)
    monkeypatch.setattr(config, "OIDC_DEFAULT_ROLES", "research")
    resp, _ = _callback(client, idp, username="newhire")
    assert resp.headers["location"].endswith("/#/sso")

    created = db.query(User).filter(User.username == "newhire").one()
    assert created.oidc_subject == "stub-newhire"
    assert created.clearance == 1 and created.role_list() == ["research"]
    assert created.pwd_hash == ""   # 无本地口令：只能走 SSO
    # 口令登录这条路必须关死（空口令也不能登）
    assert client.post(f"{API}/auth/login",
                       json={"username": "newhire", "password": ""}
                       ).status_code in (401, 422)


def test_disabled_account_rejected(db, client, idp):
    u = _mk_user(db, username="alice")
    u.status = False
    db.commit()
    resp, _ = _callback(client, idp)
    assert "sso_error=user_disabled" in resp.headers["location"]


def test_unreachable_idp_returns_503(client, idp, monkeypatch):
    """防：IdP 挂掉时登录页给白屏/500——必须降级成"暂不可用"提示。"""
    monkeypatch.setattr(config, "OIDC_ISSUER", "http://127.0.0.1:1")
    monkeypatch.setattr(config, "OIDC_HTTP_TIMEOUT", 2)
    oidc.clear_cache()
    r = client.get(f"{API}/auth/oidc/start", follow_redirects=False)
    assert r.status_code == 503
    assert "单点登录暂不可用" in r.json()["detail"]


# ---------------------------------------------------------------- claim 同步

def test_claim_sync_applies_roles_over_real_http_idp(db, client, idp, monkeypatch):
    """真链路口径：IdP 下发的 roles claim 经白名单映射写入本地，并留审计。

    同时确认两道硬栏杆在真实流程里同样生效：密级被 cap 限制、admin 需开关。
    """
    from sqlalchemy import select as sa_select

    from app.models import AuditLog

    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC", True)
    monkeypatch.setattr(config, "OIDC_ROLE_CLAIM", "roles")
    monkeypatch.setattr(config, "OIDC_ROLE_MAP", "fin_research:research,fin_admin:admin")
    monkeypatch.setattr(config, "OIDC_CLEARANCE_CLAIM", "clearance")
    monkeypatch.setattr(config, "OIDC_CLEARANCE_MAP", "secret:3")
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_MAX_CLEARANCE", 1)
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_ALLOW_ADMIN", False)

    idp.roles = ["fin_research", "fin_admin"]
    idp.clearance = "secret"
    u = _mk_user(db, username="alice", clearance=0, roles=[])
    resp, _ = _callback(client, idp)
    assert resp.headers["location"].endswith("/#/sso")

    db.expire_all()
    fresh = db.get(User, u.id)
    assert fresh.role_list() == ["research"], "admin 未被授予（开关未开）"
    assert fresh.clearance == 1, "密级被 cap 限制在 1，绝密仍需本地管理员"

    rows = db.execute(sa_select(AuditLog).where(
        AuditLog.action == "idp_claim_sync")).scalars().all()
    if not rows:
        # 审计走异步批量落库：断言前主动排空队列（与 test_login_throttle 同口径）
        from app.audit import flush_audit
        flush_audit(timeout=2.0)
        rows = db.execute(sa_select(AuditLog).where(
            AuditLog.action == "idp_claim_sync")).scalars().all()
    assert rows and "授权角色 research" in rows[0].reason


def test_claim_sync_strict_mode_blocks_sso(db, client, idp, monkeypatch):
    """白名单外取值 + 严格模式：整次登录被拒（而不是悄悄放行）。"""
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC", True)
    monkeypatch.setattr(config, "OIDC_ROLE_MAP", "fin_research:research")
    monkeypatch.setattr(config, "OIDC_CLAIM_SYNC_UNKNOWN", "deny")
    idp.roles = ["superuser"]
    _mk_user(db, username="alice")
    resp, _ = _callback(client, idp)
    assert "sso_error=claim_sync_rejected" in resp.headers["location"]
