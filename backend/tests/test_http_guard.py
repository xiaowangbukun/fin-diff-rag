# SPDX-License-Identifier: Apache-2.0
"""传输与浏览器边界（P0-2）：安全头 / HTTPS 跳转 / CORS 白名单 / Host 校验。

为什么不用"反配上配一下就行"：
  · 灰度直连、排障绕反代、Windows 单机演示都会绕过反代，此时反代上的
    安全头全部消失；应用自己的默认值才是可评审、可测试的那一份。
  · CORS 默认必须**拒绝**：金融系统前端与 API 同源部署，任何跨域白名单
    都应是显式决策（写进配置、进评审），而不是框架默认 `*` 带出的"顺手开了"。

这些用例直接挂中间件到最小 Starlette 应用上跑：断言的正是中间件行为本身，
不依赖业务路由，也不受其它用例的配置污染。
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import config
from app.httpguard import (
    CORSGuardMiddleware, HTTPSRedirectMiddleware, SecurityHeadersMiddleware,
    is_https,
)

CSP = "default-src 'self'; script-src 'self'"


def _build(cors_origins=None):
    app = FastAPI()

    @app.get("/api/health")
    def health():
        return {"ok": True}

    @app.get("/api/thing")
    def thing():
        return {"x": 1}

    @app.post("/api/thing")
    def thing_post():
        return {"created": True}

    @app.get("/page")
    def page():
        return {"html": True}

    # 顺序与 main.py 一致：后加者在外层
    app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(CORSGuardMiddleware, origins=cors_origins or [])
    app.add_middleware(SecurityHeadersMiddleware)
    return TestClient(app)


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    """默认生产口径：安全头开、CSP 有值、HSTS 一天、不强制 HTTPS。"""
    monkeypatch.setattr(config, "SECURITY_HEADERS", True)
    monkeypatch.setattr(config, "CSP_POLICY", CSP)
    monkeypatch.setattr(config, "HSTS_SECONDS", 86400)
    monkeypatch.setattr(config, "FORCE_HTTPS", False)
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", False)


# ---------------------------------------------------------------- 安全头


def test_api_response_carries_baseline_headers():
    r = _build().get("/api/thing")
    assert r.status_code == 200
    h = r.headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"
    assert "geolocation=()" in h["Permissions-Policy"]
    assert h["Content-Security-Policy"] == CSP
    # API 响应禁止缓存（令牌/密级内容不能留在共享终端缓存里）
    assert h["Cache-Control"] == "no-store"


def test_static_page_not_cached_but_has_headers():
    r = _build().get("/page")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Cache-Control" not in r.headers


def test_https_request_gets_hsts():
    client = _build()
    r = client.get("/api/thing", headers={"X-Forwarded-Proto": "https"})
    # 未开 TRUST_PROXY_HEADERS 时不认转发头：明文场景不发 HSTS
    assert "Strict-Transport-Security" not in r.headers


def test_hsts_only_when_https_and_behind_trusted_proxy(monkeypatch):
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    r = _build().get("/api/thing", headers={"X-Forwarded-Proto": "https"})
    assert r.headers["Strict-Transport-Security"] == (
        "max-age=86400; includeSubDomains")


def test_hsts_disabled_by_zero(monkeypatch):
    monkeypatch.setattr(config, "HSTS_SECONDS", 0)
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    r = _build().get("/api/thing", headers={"X-Forwarded-Proto": "https"})
    assert "Strict-Transport-Security" not in r.headers


def test_security_headers_can_be_disabled(monkeypatch):
    monkeypatch.setattr(config, "SECURITY_HEADERS", False)
    r = _build().get("/api/thing")
    assert "X-Frame-Options" not in r.headers


def test_main_app_puts_security_headers_outermost():
    """真实 main.py 的中间件顺序：SecurityHeaders 必须最外层。

    顺序写错不会让任何功能挂掉，却会让"被拒请求"（Host 白名单 400、跳转
    308、预检 403）丢掉安全头——这些恰恰是最需要最小信息量的分支，而单元
    用例只测单个中间件时完全看不出来。
    """
    from app.main import app as main_app

    assert main_app.user_middleware[0].cls is SecurityHeadersMiddleware


def test_trusted_host_rejection_still_has_security_headers():
    """Host 白名单拒绝（400）不能绕过安全头。

    复现 main.py 修正过的顺序：TrustedHost 必须在 SecurityHeaders **之前**
    注册（后加者在外层）。若排在后面，它就成了最外层，400 响应直接由它
    返回，安全头与 no-store 都不带——攻击者用伪造 Host 试探时反而收到一份
    没有最小化约束的响应。
    """
    app = FastAPI()

    @app.get("/api/thing")
    def thing():
        return {"x": 1}

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["good.example"])
    app.add_middleware(SecurityHeadersMiddleware)
    client = TestClient(app)
    r = client.get("/api/thing", headers={"Host": "evil.example"})
    assert r.status_code == 400
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_error_response_also_has_headers():
    """未捕获异常的 500 也必须带安全头。

    这条用例复现的是真实拓扑的**坑**：`Exception` 处理器由 Starlette 的
    ServerErrorMiddleware 调用，位于所有 user middleware 之外，所以 500
    响应不经过 SecurityHeadersMiddleware。修复方式是 errors 处理器自己对
    响应调用同一个 apply_security_headers（见 errors.py）。
    """
    from fastapi import FastAPI as _F

    from app.errors import internal_error_handler

    app = _F()

    @app.get("/api/boom")
    def boom():
        raise RuntimeError("x")

    app.add_exception_handler(Exception, internal_error_handler)
    app.add_middleware(SecurityHeadersMiddleware)
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/api/boom")
    assert r.status_code == 500
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_is_https_trusts_forwarded_proto_only_when_enabled(monkeypatch):
    """Cookie 的 Secure 与 HSTS 必须共用同一套协议判定。

    反代终止 TLS 时应用看到的是 http：只认 request.url.scheme 会让会话
    Cookie 漏发 Secure（明文回传）；只认转发头又会被伪造头绕过，因此必须
    由 TRUST_PROXY_HEADERS 决定信不信。
    """
    class _Req:
        class url:  # noqa: N801
            scheme = "http"

        headers = {"x-forwarded-proto": "https"}

    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", False)
    assert is_https(_Req()) is False
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    assert is_https(_Req()) is True

    class _Plain(_Req):
        headers = {}

    assert is_https(_Plain()) is False


def test_apply_security_headers_respects_disabled_flag(monkeypatch):
    from app.httpguard import apply_security_headers
    monkeypatch.setattr(config, "SECURITY_HEADERS", False)

    class _Req:
        class url:  # noqa: N801
            path = "/api/x"
            scheme = "https"

    class _Resp:
        headers = {}

    apply_security_headers(_Req(), _Resp())
    assert _Resp.headers == {}


# ---------------------------------------------------------------- HTTPS 跳转


def test_force_https_redirects_308(monkeypatch):
    monkeypatch.setattr(config, "FORCE_HTTPS", True)
    r = _build().get("/api/thing", follow_redirects=False)
    assert r.status_code == 308
    assert r.headers["location"].startswith("https://")


def test_health_is_exempt_from_redirect(monkeypatch):
    """负载均衡器的明文探针不能被 308（否则实例被判不健康）。"""
    monkeypatch.setattr(config, "FORCE_HTTPS", True)
    assert _build().get("/api/health", follow_redirects=False).status_code == 200


def test_force_https_accepts_trusted_forwarded_proto(monkeypatch):
    monkeypatch.setattr(config, "FORCE_HTTPS", True)
    monkeypatch.setattr(config, "TRUST_PROXY_HEADERS", True)
    r = _build().get("/api/thing", headers={"X-Forwarded-Proto": "https"},
                    follow_redirects=False)
    assert r.status_code == 200


def test_force_https_ignores_forwarded_proto_by_default(monkeypatch):
    """不信任转发头时，伪造 X-Forwarded-Proto 不能绕过强制 HTTPS。"""
    monkeypatch.setattr(config, "FORCE_HTTPS", True)
    r = _build().get("/api/thing", headers={"X-Forwarded-Proto": "https"},
                     follow_redirects=False)
    assert r.status_code == 308


# ---------------------------------------------------------------- CORS


def test_no_cors_headers_by_default():
    r = _build().get("/api/thing", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_preflight_from_unknown_origin_is_403():
    r = _build().options("/api/thing", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST"})
    assert r.status_code == 403
    assert "Access-Control-Allow-Origin" not in r.headers


def test_non_preflight_from_unknown_origin_is_passed_through_without_cors():
    """非预检的跨域请求不改写响应：浏览器按"没有 ACAO 头"自行拦截。"""
    r = _build().get("/api/thing", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200
    assert "Access-Control-Allow-Origin" not in r.headers


def test_whitelisted_origin_gets_echoed_not_star():
    client = _build(["https://console.finrag.internal"])
    r = client.get("/api/thing", headers={"Origin": "https://console.finrag.internal"})
    assert r.headers["Access-Control-Allow-Origin"] == "https://console.finrag.internal"
    # Cookie 会话必须允许携带凭据；同时绝不能回 "*"（* 与 credentials 互斥）
    assert r.headers["Access-Control-Allow-Credentials"] == "true"
    assert r.headers["Vary"] == "Origin"


def test_whitelisted_preflight_returns_204_with_csrf_header_allowed():
    client = _build(["http://localhost:5173"])
    r = client.options("/api/thing", headers={
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-csrf-token"})
    assert r.status_code == 204
    assert r.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"
    assert "X-CSRF-Token" in r.headers["Access-Control-Allow-Headers"]
    assert "POST" in r.headers["Access-Control-Allow-Methods"]


def test_trailing_slash_variance_is_tolerated():
    client = _build(["https://console.finrag.internal/"])
    r = client.get("/api/thing", headers={"Origin": "https://console.finrag.internal"})
    assert r.headers["Access-Control-Allow-Origin"] == "https://console.finrag.internal"
