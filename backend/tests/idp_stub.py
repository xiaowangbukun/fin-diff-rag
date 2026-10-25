# SPDX-License-Identifier: AGPL-3.0-only
"""真实 OIDC Provider（测试/本地联调用），只依赖标准库 + cryptography。

为什么不是"mock"：本文件起一个真正的 HTTP 服务，完整跑一遍发现文档、
JWKS、授权请求（含 PKCE 校验）、登录表单、code 换 token、RS256 签名
的 id_token。被测代码的协议函数一行不 monkeypatch——发现文档要真的
联网拉取、JWKS 要真的解析、PKCE 要真的校验，这样才测得出"参数拼错"
"issuer 拼错""签名算法不对"这类只在真实对接时才暴露的问题。

用途：
  1. pytest 集成测试里 in-process 起一个（见 tests/test_oidc_real_idp.py）；
  2. 本地联调：`python tests/idp_stub.py 9110` 打印 issuer，再让后端
     `OIDC_ISSUER=http://127.0.0.1:9110` 指过来，用
     `python scripts/oidc_live_check.py` 跑真实浏览器流程。

与真实 IdP 的差异（刻意保持最小）：
  · 登录表单是极简 HTML（Keycloak 的登录页有主题/CSRF/credentialId），
    scripts/oidc_live_check.py 用"解析 form action + 填 username/password"
    的通用方式驱动，两边都能跑通；
  · 不支持 refresh_token / userinfo / 登出端点——本项目的对接面只用
    id_token，多实现一分就多一分"测了假东西"的风险。
"""
import base64
import hashlib
import html
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

CONFIGURED_PASSWORD = os.getenv("IDP_PASSWORD", "Alice#2026")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class StubIdp:
    """进程内 OIDC Provider。start() 后 issuer 可读，stop() 回收端口。"""

    def __init__(self, client_id="finrag-client", client_secret="s3cr3t",
                 host="127.0.0.1", port=0):
        self.client_id = client_id
        self.client_secret = client_secret
        self.password = CONFIGURED_PASSWORD
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self._key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        self.jwk = jwk
        self.requests: dict[str, dict] = {}    # rid -> 授权请求参数
        self.codes: dict[str, dict] = {}       # code -> 授权码记录
        self.hits = {"discovery": 0, "jwks": 0, "authorize": 0,
                     "login": 0, "token": 0}
        # 故障注入（负向用例用）
        self.force_nonce: str | None = None
        self.force_issuer: str | None = None
        self.reject_pkce = False
        self.expire_codes = False
        # 可选 claim（None = 不发；用于 claim→权限同步的真链路用例）
        self.roles: list[str] | None = None
        self.clearance: str | None = None

    # -- 生命周期 ------------------------------------------------------
    kid = "stub-key-1"

    @property
    def issuer(self) -> str:
        port = self._httpd.server_address[1] if self._httpd else self.port
        return f"http://{self.host}:{port}"

    def start(self) -> "StubIdp":
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # 静默：测试输出不要噪声
                pass

            def do_GET(self):
                server._handle(self, "GET")

            def do_POST(self):
                server._handle(self, "POST")

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._httpd.timeout = 5
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # -- 内部工具 ------------------------------------------------------
    def _send(self, h, code: int, body: bytes, ctype: str,
              extra: dict | None = None) -> None:
        h.send_response(code)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(body)

    def _json(self, h, code: int, obj: dict) -> None:
        self._send(h, code, json.dumps(obj).encode(), "application/json")

    def _id_token(self, req: dict, sub: str, username: str,
                  nonce: str | None) -> str:
        now = int(time.time())
        claims = {
            "iss": self.force_issuer or self.issuer,
            "aud": req["client_id"],
            "sub": sub,
            "preferred_username": username,
            "name": username.upper(),
            "email": f"{username}@example.com",
            "iat": now,
            "exp": now + 300,
            "nonce": self.force_nonce if self.force_nonce is not None else nonce,
        }
        # 可选的角色/密级 claim：用于验证 "IdP claim → 本地权限同步" 的真链路
        # （默认不发，避免影响不关心 claim 的用例）。
        if self.roles is not None:
            claims["roles"] = list(self.roles)
        if self.clearance is not None:
            claims["clearance"] = self.clearance
        return jwt.encode(claims, self._key, algorithm="RS256",
                          headers={"kid": self.kid})

    # -- 路由 ----------------------------------------------------------
    def _handle(self, h, method: str) -> None:
        parsed = urllib.parse.urlparse(h.path)
        path = parsed.path.rstrip("/") or "/"
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/.well-known/openid-configuration":
                self.hits["discovery"] += 1
                self._json(h, 200, {
                    "issuer": self.force_issuer or self.issuer,
                    "authorization_endpoint": self.issuer + "/authorize",
                    "token_endpoint": self.issuer + "/token",
                    "jwks_uri": self.issuer + "/jwks",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported":
                        ["client_secret_post", "client_secret_basic"],
                    "scopes_supported": ["openid", "profile", "email"],
                })
                return
            if method == "GET" and path == "/jwks":
                self.hits["jwks"] += 1
                self._json(h, 200, {"keys": [self.jwk]})
                return
            if method == "GET" and path == "/authorize":
                self._authorize(h, qs)
                return
            if method == "POST" and path == "/authorize/login":
                self._login(h)
                return
            if method == "POST" and path == "/token":
                self._token(h)
                return
            self._json(h, 404, {"error": "not_found", "path": path})
        except Exception as exc:  # noqa: BLE001 测试替身：把异常变成 500 便于定位
            self._json(h, 500, {"error": "stub_error", "detail": str(exc)})

    def _authorize(self, h, qs: dict) -> None:
        self.hits["authorize"] += 1
        get = lambda k: (qs.get(k) or [""])[0]  # noqa: E731
        if get("response_type") != "code":
            self._json(h, 400, {"error": "unsupported_response_type"})
            return
        if get("client_id") != self.client_id:
            self._json(h, 400, {"error": "invalid_client"})
            return
        if not get("redirect_uri"):
            self._json(h, 400, {"error": "invalid_request",
                                "error_description": "redirect_uri required"})
            return
        if get("code_challenge_method") != "S256" or not get("code_challenge"):
            self._json(h, 400, {"error": "invalid_request",
                                "error_description": "PKCE S256 required"})
            return
        rid = secrets.token_urlsafe(12)
        self.requests[rid] = {
            "client_id": get("client_id"),
            "redirect_uri": get("redirect_uri"),
            "state": get("state"),
            "nonce": get("nonce"),
            "challenge": get("code_challenge"),
            "scope": get("scope"),
        }
        page = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Stub IdP 登录</title></head><body>
<h3>Stub IdP 登录</h3>
<form method="post" action="/authorize/login">
  <input type="hidden" name="rid" value="{html.escape(rid)}"/>
  <label>用户名 <input name="username" autocomplete="username"/></label><br/>
  <label>口令 <input name="password" type="password" autocomplete="current-password"/></label><br/>
  <button type="submit" name="submit">登录</button>
</form></body></html>"""
        self._send(h, 200, page.encode("utf-8"), "text/html; charset=utf-8")

    def _login(self, h) -> None:
        self.hits["login"] += 1
        length = int(h.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(h.rfile.read(length).decode("utf-8"))
        rid = (form.get("rid") or [""])[0]
        username = (form.get("username") or [""])[0].strip()
        password = (form.get("password") or [""])[0]
        req = self.requests.get(rid)
        if not req:
            self._json(h, 400, {"error": "invalid_request", "detail": "rid"})
            return
        if not username or password != self.password:
            page = ("<html><body><h3>登录失败</h3><p>用户名或口令错误</p>"
                    f'<form method="post" action="/authorize/login">'
                    f'<input type="hidden" name="rid" value="{rid}"/>'
                    f'<input name="username"/><input name="password" type="password"/>'
                    f'<button type="submit">登录</button></form></body></html>')
            self._send(h, 200, page.encode("utf-8"), "text/html; charset=utf-8")
            return
        code = secrets.token_urlsafe(24)
        self.codes[code] = {
            **req, "sub": f"stub-{username}", "username": username,
            "used": False, "created": time.time(),
        }
        sep = "&" if "?" in req["redirect_uri"] else "?"
        location = (f"{req['redirect_uri']}{sep}"
                    + urllib.parse.urlencode({"code": code,
                                              "state": req["state"] or ""}))
        self._send(h, 302, b"", "text/plain", {"Location": location})

    def _token(self, h) -> None:
        self.hits["token"] += 1
        length = int(h.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(h.rfile.read(length).decode("utf-8"))
        get = lambda k: (form.get(k) or [""])[0]  # noqa: E731
        if get("grant_type") != "authorization_code":
            self._json(h, 400, {"error": "unsupported_grant_type"})
            return
        record = self.codes.get(get("code"))
        if not record:
            self._json(h, 400, {"error": "invalid_grant",
                                "error_description": "unknown code"})
            return
        if record["used"]:
            self._json(h, 400, {"error": "invalid_grant",
                                "error_description": "code already redeemed"})
            return
        if self.expire_codes or time.time() - record["created"] > 120:
            self._json(h, 400, {"error": "invalid_grant",
                                "error_description": "code expired"})
            return
        if get("client_id") != self.client_id:
            self._json(h, 400, {"error": "invalid_client"})
            return
        if self.client_secret and get("client_secret") != self.client_secret:
            self._json(h, 401, {"error": "invalid_client"})
            return
        if get("redirect_uri") != record["redirect_uri"]:
            self._json(h, 400, {"error": "invalid_grant",
                                "error_description": "redirect_uri mismatch"})
            return
        verifier = get("code_verifier")
        expected = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        if self.reject_pkce or not verifier or expected != record["challenge"]:
            self._json(h, 400, {"error": "invalid_grant",
                                "error_description": "PKCE verification failed"})
            return
        record["used"] = True   # 授权码一次性：重放必须被 IdP 侧拒绝
        self._json(h, 200, {
            "access_token": secrets.token_urlsafe(24),
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": self._id_token(record, record["sub"],
                                       record["username"], record["nonce"]),
        })


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9110
    stub = StubIdp(port=port, client_id="finrag",
                   client_secret=os.getenv("IDP_CLIENT_SECRET", "s3cr3t"))
    stub.start()
    print(f"issuer={stub.issuer} client_id={stub.client_id} "
          f"password={stub.password}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stub.stop()
