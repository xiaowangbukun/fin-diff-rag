# SPDX-License-Identifier: AGPL-3.0-only
"""OIDC 真联调脚本：对**正在运行**的 RAG 后端 + 真实 IdP 跑一遍授权码流程。

与 pytest 的分工：
  · tests/test_oidc_real_idp.py 用 TestClient + 进程内 IdP 验证协议实现；
  · 本脚本连的是**真的监听端口**（回调地址登记、反向代理、Cookie 属性、
    跨域重定向这些只有真部署才暴露），可指向 Keycloak / Azure AD / Okta。

用法：
  # 1) 只查协议参数（不需要 IdP 账号，验证 discovery 与 /oidc/start 拼装）
  RAG_BASE=http://127.0.0.1:8000 python scripts/oidc_live_check.py

  # 2) 完整登录（IdP 上有测试账号时）
  RAG_BASE=http://127.0.0.1:8000 OIDC_ISSUER=http://127.0.0.1:9110 \\
  IDP_USER=admin IDP_PASSWORD=Admin@123 python scripts/oidc_live_check.py

环境变量：
  RAG_BASE      被测服务地址（默认 http://127.0.0.1:8000）
  OIDC_ISSUER   仅用于核对 discovery 的 issuer / PKCE 能力（缺省跳过该组）
  IDP_USER / IDP_PASSWORD   IdP 测试账号；缺失则只跑"协议参数检查"
  LIVE_TIMEOUT  单请求超时秒数（默认 15）

退出码：0 全通过；1 有失败项（可直接接进 CI/上线检查清单）。
"""
import html.parser
import os
import sys
import urllib.parse

import httpx

BASE = os.getenv("RAG_BASE", "http://127.0.0.1:8000").rstrip("/")
API = BASE + "/api/v1"
ISSUER = os.getenv("OIDC_ISSUER", "").rstrip("/")
IDP_USER = os.getenv("IDP_USER", "")
IDP_PASSWORD = os.getenv("IDP_PASSWORD", "")
TIMEOUT = float(os.getenv("LIVE_TIMEOUT", "15"))

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(("  [OK] " if cond else "  [!!] ") + name + (f"  {extra}" if extra else ""))


# ---------------------------------------------------------------- 表单解析

class _FormParser(html.parser.HTMLParser):
    """只取"action + 输入字段"，够驱动 Keycloak/Stub/通用 OIDC 登录页。"""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._cur = {"action": d.get("action") or "",
                         "method": (d.get("method") or "get").lower(),
                         "inputs": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({
                "name": d.get("name") or "",
                "type": (d.get("type") or "text").lower(),
                "value": d.get("value") or "",
            })

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _login_form(text: str):
    p = _FormParser()
    p.feed(text)
    for f in p.forms:
        if any(i["type"] == "password" for i in f["inputs"]):
            return f
    return None


_USERNAME_HINTS = ("user", "email", "login", "account", "uname", "upn")


def _form_payload(form: dict, username: str, password: str) -> dict:
    data: dict = {}
    for i in form["inputs"]:
        name, typ, value = i["name"], i["type"], i["value"]
        if not name or typ in ("submit", "button", "checkbox", "radio", "file"):
            continue
        if typ == "password":
            data[name] = password
        elif typ == "email" or any(h in name.lower() for h in _USERNAME_HINTS):
            data[name] = username
        else:
            data[name] = value      # hidden：rid / credentialId / execution …
    return data


# ---------------------------------------------------------------- 主流程

def _summary() -> int:
    print("\n" + "=" * 46)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项：" + "；".join(FAIL))
        return 1
    print("OIDC 联调通过")
    return 0


def main() -> int:
    client = httpx.Client(timeout=TIMEOUT, trust_env=False,
                          follow_redirects=True)
    try:
        health = client.get(BASE + "/api/health")
        check("服务健康", health.status_code == 200
              and health.json().get("ok") is True,
              f"{health.status_code} {health.text[:60]}")

        prov = client.get(API + "/auth/providers").json()
        check("服务端已启用 OIDC", prov.get("oidc", {}).get("enabled") is True,
              str(prov.get("oidc")))
        if prov.get("oidc", {}).get("enabled") is not True:
            return _summary()

        # ---- 协议参数：/oidc/start 的 302 与 PKCE/nonce/state ----
        start = client.get(API + "/auth/oidc/start", follow_redirects=False)
        check("/oidc/start 返回 302", start.status_code == 302,
              f"HTTP {start.status_code}")
        loc = start.headers.get("location", "")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        check("授权请求为 code 流程",
              qs.get("response_type") == ["code"], loc[:120])
        check("授权请求含 PKCE S256",
              qs.get("code_challenge_method") == ["S256"]
              and bool((qs.get("code_challenge") or [""])[0]))
        check("授权请求带 nonce 与 state",
              bool((qs.get("nonce") or [""])[0])
              and bool((qs.get("state") or [""])[0]))
        check("state 已写入 HttpOnly cookie",
              bool(start.cookies.get("finrag_oidc_state")))
        check("redirect_uri 命中本服务",
              (qs.get("redirect_uri") or [""])[0].startswith(BASE),
              (qs.get("redirect_uri") or [""])[0])

        # ---- IdP 元数据（给了 ISSUER 才查）----
        if ISSUER:
            doc = httpx.get(ISSUER + "/.well-known/openid-configuration",
                            timeout=TIMEOUT, trust_env=False).json()
            check("discovery issuer 与配置一致",
                  str(doc.get("issuer", "")).rstrip("/") == ISSUER,
                  str(doc.get("issuer")))
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                check(f"discovery 提供 {key}", bool(doc.get(key)))
            algs = doc.get("id_token_signing_alg_values_supported") or []
            check("discovery 声明非对称签名算法",
                  bool(algs) and all(a not in ("HS256", "HS384", "HS512", "none")
                                     for a in algs), str(algs))
            if "code_challenge_methods_supported" in doc:
                check("discovery 声明支持 PKCE S256",
                      "S256" in doc["code_challenge_methods_supported"],
                      str(doc["code_challenge_methods_supported"]))

        if not (IDP_USER and IDP_PASSWORD):
            print("\n（未提供 IDP_USER/IDP_PASSWORD：跳过完整登录，"
                  "仅完成协议参数检查）")
            return _summary()

        # ---- 完整登录：IdP 登录页 → 回调 → 交接票据 → 会话 ----
        page = client.get(loc)
        check("到达 IdP 登录页", page.status_code == 200
              and "form" in page.text.lower(),
              f"{page.status_code} {page.url}")
        form = _login_form(page.text)
        check("登录页含口令输入表单", form is not None)
        if form is None:
            return _summary()

        action = urllib.parse.urljoin(str(page.url),
                                      form["action"] or str(page.url))
        done = client.post(action, data=_form_payload(form,
                                                      IDP_USER, IDP_PASSWORD))
        check("IdP 认证后回到本站", str(done.url).startswith(BASE),
              str(done.url))
        check("回调种下交接票据（HttpOnly cookie）",
              bool(client.cookies.get("finrag_sso_handoff")))

        sess = client.post(API + "/auth/oidc/session")
        ok = sess.status_code == 200 and bool(sess.json().get("token"))
        check("交接票据换取到会话令牌", ok,
              f"HTTP {sess.status_code} {sess.text[:80]}")
        if not ok:
            return _summary()

        token = sess.json()["token"]
        hdr = {"Authorization": f"Bearer {token}"}
        me = client.get(API + "/auth/me", headers=hdr)
        check("令牌可用：/auth/me", me.status_code == 200,
              f"HTTP {me.status_code}")
        check("登录账号与 IdP 账号一致",
              me.status_code == 200 and me.json().get("username") == IDP_USER,
              str(me.json().get("username") if me.status_code == 200 else me.text[:60]))
        check("令牌可访问受保护资源 /docs",
              client.get(API + "/docs", headers=hdr).status_code == 200)
        return _summary()
    except httpx.HTTPError as exc:
        print(f"  [!!] 网络错误：{exc}")
        FAIL.append("网络错误")
        return _summary()
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
