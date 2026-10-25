# SPDX-License-Identifier: Apache-2.0
"""Cookie 会话模式（AUTH_COOKIE_MODE=true）真机 HTTP 验证。

为什么单独一个脚本而不是并进 http_check.py：两种模式的登录响应形态不同
（cookie 模式不回传 token），而 http_check 是"默认 Bearer 模式"的回归基线。
这里只验 cookie 模式特有的四件事：

  1. 登录响应**不回传令牌**，改种 HttpOnly Cookie（XSS 拿不到令牌）；
  2. 写操作缺 X-CSRF-Token → 403（双提交 Cookie，跨站请求拿不到该头）；
  3. 带上 CSRF 头 → 正常放行；
  4. 登出清 Cookie 且会话被吊销。

用法：先以 `AUTH_COOKIE_MODE=true` 启动服务，再执行
    python cookie_mode_check.py
"""
import json
import sys
from pathlib import Path

import httpx

BASE_URL = "http://127.0.0.1:8000"
out = open(Path(__file__).resolve().parent / ".cookiecheck.txt", "w", encoding="utf-8")
sys.stdout = sys.stderr = out

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK] " if cond else "  [!!] ") + name + (f"  {extra}" if extra else ""))


c = httpx.Client(base_url=BASE_URL, timeout=60, trust_env=False)
r = c.post("/api/auth/login", json={"username": "admin", "password": "Admin@123"})
body = r.json()
check("登录成功且**不回传**访问令牌", r.status_code == 200 and body.get("token") is None,
      f"HTTP {r.status_code} token={body.get('token')}")
check("登录响应声明需要 CSRF 头", body.get("csrf_required") is True)
check("会话 ID 单独下发（前端据此展示登录设备）", len(body.get("session_id") or "") == 36)

set_cookie = "; ".join(r.headers.get_list("set-cookie")).lower()
check("会话 Cookie 为 HttpOnly（脚本/插件读不到）", "httponly" in set_cookie)
check("会话 Cookie 带 SameSite（跨站请求默认不带）",
      "samesite=lax" in set_cookie or "samesite=strict" in set_cookie)
check("响应头带 X-CSRF-Token（前端写进后续请求头）",
      bool(r.headers.get("X-CSRF-Token")))

r = c.get("/api/auth/me")
check("Cookie 可独立完成鉴权（不需要 Authorization 头）",
      r.status_code == 200 and r.json().get("username") == "admin",
      f"HTTP {r.status_code}")

payload = {"query": "反洗钱客户身份识别九要素包括哪些"}
r = c.post("/api/chat", json=payload)
check("写操作缺 X-CSRF-Token → 403（双提交 Cookie 生效）",
      r.status_code == 403, f"HTTP {r.status_code} {r.text[:60]}")

csrf = c.cookies.get("finrag_csrf") or ""
# 放行断言刻意用"不依赖 embedding 服务"的写接口（运维日报清理）：
# 用 /api/chat 验证会把"CSRF 是否放行"和"检索服务是否在线"两件事搅在一起，
# 本机没有向量服务时 503 会被误读成 CSRF 失败。
r = c.post("/api/admin/metrics/cleanup", headers={"X-CSRF-Token": csrf})
check("带上 CSRF 头后写操作放行", r.status_code == 200 and "kept" in r.json(),
      f"HTTP {r.status_code} {r.text[:60]}")
check("携带错误的 CSRF 头仍被拒",
      c.post("/api/admin/metrics/cleanup",
             headers={"X-CSRF-Token": "wrong-token"}).status_code == 403)

sid = body["session_id"]
# 登出也是写操作：同样受 CSRF 保护（否则第三方站点能把人"登出"，
# 属可用性攻击；也与前端 api.js "所有写方法带 CSRF"的口径一致）。
check("登出缺 CSRF 头同样被拒（防登出 CSRF）",
      c.post("/api/auth/logout").status_code == 403)
r = c.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
check("登出成功", r.status_code == 200)
check("登出后 Cookie 已清空", not (c.cookies.get("finrag_session") or ""))
r = c.get("/api/auth/sessions")
check("登出后会话不可再用", r.status_code == 401, f"HTTP {r.status_code}")

print("\n" + "=" * 46)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
if FAIL:
    print("失败项：" + "；".join(FAIL))
    sys.exit(1)
print("Cookie 会话模式验证通过")
