# SPDX-License-Identifier: Apache-2.0
"""一次性恢复码的**活服务**实测：对新起的真实进程跑完整绑定/使用/重生成/重置链路。

与 pytest 的分工：
  · tests/test_recovery_codes.py 覆盖分支与边界（每用例独立 schema）；
  · 本脚本打的是**真实监听端口 + 持久库**，用真实 HTTP 客户端（有 cookie/
    超时/重定向），能暴露"迁移没跑、列没加、网关不转发、状态码被 SDK 改写"
    这类只在部署态出现的问题。跑完会把被测账号的动态口令**重置回未绑定**，
    可重复执行。

环境变量：
  RAG_BASE        被测服务（默认 http://127.0.0.1:8000）
  RC_USER         被测账号（默认 intern01，须已存在且**未绑定**动态口令）
  RC_PASSWORD     被测账号口令（默认 User@123）
  ADMIN_USER      管理员账号（默认 admin）
  ADMIN_PASSWORD  管理员口令（默认 Admin@123）

注意：脚本会临时给被测账号绑定动态口令，结束时用管理员 `mfa-reset` 复原
（同时吊销该账号所有会话）。请在演示/测试环境运行。

退出码：0 全通过；1 有失败项。
"""
import os
import re
import sys
from pathlib import Path

import httpx

BASE = os.getenv("RAG_BASE", "http://127.0.0.1:8000").rstrip("/")
API = BASE + "/api/v1"
USER = os.getenv("RC_USER", "intern01")
PWD = os.getenv("RC_PASSWORD", "User@123")
ADMIN = os.getenv("ADMIN_USER", "admin")
ADMIN_PWD = os.getenv("ADMIN_PASSWORD", "Admin@123")
CODE_RE = re.compile(r"^[A-HJ-KM-NP-Z2-9]{4}(-[A-HJ-KM-NP-Z2-9]{4}){2}$")

# 用后端自己的 TOTP 实现生成口令：与应用内校验同一套 RFC 6238 参数
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from app import totp  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond, extra: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(("  [OK] " if cond else "  [!!] ") + name + (f"  {extra}" if extra else ""))


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _summary() -> int:
    print("\n" + "=" * 46)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项：" + "；".join(FAIL))
        return 1
    print("恢复码活服务实测通过")
    return 0


def main() -> int:
    c = httpx.Client(base_url=API, timeout=30, trust_env=False)
    admin_tk, uid = "", ""
    try:
        health = c.get("/health").json()
        check("服务健康", health.get("ok") is True, str(health.get("storage")))

        admin_tk = c.post("/auth/login",
                          json={"username": ADMIN, "password": ADMIN_PWD}
                          ).json()["token"]
        users = c.get("/admin/users", headers=_hdr(admin_tk)).json()
        target = next((u for u in users if u["username"] == USER), None)
        check(f"被测账号 {USER} 存在", target is not None)
        if target is None:
            return _summary()
        uid = target["id"]
        check("前置状态：未绑定动态口令",
              target["mfa_enabled"] is False and target["recovery_codes_remaining"] == 0,
              f"mfa={target['mfa_enabled']} codes={target['recovery_codes_remaining']}")
        if target["mfa_enabled"]:
            c.post(f"/admin/users/{uid}/mfa-reset", headers=_hdr(admin_tk))

        # ---- 绑定并发码 ----
        tk = c.post("/auth/login", json={"username": USER, "password": PWD}
                    ).json()["token"]
        setup = c.post("/auth/totp/setup", headers=_hdr(tk), json={"password": PWD})
        check("生成 TOTP 待绑定密钥", setup.status_code == 200, setup.text[:80])
        secret = setup.json()["secret"]
        conf = c.post("/auth/totp/confirm", headers=_hdr(tk),
                      json={"code": totp.code_at(secret)})
        check("绑定成功", conf.status_code == 200, conf.text[:80])
        codes = conf.json().get("recovery_codes") or []
        check("绑定即发放恢复码（10 个）", len(codes) == 10, f"{len(codes)} 个")
        check("恢复码格式可手抄（XXXX-XXXX-XXXX，无 0/O/1/I/L）",
              all(CODE_RE.match(x) for x in codes))
        me = c.get("/auth/me", headers=_hdr(tk)).json()
        check("剩余数量与发放数一致", me.get("recovery_codes_remaining") == len(codes),
              str(me.get("recovery_codes_remaining")))

        # ---- 口令 → 挑战票据 ----
        step1 = c.post("/auth/login", json={"username": USER, "password": PWD}).json()
        check("再次登录需第二因子", step1.get("mfa_required") is True
              and bool(step1.get("challenge")) and "token" not in step1)
        step1b = c.post("/auth/login", json={"username": USER, "password": PWD}).json()

        bad = c.post("/auth/login/mfa",
                      json={"challenge": step1["challenge"],
                            "recovery_code": "ZZZZ-ZZZZ-ZZZZ"})
        check("错误恢复码被拒（401）", bad.status_code == 401, bad.text[:60])

        # ---- 恢复码登录 ----
        used = c.post("/auth/login/mfa",
                      json={"challenge": step1b["challenge"],
                            "recovery_code": codes[0].lower()})
        check("恢复码登录成功（大小写不敏感）", used.status_code == 200, used.text[:80])
        body = used.json()
        check("响应带剩余数量 9", body.get("recovery_codes_remaining") == 9,
              str(body.get("recovery_codes_remaining")))
        check("未触发告警（还剩 9 个）", "recovery_warning" not in body)
        check("恢复码换来的令牌可访问 /docs",
              c.get("/docs", headers=_hdr(body["token"])).status_code == 200)

        # ---- 重放 ----
        step1c = c.post("/auth/login", json={"username": USER, "password": PWD}).json()
        replay = c.post("/auth/login/mfa",
                        json={"challenge": step1c["challenge"],
                              "recovery_code": codes[0]})
        check("同一恢复码重放被拒（401）", replay.status_code == 401, replay.text[:60])
        check("重放不影响剩余数量",
              c.get("/auth/me", headers=_hdr(tk)).json()["recovery_codes_remaining"] == 9)

        # ---- 重新生成 ----
        wrong = c.post("/auth/recovery-codes/regenerate", headers=_hdr(tk),
                       json={"password": "Wrong-Passw0rd!2026"})
        check("重新生成需正确口令（401）", wrong.status_code == 401, wrong.text[:60])
        regen = c.post("/auth/recovery-codes/regenerate", headers=_hdr(tk),
                       json={"password": PWD})
        check("重新生成成功", regen.status_code == 200, regen.text[:80])
        new_codes = regen.json().get("recovery_codes") or []
        check("新码 10 个且与旧码无重叠", len(new_codes) == 10
              and not set(new_codes) & set(codes), f"{len(new_codes)} 个")

        step1d = c.post("/auth/login", json={"username": USER, "password": PWD}).json()
        old = c.post("/auth/login/mfa",
                     json={"challenge": step1d["challenge"], "recovery_code": codes[1]})
        check("旧码整组作废（401）", old.status_code == 401, old.text[:60])
        step1e = c.post("/auth/login", json={"username": USER, "password": PWD}).json()
        fresh = c.post("/auth/login/mfa",
                       json={"challenge": step1e["challenge"],
                             "recovery_code": new_codes[0]})
        check("新码可用", fresh.status_code == 200
              and fresh.json().get("recovery_codes_remaining") == 9)

        # ---- 管理员重置：清码 + 复原未绑定 ----
        reset = c.post(f"/admin/users/{uid}/mfa-reset", headers=_hdr(admin_tk))
        check("管理员重置成功", reset.status_code == 200, reset.text[:80])
        check("重置回报作废的恢复码数量（9）",
              reset.json().get("recovery_codes_dropped") == 9,
              str(reset.json().get("recovery_codes_dropped")))
        back = c.post("/auth/login", json={"username": USER, "password": PWD}).json()
        check("重置后回到单因子登录（前置状态已复原）",
              back.get("mfa_required") is not True and bool(back.get("token")))
        after = {u["username"]: u for u in
                 c.get("/admin/users", headers=_hdr(admin_tk)).json()}
        check("账号已复原为未绑定且恢复码为 0",
              after[USER]["mfa_enabled"] is False
              and after[USER]["recovery_codes_remaining"] == 0)
        return _summary()
    except httpx.HTTPError as exc:
        print(f"  [!!] 网络错误：{exc}")
        FAIL.append("网络错误")
        return _summary()
    finally:
        # 异常中断也要尽量复原被改动的演示账号
        if admin_tk and uid and FAIL:
            try:
                c.post(f"/admin/users/{uid}/mfa-reset", headers=_hdr(admin_tk))
                print("  [..] 已尝试复原被测账号的动态口令状态")
            except Exception:
                pass
        c.close()


if __name__ == "__main__":
    sys.exit(main())
