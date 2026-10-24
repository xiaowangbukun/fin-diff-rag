# SPDX-License-Identifier: Apache-2.0
"""一次性恢复码（备用码）：TOTP 绑定的自助恢复通道。

覆盖口径：
  · 生成：整组返回、只存 HMAC 摘要、字符集/长度"可手抄"（去 0/O/1/I/L）；
  · 使用：一次一码（用后标 used_at）、同码重放拒绝、用尽后拒绝；
  · 与登录流程的耦合：恢复码仍走"口令 → 挑战票据 → 第二因子"两步，
    不能绕过口令；剩余 ≤2 下发告警，用尽时明确提示找管理员；
  · 失效面：重新生成需口令且旧码整组作废；解绑 TOTP / 管理员重置都清码；
  · 健壮性：损坏的入库 JSON、中文/全角输入不能让登录 500。
"""
import json
import re

import pytest
from fastapi.testclient import TestClient

from app import config, recovery, totp
from app.main import app as real_app
from app.models import User, new_id
from app.security import hash_password

API = "/api/v1"
PWD = "Str0ng-Passw0rd!2026"
# 32 字母表去掉了 I/L/O 与 0/1：ABCD-EFGH-JKLM 形态，3 组 × 4 字符
CODE_RE = re.compile(r"^[A-HJ-KM-NP-Z2-9]{4}(-[A-HJ-KM-NP-Z2-9]{4}){2}$")


@pytest.fixture
def client():
    return TestClient(real_app)


@pytest.fixture(autouse=True)
def _reset_throttle():
    """登录失败计数是进程级状态，跨用例会互相污染（与 test_mfa_auth 同因）。"""
    from app import loginthrottle
    loginthrottle.reset()
    yield
    loginthrottle.reset()


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


def _login(client, username="alice", password=PWD):
    return client.post(f"{API}/auth/login",
                       json={"username": username, "password": password})


def _challenge(client, username="alice"):
    body = _login(client, username).json()
    assert body.get("mfa_required") is True
    return body["challenge"]


def _enroll(client, username="alice"):
    """走完整绑定流程（口令 → setup → confirm），返回 (会话, 明文恢复码)。"""
    token = _login(client, username).json()["token"]
    setup = client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                        json={"password": PWD})
    assert setup.status_code == 200, setup.text
    r = client.post(f"{API}/auth/totp/confirm", headers=_hdr(token),
                    json={"code": totp.code_at(setup.json()["secret"])})
    assert r.status_code == 200, r.text
    return token, r.json()["recovery_codes"]


def _use_code(client, code, username="alice"):
    return client.post(f"{API}/auth/login/mfa",
                       json={"challenge": _challenge(client, username),
                             "recovery_code": code})


# ---------------------------------------------------------------- 单元口径

def test_generate_returns_distinct_handcopy_friendly_codes():
    """防：码太长/含易混字符（0/O/1/I/L）→ 用户抄错，恢复通道形同虚设。"""
    codes, blob = recovery.generate(10)
    assert len(codes) == 10
    assert len(set(codes)) == 10, "同组内不允许重复"
    assert all(CODE_RE.match(c) for c in codes), codes
    assert all(len(c.replace("-", "")) == 12 for c in codes)  # 32^12 ≈ 60 bit
    assert recovery.total(blob) == 10
    assert recovery.remaining(blob) == 10


def test_generate_stores_only_digests():
    """防：明文恢复码入库——库被读走等于第二因子被读走。"""
    codes, blob = recovery.generate(3)
    assert all(c not in blob for c in codes), "明文（含连字符）不得出现在入库 JSON"
    data = json.loads(blob)
    assert all(set(item) == {"h", "used_at"} for item in data["codes"])
    assert all(len(item["h"]) == 64 for item in data["codes"])  # HMAC-SHA256


def test_consume_is_single_use_and_marks_used_at():
    """防：一个恢复码能用两次——等价于第二因子可重放。"""
    codes, blob = recovery.generate(3)
    ok, new_blob, left = recovery.consume(blob, codes[0])
    assert ok is True and left == 2
    used = [item for item in json.loads(new_blob)["codes"] if item["used_at"]]
    assert len(used) == 1

    again, same_blob, left2 = recovery.consume(new_blob, codes[0])
    assert again is False and left2 == 2
    # 失败不得改动入库内容（不能因为"重复提交"就抹掉别人的记录）
    assert same_blob == new_blob


def test_normalize_tolerates_case_spaces_and_dashes():
    """防：用户从纸上抄码时大小写/空格/连字符不一致就被判错。"""
    codes, blob = recovery.generate(1)
    messy = " " + codes[0].lower().replace("-", " - ") + " "
    ok, _, left = recovery.consume(blob, messy)
    assert ok is True and left == 0


def test_non_ascii_input_is_rejected_without_crashing():
    """防：恢复码框里填了中文 → UnicodeEncodeError 500（而不是正常 401）。"""
    codes, blob = recovery.generate(1)
    assert recovery.normalize("中文恢复码") == ""
    ok, _, left = recovery.consume(blob, "中文恢复码")
    assert ok is False and left == 1
    # 全角字母/连字符同样只应被过滤为"无有效字符"
    assert recovery.consume(blob, "ＡＢＣＤ－ＥＦＧＨ")[0] is False
    assert recovery.remaining(blob) == 1


def test_corrupt_blob_degrades_to_empty_not_500():
    """防：入库 JSON 损坏（手工改库/半写）→ 登录直接 500，账号被永久锁死。"""
    assert recovery.remaining("not-json") == 0
    assert recovery.remaining('{"codes": "oops"}') == 0
    ok, new_blob, left = recovery.consume("not-json", "ABCD-EFGH-JKLM")
    assert ok is False and left == 0 and new_blob == "not-json"


def test_generate_refuses_without_server_key(monkeypatch):
    """防：没配密钥时"生成"悄悄产出弱码（无 HMAC 密钥 = 摘要可被离线重算）。"""
    monkeypatch.setattr(config, "MFA_SECRET_KEY", "")
    monkeypatch.setattr(config, "JWT_SECRET", "")
    assert recovery.available() is False
    with pytest.raises(RuntimeError):
        recovery.generate(1)
    assert recovery.consume("", "ABCD-EFGH-JKLM")[0] is False


# ---------------------------------------------------------------- 绑定发放

def test_binding_issues_codes_once_and_never_returns_plaintext_again(db, client):
    """绑定成功即发码；之后任何接口都不该再吐明文。"""
    _mk_user(db)
    token, codes = _enroll(client)
    assert len(codes) == config.RECOVERY_CODE_COUNT

    db.expire_all()
    u = db.query(User).one()
    assert recovery.remaining(u.recovery_codes) == len(codes)
    assert all(c not in u.recovery_codes for c in codes)

    me = client.get(f"{API}/auth/me", headers=_hdr(token)).json()
    assert me["recovery_codes_remaining"] == len(codes)
    assert me["mfa_enabled"] is True

    # 已绑定后再调 setup 必须 409：不能靠重复绑定再拿一组明文
    again = client.post(f"{API}/auth/totp/setup", headers=_hdr(token),
                        json={"password": PWD})
    assert again.status_code == 409
    assert "recovery_codes" not in again.text


# ---------------------------------------------------------------- 登录使用

def test_recovery_code_logs_in_once_and_reports_remaining(db, client):
    _mk_user(db)
    _, codes = _enroll(client)

    r = _use_code(client, codes[0].lower())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["token"]
    assert body["recovery_codes_remaining"] == len(codes) - 1
    assert body["user"]["recovery_codes_remaining"] == len(codes) - 1
    assert "recovery_warning" not in body   # 还剩 9 个，不该打扰用户
    assert client.get(f"{API}/docs",
                      headers=_hdr(body["token"])).status_code == 200

    # 同一个码重放（即便换了新挑战票据）必须失败
    replay = _use_code(client, codes[0])
    assert replay.status_code == 401
    assert "已被使用" in replay.json()["detail"]

    db.expire_all()
    assert recovery.remaining(db.query(User).one().recovery_codes) == len(codes) - 1


def test_recovery_code_cannot_bypass_password_step(db, client):
    """恢复码是第二因子替代品，不是登录凭证：没有口令换来的挑战票据就无效。"""
    _mk_user(db)
    _, codes = _enroll(client)
    r = client.post(f"{API}/auth/login/mfa",
                    json={"challenge": "this-is-not-a-jwt-at-all",
                          "recovery_code": codes[0]})
    assert r.status_code == 401
    db.expire_all()
    # 失败路径不得消耗恢复码
    assert recovery.remaining(db.query(User).one().recovery_codes) == len(codes)


def test_login_mfa_requires_code_or_recovery_code(db, client):
    _mk_user(db)
    _enroll(client)
    ch = _challenge(client)
    r = client.post(f"{API}/auth/login/mfa", json={"challenge": ch})
    assert r.status_code == 400
    assert "恢复码" in r.json()["detail"]


def test_warning_when_only_two_codes_left(db, client):
    _mk_user(db)
    _, codes = _enroll(client)
    body = {}
    for c in codes[:-2]:
        r = _use_code(client, c)
        assert r.status_code == 200
        body = r.json()
    assert body["recovery_codes_remaining"] == 2
    assert "仅剩 2 个" in body["recovery_warning"]


def test_all_codes_used_up_then_rejected_with_admin_hint(db, client):
    _mk_user(db)
    _, codes = _enroll(client)
    body = {}
    for c in codes:
        r = _use_code(client, c)
        assert r.status_code == 200
        body = r.json()
    assert body["recovery_codes_remaining"] == 0
    assert "用尽" in body["recovery_warning"]

    r = _use_code(client, codes[0])
    assert r.status_code == 401
    assert "管理员重置" in r.json()["detail"]


def test_recovery_disabled_switch_rejects_use(db, client, monkeypatch):
    """应急降级：关掉 RECOVERY_CODE_ENABLED 后存量码立即失效。"""
    _mk_user(db)
    _, codes = _enroll(client)
    monkeypatch.setattr(config, "RECOVERY_CODE_ENABLED", False)
    r = _use_code(client, codes[0])
    assert r.status_code == 400
    assert "未启用恢复码" in r.json()["detail"]
    db.expire_all()
    assert recovery.remaining(db.query(User).one().recovery_codes) == len(codes)


# ---------------------------------------------------------------- 重新生成

def test_regenerate_requires_password_and_voids_old_codes(db, client):
    _mk_user(db)
    token, codes = _enroll(client)

    wrong = client.post(f"{API}/auth/recovery-codes/regenerate",
                        headers=_hdr(token), json={"password": "Wr0ng-Passw0rd!"})
    assert wrong.status_code == 401

    ok = client.post(f"{API}/auth/recovery-codes/regenerate",
                     headers=_hdr(token), json={"password": PWD})
    assert ok.status_code == 200, ok.text
    new_codes = ok.json()["recovery_codes"]
    assert len(new_codes) == len(codes)
    assert not set(new_codes) & set(codes), "新码不得与旧码重叠"
    assert ok.json()["remaining"] == len(new_codes)
    assert ok.json()["user"]["recovery_codes_remaining"] == len(new_codes)

    # 旧码整组作废
    old = _use_code(client, codes[0])
    assert old.status_code == 401
    # 新码可用
    fresh = _use_code(client, new_codes[0])
    assert fresh.status_code == 200
    assert fresh.json()["recovery_codes_remaining"] == len(new_codes) - 1


def test_regenerate_requires_enrolled_mfa(db, client):
    """未绑定第二因子时恢复码没有意义（只有一道口令），发了是安全负债。"""
    _mk_user(db)
    token = _login(client).json()["token"]
    r = client.post(f"{API}/auth/recovery-codes/regenerate",
                    headers=_hdr(token), json={"password": PWD})
    assert r.status_code == 400
    assert "动态口令" in r.json()["detail"]


# ---------------------------------------------------------------- 失效面

def test_disable_clears_recovery_codes(db, client):
    """解绑第二因子后恢复码必须一并清空，否则旧码能绕过新验证器。"""
    _mk_user(db)
    token, _codes = _enroll(client)
    r = client.post(f"{API}/auth/totp/disable", headers=_hdr(token),
                    json={"password": PWD})
    assert r.status_code == 200
    assert r.json()["user"]["recovery_codes_remaining"] == 0
    db.expire_all()
    u = db.query(User).one()
    assert u.recovery_codes == "" and u.totp_secret == ""
    # 解绑后只剩口令一道因子：登录不再要挑战票据
    assert _login(client, "alice").json().get("mfa_required") is not True


def test_admin_reset_drops_recovery_codes(db, client):
    _mk_user(db, username="root", roles=["admin"], clearance=3,
             password="Adm1n-Passw0rd!2026")
    victim = _mk_user(db, username="bob")
    _, codes = _enroll(client, "bob")

    admin_token = _login(client, "root", "Adm1n-Passw0rd!2026").json()["token"]
    r = client.post(f"{API}/admin/users/{victim.id}/mfa-reset",
                    headers=_hdr(admin_token))
    assert r.status_code == 200
    assert r.json()["was_enrolled"] is True
    assert r.json()["recovery_codes_dropped"] == len(codes)
    db.expire_all()
    assert db.get(User, victim.id).recovery_codes == ""
