# SPDX-License-Identifier: AGPL-3.0-only
"""启动安全姿态自检（app/security_posture.py）。

这组用例守的不是"报告能打印"，而是**结论的方向性**：
  · 关掉一条防线 → 必须 FAIL（而不是 INFO 糊过去）；
  · 需要按部署形态确认的项 → 必须 WARN，且给出可执行的环境变量建议；
  · 生产口径全开时 production_ready 必须为 True（否则清单永远清不零，运维会
    学会忽略它——和审计告警被噪声淹没是同一类失效）；
  · STRICT_SECURITY_POSTURE=true 且有 WARN/FAIL 时，启动必须直接拒绝。

值全部通过 monkeypatch `app.config` 模块属性注入：姿态模块按名字取值，
不重载进程就能构造"某个部署组合"。
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import config, security_posture
from app.main import app as real_app
from app.models import User, new_id
from app.security import hash_password
from app.security_posture import FAIL, OK, WARN, assess, evaluate_and_report, summarize

API = "/api/v1"

# 生产口径（WARN/FAIL 应全部消失）。每条都对应一个真实环境变量。
PRODUCTION_ENV = {
    "SECURITY_HEADERS": True,
    "JIGSAW_ENABLED": True,
    "INTENT_ENABLED": True,
    "FAIL_SECURE_ENABLED": True,
    "AUDIT_APPEND_ONLY": True,
    "AUDIT_ANCHOR_EXTERNAL_FILE": "/secure/audit.ndjson",
    "AUDIT_ANCHOR_URL": "",
    "JWT_SECRET": "x" * 48,
    "AUTH_COOKIE_MODE": True,
    "MFA_ENABLED": True,
    "MFA_ENFORCE_ADMIN": True,
    "MFA_ENFORCE_ALL": False,
    "OIDC_CLAIM_SYNC": False,
    "OIDC_CLAIM_SYNC_UNKNOWN": "ignore",
    "TRUST_PROXY_HEADERS": False,
    "FORCE_HTTPS": True,
    "HSTS_SECONDS": 31536000,
    "TRUSTED_HOSTS": "rag.example.com",
    "DISABLE_DOCS": True,
    "SECRETS_PROVIDER": "file",
    "SECRETS_DIR": "/run/secrets",
    "REQUIRE_SECRETS_PROVIDER": True,
    "REQUIRE_DB_TLS": True,
    "DATABASE_URL": "postgresql+psycopg://finrag:secret@10.0.0.9:5432/finrag?sslmode=require",
    "METRICS_ENABLED": True,
    "STRICT_SECURITY_POSTURE": False,
}


def _apply(monkeypatch, **overrides):
    env = dict(PRODUCTION_ENV)
    env.update(overrides)
    for key, value in env.items():
        monkeypatch.setattr(config, key, value, raising=False)


def _by_key(findings):
    return {f.key: f for f in findings}


@pytest.fixture
def prod(monkeypatch):
    _apply(monkeypatch)
    return monkeypatch


# ------------------------------------------------------------------ 方向性


def test_production_posture_is_clean(prod):
    """生产口径全开时清单必须清零——否则运维迟早学会忽略它。"""
    findings = assess()
    s = summarize(findings)
    assert s["counts"][WARN] == 0, [f.key for f in findings if f.level == WARN]
    assert s["counts"][FAIL] == 0, [f.key for f in findings if f.level == FAIL]
    assert s["production_ready"] is True
    # 关键防线必须有明确的 OK 结论（不是"没提"）
    keys = _by_key(findings)
    for key in ("SECURITY_HEADERS", "JIGSAW_ENABLED", "INTENT_ENABLED",
                "FAIL_SECURE_ENABLED", "AUDIT_APPEND_ONLY", "JWT_SECRET",
                "AUTH_COOKIE_MODE", "MFA_ENFORCE"):
        assert keys[key].level == OK, (key, keys[key].level)


@pytest.mark.parametrize("switch", [
    "SECURITY_HEADERS", "JIGSAW_ENABLED", "INTENT_ENABLED",
    "FAIL_SECURE_ENABLED", "AUDIT_APPEND_ONLY",
])
def test_core_defence_switched_off_is_fail(prod, switch):
    """这五个开关一关就等于从产品里删掉一条防线，必须是 FAIL 而非 WARN。"""
    prod.setattr(config, switch, False)
    item = _by_key(assess())[switch]
    assert item.level == FAIL, (switch, item)
    assert item.fix, "FAIL 必须给出整改方式，否则运维无从下手"


def test_missing_jwt_secret_is_fail(prod):
    """随机密钥 = 重启掉线 + 多 worker 间歇 401，且没有任何症状指向配置。"""
    prod.setattr(config, "JWT_SECRET", "")
    item = _by_key(assess())["JWT_SECRET"]
    assert item.level == FAIL
    assert "JWT_SECRET" in item.fix


def test_metrics_off_is_warn_with_remediation(prod):
    prod.setattr(config, "METRICS_ENABLED", False)
    item = _by_key(assess())["METRICS_ENABLED"]
    assert item.level == WARN
    assert "METRICS_ENABLED=true" in item.fix


def test_mfa_available_but_not_enforced_is_warn(prod):
    prod.setattr(config, "MFA_ENFORCE_ADMIN", False)
    assert _by_key(assess())["MFA_ENFORCE_ADMIN"].level == WARN


def test_mfa_globally_off_is_warn(prod):
    prod.setattr(config, "MFA_ENABLED", False)
    assert _by_key(assess())["MFA_ENABLED"].level == WARN


def test_no_external_anchor_is_warn(prod):
    """只有本地锚点时，DB + 磁盘双写权限即可同步篡改而不被检出。"""
    prod.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    prod.setattr(config, "AUDIT_ANCHOR_URL", "")
    item = _by_key(assess())["AUDIT_ANCHOR_EXTERNAL"]
    assert item.level == WARN
    assert "AUDIT_ANCHOR_EXTERNAL_FILE" in item.fix


def test_oidc_unknown_claim_ignore_is_warn(prod):
    prod.setattr(config, "OIDC_CLAIM_SYNC", True)
    prod.setattr(config, "OIDC_CLAIM_SYNC_UNKNOWN", "ignore")
    assert _by_key(assess())["OIDC_CLAIM_SYNC_UNKNOWN"].level == WARN


def test_trust_proxy_headers_warns_even_when_enabled(prod):
    """这是双向风险：开启可被伪造，关闭则反代部署漏发 Cookie Secure。"""
    prod.setattr(config, "TRUST_PROXY_HEADERS", True)
    item = _by_key(assess())["TRUST_PROXY_HEADERS"]
    assert item.level == WARN
    assert "FORWARDED_ALLOW_IPS" in item.fix


def test_remote_db_without_tls_is_warn(prod):
    prod.setattr(config, "REQUIRE_DB_TLS", False)
    prod.setattr(config, "DATABASE_URL", "postgresql+psycopg://finrag:pw@10.0.0.9:5432/finrag")
    item = _by_key(assess())["DB_TLS"]
    assert item.level == WARN
    assert "sslmode" in item.fix


def test_local_db_without_tls_is_info(prod):
    """本机回环的明文链路是正常形态，不该被当成缺陷刷屏。"""
    prod.setattr(config, "REQUIRE_DB_TLS", False)
    prod.setattr(config, "DATABASE_URL", "postgresql+psycopg://finrag:pw@127.0.0.1:5432/finrag")
    item = _by_key(assess())["DB_TLS"]
    assert item.level not in (WARN, FAIL)


def test_db_host_is_extracted_without_leaking_password(prod):
    """报告里不能出现口令：只允许出现主机名。"""
    prod.setattr(config, "REQUIRE_DB_TLS", False)
    prod.setattr(config, "DATABASE_URL",
                 "postgresql+psycopg://finrag:sup3r-secret@db.internal:5432/finrag")
    text = security_posture.report(assess())
    assert "sup3r-secret" not in text
    assert "db.internal" in text


# ------------------------------------------------------------------ 严格模式


def test_strict_mode_refuses_to_start_when_warn_remains(prod, capsys):
    prod.setattr(config, "STRICT_SECURITY_POSTURE", True)
    prod.setattr(config, "METRICS_ENABLED", False)
    with pytest.raises(RuntimeError) as ei:
        evaluate_and_report()
    assert "METRICS_ENABLED" in str(ei.value)
    # 拒绝之前必须先把完整清单打印出来，否则运维不知道还差哪几条
    err = capsys.readouterr().err
    assert "启动安全姿态自检" in err
    assert "METRICS_ENABLED" in err


def test_strict_mode_starts_when_clean(prod):
    prod.setattr(config, "STRICT_SECURITY_POSTURE", True)
    assert evaluate_and_report()          # 不抛异常即通过


def test_default_mode_only_warns(prod):
    """默认不阻断：演示环境必须能起来（否则测试与本地联调全部失效）。"""
    prod.setattr(config, "STRICT_SECURITY_POSTURE", False)
    prod.setattr(config, "METRICS_ENABLED", False)
    findings = evaluate_and_report()
    assert any(f.key == "METRICS_ENABLED" and f.level == WARN for f in findings)


# ------------------------------------------------------------------ 管理端接口


@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username, password, roles, clearance=3):
    pwd, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles),
             pwd_hash=pwd, salt=salt, status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.commit()
    return u


def _token(client, username, password):
    r = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_admin_can_read_posture(db, client):
    """接口与启动日志同源：管理员应能看到同一份清单（含每条整改建议）。

    这里刻意**不**套 `prod` fixture：JWT 签发/校验用的是模块导入期取自
    config 的常量，中途 monkeypatch 会让登录令牌验不过，属于测试自伤。
    接口本身的正确性只依赖于"把 assess() 的结果原样返回"。
    """
    _mk_user(db, "posture_admin", "Adm1n-Passw0rd!2026", ["admin"])
    hdr = {"Authorization": f"Bearer {_token(client, 'posture_admin', 'Adm1n-Passw0rd!2026')}"}
    r = client.get(f"{API}/admin/security-posture", headers=hdr)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["findings"]) == sum(body["counts"].values())
    keys = {f["key"]: f for f in body["findings"]}
    # 决定性开关至少要有明确结论，且 FAIL 项必须带整改建议
    for key in ("AUDIT_APPEND_ONLY", "JIGSAW_ENABLED", "INTENT_ENABLED",
                "FAIL_SECURE_ENABLED", "SECURITY_HEADERS"):
        assert keys[key]["level"] == OK, (key, keys[key])
    for item in body["findings"]:
        if item["level"] == "FAIL":
            assert item["fix"], item
    assert body["production_ready"] == (body["counts"]["WARN"] == 0
                                        and body["counts"]["FAIL"] == 0)


def test_non_admin_cannot_read_posture(db, client):
    _mk_user(db, "posture_guest", "Gu3st-Passw0rd!2026", ["guest"], clearance=1)
    hdr = {"Authorization": f"Bearer {_token(client, 'posture_guest', 'Gu3st-Passw0rd!2026')}"}
    r = client.get(f"{API}/admin/security-posture", headers=hdr)
    assert r.status_code == 403
