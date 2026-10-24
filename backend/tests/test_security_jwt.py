# SPDX-License-Identifier: Apache-2.0
"""JWT 密钥运维必配单测（#10）。

覆盖三层：
  · _resolve_secrets 三态 —— 固定密钥直通 / 空且 ENFORCE 拒绝启动 /
    空且非 ENFORCE 告警并生成进程级随机密钥（两次结果不同）
  · health 的 jwt_secret 信号两态 —— configured / ephemeral
    （JWT_SECRET_OLD 单独存在不算 configured：签发只认新密钥）
  · 轮换口径 —— JWT_SECRET_OLD 只参与验证，create_token 只用 _SECRETS[0]
"""
import jwt
import pytest
from fastapi.testclient import TestClient

from app import security
from app.main import app

# 不走 lifespan（不起后台消费线程、不建库）：health 与 _resolve_secrets
# 都是纯函数路径，TestClient 仅作 ASGI 调用壳。
client = TestClient(app)

NEW = "n" * 32
OLD = "o" * 32


class _FakeUser:
    """create_token 只要 .id / .username，不必连库。"""

    id = "u-1"
    username = "tester"


# ---------------------------------------------------------------------------
# _resolve_secrets：三态
# ---------------------------------------------------------------------------


def test_resolve_secrets_returns_fixed_secret(monkeypatch):
    monkeypatch.setattr(security, "JWT_SECRET", NEW)
    monkeypatch.setattr(security, "JWT_SECRET_OLD", "")
    assert security._resolve_secrets() == [NEW]


def test_resolve_secrets_orders_new_before_old(monkeypatch):
    """新密钥在前（签发用它），旧密钥在后（只兜验证）。"""
    monkeypatch.setattr(security, "JWT_SECRET", NEW)
    monkeypatch.setattr(security, "JWT_SECRET_OLD", OLD)
    assert security._resolve_secrets() == [NEW, OLD]


def test_resolve_secrets_missing_enforced_refuses_startup(monkeypatch):
    monkeypatch.setattr(security, "JWT_SECRET", "")
    monkeypatch.setattr(security, "JWT_SECRET_OLD", "")
    monkeypatch.setattr(security, "ENFORCE_JWT_SECRET", True)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        security._resolve_secrets()


def test_resolve_secrets_missing_not_enforced_warns_and_randomizes(monkeypatch):
    """默认态：告警 + 进程级随机密钥。每次调用结果不同——重启即换密钥，
    "忘配固定密钥"从安全事故降级为可用性问题（重启后需重新登录）。"""
    monkeypatch.setattr(security, "JWT_SECRET", "")
    monkeypatch.setattr(security, "JWT_SECRET_OLD", "")
    monkeypatch.setattr(security, "ENFORCE_JWT_SECRET", False)
    with pytest.warns(RuntimeWarning, match="JWT_SECRET"):
        first = security._resolve_secrets()
    with pytest.warns(RuntimeWarning, match="JWT_SECRET"):
        second = security._resolve_secrets()
    assert len(first) == 1
    assert len(first[0]) == 64          # os.urandom(32).hex()
    assert first != second


# ---------------------------------------------------------------------------
# health：jwt_secret 信号两态
# ---------------------------------------------------------------------------


def test_health_reports_configured(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "JWT_SECRET", "fixed-secret-for-probe")
    body = client.get("/api/v1/health").json()
    assert body["jwt_secret"] == "configured"


def test_health_reports_ephemeral(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "JWT_SECRET", "")
    body = client.get("/api/v1/health").json()
    assert body["jwt_secret"] == "ephemeral"


def test_health_old_secret_alone_is_not_configured(monkeypatch):
    """轮换过渡期只配了 OLD：签发密钥仍然缺失 → ephemeral。"""
    from app import config

    monkeypatch.setattr(config, "JWT_SECRET", "")
    monkeypatch.setattr(config, "JWT_SECRET_OLD", OLD)
    body = client.get("/api/v1/health").json()
    assert body["jwt_secret"] == "ephemeral"


def test_health_never_leaks_secret_value(monkeypatch):
    from app import config

    monkeypatch.setattr(config, "JWT_SECRET", "top-secret-value")
    body = client.get("/api/v1/health").json()
    assert "top-secret-value" not in str(body)


# ---------------------------------------------------------------------------
# 轮换口径：OLD 只验证不签发
# ---------------------------------------------------------------------------


def test_old_secret_verifies_but_never_signs(monkeypatch):
    monkeypatch.setattr(security, "_SECRETS", [NEW, OLD])

    # 签发：用的是 _SECRETS[0]（新密钥），旧密钥解不开
    token = security.create_token(_FakeUser())
    assert security.decode_token(token)["username"] == "tester"
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, OLD, algorithms=["HS256"])
    jwt.decode(token, NEW, algorithms=["HS256"])  # 新密钥可解 = 签发用新密钥

    # 验证：轮换窗口内旧密钥签发的 token 仍有效（无缝轮换）
    legacy = jwt.encode({"sub": "u-1", "username": "tester"}, OLD, algorithm="HS256")
    assert security.decode_token(legacy)["username"] == "tester"
