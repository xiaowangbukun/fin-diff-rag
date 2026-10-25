# SPDX-License-Identifier: Apache-2.0
"""密钥托管（P0-5）：终止"密钥只以明文躺在 .env 里"这一状态。

验收口径（金融机构常见要求）：
  · 密钥可由 KMS / Vault / 密封卷在启动时注入，应用不落盘密钥；
  · 托管源一旦启用，**不允许静默回落**到环境变量明文——"以为在托管、
    实际在用明文"是最坏的一种状态，因为它连告警都不产生；
  · 取不到关键密钥就**拒绝启动**，而不是运行到半夜才因签名失败报 401。

file / http 两个适配器都不引入新依赖（urllib + pathlib），因此测试可以用
临时目录与本地 HTTP 服务完整覆盖，不需要起 Vault。
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import secrets_provider as sp

KEY = "K" * 32


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("SECRETS_PROVIDER", "SECRETS_DIR", "SECRETS_URL",
                 "SECRETS_TOKEN", "SECRETS_TTL", "REQUIRE_SECRETS_PROVIDER",
                 "SECRETS_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)
    sp.reset_cache()
    yield
    sp.reset_cache()


# ---------------------------------------------------------------- 来源探测


def test_auto_provider_is_none_without_config():
    assert sp.provider_name() == "none"
    assert sp.fetch("JWT_SECRET") is None


def test_auto_prefers_file_then_http(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    assert sp.provider_name() == "file"
    monkeypatch.setenv("SECRETS_URL", "http://127.0.0.1:1")
    assert sp.provider_name() == "file"      # file 优先（本地密封卷最可靠）
    monkeypatch.delenv("SECRETS_DIR")
    assert sp.provider_name() == "http"


def test_explicit_unknown_provider_degrades_to_none(monkeypatch):
    monkeypatch.setenv("SECRETS_PROVIDER", "vault-pro")
    assert sp.provider_name() == "none"


# ---------------------------------------------------------------- file 适配器


def test_file_plain_value(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "JWT_SECRET").write_text(KEY + "\n", encoding="utf-8")
    assert sp.resolve("JWT_SECRET", "from-env") == KEY
    assert sp.provenance()["JWT_SECRET"] == "file"


def test_file_lowercase_and_dash_variants(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "jwt-secret").write_text(KEY, encoding="utf-8")
    assert sp.fetch("JWT_SECRET") == KEY


def test_file_name_value_format_is_not_used_verbatim(monkeypatch, tmp_path):
    """`JWT_SECRET=xxx` 单行格式必须剥掉 key 名，否则签名全错且极难排查。"""
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "JWT_SECRET").write_text("JWT_SECRET=abc123\n", encoding="utf-8")
    assert sp.fetch("JWT_SECRET") == "abc123"


def test_file_empty_is_treated_as_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "JWT_SECRET").write_text("   \n", encoding="utf-8")
    assert sp.fetch("JWT_SECRET") is None


def test_missing_secret_does_not_fall_back_to_env(monkeypatch, tmp_path):
    """托管源启用但缺这个密钥 → 返回空串（绝不悄悄用明文 .env 顶上）。"""
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    assert sp.resolve("JWT_SECRET", KEY) == ""
    assert sp.provenance()["JWT_SECRET"] == "missing"


def test_no_provider_keeps_env_default():
    assert sp.resolve("JWT_SECRET", KEY) == KEY
    assert sp.provenance()["JWT_SECRET"] == "env"


# ---------------------------------------------------------------- http 适配器


class _Handler(BaseHTTPRequestHandler):
    payload: dict = {}
    seen_tokens: list = []

    def do_GET(self):  # noqa: N802
        _Handler.seen_tokens.append(
            (self.path, self.headers.get("X-Vault-Token", "")))
        body = _Handler.payload.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):  # 静音测试输出
        return


@pytest.fixture
def vault(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("SECRETS_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("SECRETS_TOKEN", "tok-abc")
    _Handler.payload = {}
    _Handler.seen_tokens = []
    yield _Handler
    srv.shutdown()
    srv.server_close()


def test_http_flat_value(vault):
    vault.payload["/v1/secret/JWT_SECRET"] = {"value": KEY}
    assert sp.fetch("JWT_SECRET") == KEY
    assert vault.seen_tokens[0] == ("/v1/secret/JWT_SECRET", "tok-abc")


def test_http_vault_kv_v2_shape(vault):
    vault.payload["/v1/secret/JWT_SECRET"] = {"data": {"value": KEY}}
    assert sp.fetch("JWT_SECRET") == KEY


def test_http_falls_back_to_lowercase_path(vault):
    vault.payload["/v1/secret/jwt_secret"] = {"value": KEY}
    assert sp.fetch("JWT_SECRET") == KEY


def test_http_missing_returns_none_and_no_env_fallback(monkeypatch, vault):
    assert sp.resolve("JWT_SECRET", KEY) == ""


def test_http_unreachable_returns_none(monkeypatch):
    monkeypatch.setenv("SECRETS_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("SECRETS_TIMEOUT", "1")
    assert sp.fetch("JWT_SECRET") is None


# ---------------------------------------------------------------- 缓存 / 启动自检


def test_value_is_cached_within_ttl(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "JWT_SECRET").write_text("first", encoding="utf-8")
    assert sp.fetch("JWT_SECRET") == "first"
    (tmp_path / "JWT_SECRET").write_text("second", encoding="utf-8")
    # TTL 内命中缓存（避免每请求打 KMS）
    assert sp.fetch("JWT_SECRET") == "first"
    sp.reset_cache()
    assert sp.fetch("JWT_SECRET") == "second"


def test_expired_cache_refetches(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.setenv("SECRETS_TTL", "0")
    (tmp_path / "JWT_SECRET").write_text("first", encoding="utf-8")
    assert sp.fetch("JWT_SECRET") == "first"
    (tmp_path / "JWT_SECRET").write_text("second", encoding="utf-8")
    assert sp.fetch("JWT_SECRET") == "second"


def test_require_provider_off_by_default(monkeypatch):
    sp.require_provider(("JWT_SECRET",))   # 不应抛


def test_require_provider_rejects_when_unconfigured(monkeypatch):
    monkeypatch.setenv("REQUIRE_SECRETS_PROVIDER", "true")
    with pytest.raises(RuntimeError) as exc:
        sp.require_provider(("JWT_SECRET",))
    assert "未配置密钥托管源" in str(exc.value)


def test_require_provider_rejects_when_secret_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("REQUIRE_SECRETS_PROVIDER", "true")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    sp.resolve("JWT_SECRET")
    with pytest.raises(RuntimeError) as exc:
        sp.require_provider(("JWT_SECRET",))
    assert "缺少 JWT_SECRET" in str(exc.value)


def test_require_provider_passes_when_all_resolved(monkeypatch, tmp_path):
    monkeypatch.setenv("REQUIRE_SECRETS_PROVIDER", "yes")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    (tmp_path / "JWT_SECRET").write_text(KEY, encoding="utf-8")
    sp.resolve("JWT_SECRET")
    sp.require_provider(("JWT_SECRET",))    # 不应抛
