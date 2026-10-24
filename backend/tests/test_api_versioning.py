# SPDX-License-Identifier: Apache-2.0
"""API 版本化契约测试（#5：/api/v1 现行契约 + /api deprecated 别名）。

背景：router 前缀去掉 `/api` 段后，由 main.py 对同一 router 对象
`include_router` 两次（/api/v1 与 /api）。fastapi 0.143 的 include_router
是惰性挂载（`_IncludedRouter`），`app.routes` 枚举不到被包含的路由——
本文件全部用 TestClient 打真实请求，不枚举 app.routes（那是测量假象）。

钉住三条契约：
  1. **双前缀等价**：v1 与别名对同一端点返回相同状态码与语义；
  2. **OpenAPI 双份路径**：v1 与别名都出现在 /openapi.json，且不存在
     无前缀路径（刻意行为，见 README「六之四、API 版本与兼容策略」）；
  3. **新端点自身边界**：POST /admin/metrics/cleanup 的 403/200 与留痕。

注意：main.py 的 health 也双注册（/api/health 与 /api/v1/health），
同样在此覆盖——漏注册任何一半都是破坏性变更。
另注意：frontend/dist 存在时 SPA 回退会把任意非 /api 的 404 扮成
index.html 200，所以"无前缀路径已收敛"只能靠 OpenAPI spec 断言。
"""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import metrics
from app.audit import flush_audit
from app.main import app as real_app
from app.models import AuditLog
from app.security import create_token


@pytest.fixture
def client():
    """打真实 app 的测试客户端（不起服务、不走 lifespan）。

    表结构由 conftest 的 db 夹具负责；app 的 get_db 用的是同一个引擎
    （conftest 已把 DATABASE_URL 重定向到临时库），因此客户端请求
    与用例里 Session 看到的是同一份数据。
    """
    return TestClient(real_app)


@pytest.fixture
def user(db):
    """一个普通（非 admin）就绪用户，返回 (User, token)。"""
    from app.models import User, new_id

    u = User(
        id=new_id(), username="ver_user", display_name="ver_user",
        clearance=1, roles="[]", pwd_hash="x", salt="y", status=True,
    )
    db.add(u)
    db.commit()
    return u, create_token(u)


@pytest.fixture
def admin(db):
    """一个 admin 角色用户，返回 (User, token)。"""
    from app.models import User, new_id

    u = User(
        id=new_id(), username="ver_admin", display_name="ver_admin",
        clearance=3, roles='["admin"]', pwd_hash="x", salt="y", status=True,
    )
    db.add(u)
    db.commit()
    return u, create_token(u)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ 双前缀等价


class TestDualPrefixEquivalence:
    """/api/v1 与 /api 对同一端点必须同结果——别名是兼容承诺，不是摆设。"""

    def test_health_on_both_prefixes(self, client):
        r1 = client.get("/api/v1/health")
        r2 = client.get("/api/health")
        assert r1.status_code == r2.status_code == 200
        assert r1.json() == r2.json()
        assert r1.json()["ok"] is True

    def test_login_validation_error_on_both(self, client):
        """缺字段 → 422（pydantic 校验），两个前缀一致。"""
        r1 = client.post("/api/v1/auth/login", json={})
        r2 = client.post("/api/auth/login", json={})
        assert r1.status_code == r2.status_code == 422

    def test_docs_requires_auth_on_both(self, client):
        r1 = client.get("/api/v1/docs")
        r2 = client.get("/api/docs")
        assert r1.status_code == r2.status_code == 401

    def test_admin_stats_requires_auth_on_both(self, client):
        r1 = client.get("/api/v1/admin/stats")
        r2 = client.get("/api/admin/stats")
        assert r1.status_code == r2.status_code == 401

    def test_admin_daily_report_requires_admin_on_both(self, client, user):
        _, token = user
        r1 = client.get("/api/v1/admin/report/daily", headers=_auth(token))
        r2 = client.get("/api/admin/report/daily", headers=_auth(token))
        assert r1.status_code == r2.status_code == 403

    def test_openapi_lists_both_prefixes(self, client):
        """双份路径在 OpenAPI 里重复出现是刻意行为（别名至少一个 minor 版本后才移除）。"""
        paths = client.get("/openapi.json").json()["paths"]
        for suffix in ("/auth/login", "/admin/report/daily", "/admin/metrics",
                       "/admin/metrics/cleanup", "/health"):
            assert f"/api/v1{suffix}" in paths, f"v1 缺 {suffix}"
            assert f"/api{suffix}" in paths, f"别名缺 {suffix}"

    def test_no_unprefixed_api_paths(self, client):
        """无前缀路径（/auth/login 这类旧形态）已全部收敛。

        SPA 回退会把任意非 /api 的 404 扮成 index.html 200，状态码测不出来，
        只能断言 OpenAPI spec 里不存在非 /api/ 开头的路径。
        """
        paths = client.get("/openapi.json").json()["paths"]
        bad = [p for p in paths if not p.startswith("/api/")]
        assert bad == []


# ------------------------------------------------------------------ 清理端点（#6）


class TestMetricsCleanupEndpoint:
    """POST /admin/metrics/cleanup：只删 reports/*.md，且必须留痕。"""

    def test_cleanup_requires_admin(self, client, user):
        _, token = user
        r = client.post("/api/v1/admin/metrics/cleanup", headers=_auth(token))
        assert r.status_code == 403

    def test_cleanup_requires_auth(self, client):
        r = client.post("/api/v1/admin/metrics/cleanup")
        assert r.status_code == 401

    def test_cleanup_deletes_expired_report(self, client, admin,
                                           tmp_path, monkeypatch):
        _, token = admin
        monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
        old = tmp_path / "2000-01-01.md"
        keep = tmp_path / f"{datetime.utcnow():%Y-%m-%d}.md"
        old.write_text("旧", encoding="utf-8")
        keep.write_text("新", encoding="utf-8")

        r = client.post("/api/v1/admin/metrics/cleanup",
                        params={"days": 30}, headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["deleted"] == ["2000-01-01.md"]
        assert body["kept"] == 1
        assert not old.exists()
        assert keep.exists()

    def test_cleanup_missing_dir_returns_empty(self, client, admin,
                                              tmp_path, monkeypatch):
        _, token = admin
        target = tmp_path / "reports"
        monkeypatch.setattr(metrics, "REPORTS_DIR", target, raising=False)

        r = client.post("/api/v1/admin/metrics/cleanup", headers=_auth(token))
        assert r.status_code == 200
        assert r.json() == {
            "days": metrics.config.METRICS_RETENTION_DAYS,
            "deleted": [], "kept": 0, "unparsable": 0,
        }
        # 清理不创建目录
        assert not target.exists()

    def test_cleanup_writes_audit_trail(self, client, admin, db,
                                       tmp_path, monkeypatch):
        """清理是破坏性操作，必须进审计链（target_label 带保留天数）。"""
        _, token = admin
        monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)

        r = client.post("/api/v1/admin/metrics/cleanup",
                        params={"days": 30}, headers=_auth(token))
        assert r.status_code == 200

        flush_audit(timeout=2.0)
        rows = db.execute(
            select(AuditLog).where(AuditLog.action == "metrics_cleanup")
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].username == "ver_admin"
        assert "保留 30 天" in (rows[0].target_label or "")
        assert "清理过期日报 0 份" in (rows[0].reason or "")

    def test_cleanup_on_deprecated_alias_too(self, client, admin,
                                            tmp_path, monkeypatch):
        """别名端点同样可用（兼容承诺覆盖新端点，不只是老端点）。"""
        _, token = admin
        monkeypatch.setattr(metrics, "REPORTS_DIR", tmp_path, raising=False)
        r = client.post("/api/admin/metrics/cleanup",
                        params={"days": 30}, headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["deleted"] == []


# ------------------------------------------------------------------ 健康检查契约


def test_health_reports_storage_and_embed_mode(client):
    """/api/v1/health 的载荷字段是运维探针的依赖，不能静默增减。"""
    body = client.get("/api/v1/health").json()
    assert {"ok", "storage", "embed_mode", "llm_ready"} <= set(body)
