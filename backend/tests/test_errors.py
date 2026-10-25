# SPDX-License-Identifier: AGPL-3.0-only
"""errors.py —— A4 HTTP 错误语义单元测试（503/500 全局映射 + 4xx 不被动用）。

背景：A4 新增 `app/errors.py` 并在 `app/main.py` 注册了四个全局异常处理器。
这是**新代码路径**，交付方未附任何测试，本文件补齐三条契约：

  1. ServiceUnavailable / OperationalError / InterfaceError → 503 +
     `Retry-After: 30` + JSON 体含 `dependency`（显式 raise 与冒泡两种来源）；
  2. 未捕获异常 → 500 + JSON 体 + **完整堆栈进日志**（caplog 实证）；
  3. 既有 4xx（401/403/404/409/429）语义与之前完全一致——全局处理器
     只接管 503/500，不碰 HTTPException 既有行为。

打法说明：
  · 503/500 走**真实 app**（app.main:app）+ `dependency_overrides` 让依赖
    抛出目标异常，证明的是 main.py 的注册确实生效，而不是处理器函数本身；
  · 4xx 用例同样打真实端点，证明全局注册没有顺手改掉它们；
  · webhook/embedding/LLM 的超时→ServiceUnavailable 接线单独用
    monkeypatch 实证（embed/llm 两个上游共用 dependency_timeout 工厂）。
"""
import logging

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import InterfaceError, OperationalError

from app.errors import (
    RETRY_AFTER_SECONDS,
    ServiceUnavailable,
    dependency_timeout,
    internal_error_handler,
    service_unavailable_handler,
)
from app.main import app as real_app
from app.security import create_token

DOCS_PREFIX = "/api/docs"
ADMIN_PREFIX = "/api/admin"


# ------------------------------------------------------------------ 夹具


@pytest.fixture
def client():
    """打真实 app 的测试客户端（不起服务、不走 lifespan）。

    表结构由 conftest 的 db 夹具负责；app 的 get_db 用的是同一个引擎
    （conftest 已把 DATABASE_URL 重定向到临时库），因此客户端请求
    与用例里 Session 看到的是同一份数据。
    """
    return TestClient(real_app)


@pytest.fixture
def overrides():
    """dependency_overrides 快照式夹具：用完即还原，不污染其他用例。"""
    saved = dict(real_app.dependency_overrides)
    real_app.dependency_overrides.clear()
    yield real_app.dependency_overrides
    real_app.dependency_overrides.clear()
    real_app.dependency_overrides.update(saved)


@pytest.fixture
def user(db):
    """一个普通（非 admin）就绪用户，返回 (User, token)。"""
    from app.models import User, new_id

    u = User(
        id=new_id(), username="qa_user", display_name="qa_user",
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
        id=new_id(), username="qa_admin", display_name="qa_admin",
        clearance=3, roles='["admin"]', pwd_hash="x", salt="y", status=True,
    )
    db.add(u)
    db.commit()
    return u, create_token(u)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ 注册契约


class TestHandlerRegistration:
    """main.py 的注册本身就是契约：漏注册 = 503/500 映射整个不生效。"""

    def test_main_registers_all_four_handlers(self):
        handlers = real_app.exception_handlers
        assert handlers.get(ServiceUnavailable) is service_unavailable_handler
        assert handlers.get(OperationalError) is service_unavailable_handler
        assert handlers.get(InterfaceError) is service_unavailable_handler
        assert handlers.get(Exception) is internal_error_handler


# ------------------------------------------------------------------ 503 映射


class TestServiceUnavailableMapping:
    """下游不可用 → 503 + Retry-After + dependency 归因。"""

    def test_operational_error_bubbling_to_503(self, client, overrides, user):
        """数据库连接类异常未经转换冒到 ASGI 层 → 503（database 归因）。"""
        from app.db import get_db

        _, token = user

        def _boom():
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))
            yield  # pragma: no cover  让 FastAPI 认得这是生成器依赖

        overrides[get_db] = _boom
        r = client.get(f"{DOCS_PREFIX}/whatever", headers=_auth(token))
        assert r.status_code == 503
        assert r.headers["Retry-After"] == str(RETRY_AFTER_SECONDS) == "30"
        body = r.json()
        assert body["dependency"] == "database"
        assert "数据库" in body["detail"]

    def test_interface_error_to_503(self, client, overrides, user):
        from app.db import get_db

        _, token = user

        def _boom():
            raise InterfaceError("SELECT 1", {}, Exception("socket closed"))
            yield  # pragma: no cover

        overrides[get_db] = _boom
        r = client.get(f"{DOCS_PREFIX}/whatever", headers=_auth(token))
        assert r.status_code == 503
        assert r.json()["dependency"] == "database"

    def test_explicit_service_unavailable_honors_custom_retry_after(
            self, client, overrides, user):
        """显式 raise 的 ServiceUnavailable：自定义 retry_after 与 dependency
        必须原样进响应——网关按这个头算退避。"""
        from app.security import current_user

        _, token = user

        def _raise_su():
            raise ServiceUnavailable(
                "向量嵌入服务维护中", dependency="embedding", retry_after=7)

        overrides[current_user] = _raise_su
        r = client.get(f"{DOCS_PREFIX}/whatever", headers=_auth(token))
        assert r.status_code == 503
        assert r.headers["Retry-After"] == "7"
        assert r.json() == {
            "detail": "向量嵌入服务维护中", "dependency": "embedding"}

    def test_retry_after_is_clamped_to_at_least_one_second(self):
        """retry_after <= 0 没有意义（客户端会立即重试，放大故障）。"""
        exc = ServiceUnavailable("x", retry_after=0)
        assert exc.retry_after == 1
        exc = ServiceUnavailable("x", retry_after=-5)
        assert exc.retry_after == 1

    def test_dependency_timeout_factory_contract(self):
        exc = dependency_timeout("embedding", "向量嵌入", 60)
        assert isinstance(exc, ServiceUnavailable)
        assert exc.dependency == "embedding"
        assert exc.retry_after == RETRY_AFTER_SECONDS
        assert "60" in exc.detail and "向量嵌入" in exc.detail


# ------------------------------------------------------------------ 500 映射


class TestInternalErrorMapping:
    """未捕获异常 → 500 + JSON + 完整堆栈入日志。"""

    def test_uncaught_exception_500_with_full_traceback_in_log(
            self, client, overrides, user, caplog):
        from app.security import current_user

        _, token = user

        def _boom():
            raise RuntimeError("未预期的内部错误-QA探针")

        overrides[current_user] = _boom
        with caplog.at_level(logging.ERROR, logger="finrag.errors"):
            # raise_server_exceptions=False：让 ServerErrorMiddleware 走
            # internal_error_handler 返回 500，而不是把异常抛回测试。
            r = TestClient(real_app, raise_server_exceptions=False).get(
                f"{DOCS_PREFIX}/whatever", headers=_auth(token))
        assert r.status_code == 500
        assert r.json() == {"detail": "服务器内部错误，请联系管理员"}
        # 堆栈必须落在应用自己的日志里（不依赖 uvicorn 配置）
        assert "Traceback" in caplog.text
        assert "RuntimeError" in caplog.text
        assert "未预期的内部错误-QA探针" in caplog.text


# ------------------------------------------------------------------ 4xx 不被动用


class TestFourXXUnchanged:
    """全局处理器只接管 503/500；既有 4xx 行为必须逐码位证明没变。"""

    def test_401_without_token(self, client):
        r = client.get(f"{DOCS_PREFIX}/whatever")
        assert r.status_code == 401

    def test_401_with_garbage_token(self, client):
        r = client.get(f"{DOCS_PREFIX}/whatever",
                       headers=_auth("not-a-jwt"))
        assert r.status_code == 401

    def test_403_non_admin_on_admin_endpoint(self, client, user):
        _, token = user
        r = client.get(f"{ADMIN_PREFIX}/users", headers=_auth(token))
        assert r.status_code == 403

    def test_404_unknown_doc_is_masked(self, client, user):
        """越权/不存在同形 404：响应体不得泄露存在性线索。"""
        _, token = user
        r = client.get(f"{DOCS_PREFIX}/00000000-0000-0000-0000-000000000000",
                       headers=_auth(token))
        assert r.status_code == 404
        assert r.json()["detail"] == "文档不存在"

    def test_409_duplicate_username(self, client, admin, user, db):
        """重名建用户 → 409（IntegrityError 之外的请求撞车，不是 503）。"""
        _, admin_token = admin
        qa_user, _ = user
        r = client.post(
            f"{ADMIN_PREFIX}/users",
            headers=_auth(admin_token),
            json={"username": qa_user.username, "password": "Fin@123456"},
        )
        assert r.status_code == 409

    def test_429_full_read_limit(self, client, user, db, monkeypatch):
        """防拼图全篇直读上限 → 429：证明 jigsaw 闸没被全局处理器碰过。"""
        from app import jigsaw
        from app.models import ExposureLedger, new_id

        u, token = user
        # 显式造一篇 open + 公开级文档，保证 can_access 放行、只撞 429 闸
        from app.models import Document

        d = Document(id=new_id(), title="429探针文档", clearance=0,
                     acl_mode="open", status="ready", doc_type="txt")
        db.add(d)
        db.flush()
        row = ExposureLedger(
            id=new_id(), user_id=u.id, doc_id=d.id,
            window_key=jigsaw._window_key(),
            full_read_count=jigsaw.JIGSAW_FULLREAD_LIMIT,
        )
        db.add(row)
        db.commit()
        r = client.get(f"{DOCS_PREFIX}/{d.id}", headers=_auth(token))
        assert r.status_code == 429


# ------------------------------------------------------------------ 上游接线


class TestUpstreamTimeoutWiring:
    """embed / llm 配了远端却超时 → ServiceUnavailable（不静默降级）。"""

    def test_embed_timeout_raises_service_unavailable(self, monkeypatch):
        from app import embed

        # 卸掉 conftest autouse 的 fake `_remote`（实例属性），回到类方法，
        # 否则 httpx.post 的模拟根本走不到——测的是真实远端超时路径。
        embed.embedder.__dict__.pop("_remote", None)

        def _boom(*a, **k):
            raise httpx.TimeoutException("simulated timeout")

        monkeypatch.setattr(embed.httpx, "post", _boom)
        monkeypatch.setattr(embed.embedder, "api_mode", True)
        with pytest.raises(ServiceUnavailable) as ei:
            embed.embedder.embed(["超时探针"])
        assert ei.value.dependency == "embedding"
        assert "向量嵌入" in ei.value.detail
        assert ei.value.retry_after == RETRY_AFTER_SECONDS

    def test_llm_timeout_raises_service_unavailable(self, monkeypatch):
        from app import llm

        def _boom(*a, **k):
            raise httpx.TimeoutException("simulated timeout")

        monkeypatch.setattr(llm.httpx, "post", _boom)
        monkeypatch.setattr(llm, "LLM_API_KEY", "sk-fake")
        with pytest.raises(ServiceUnavailable) as ei:
            llm._chat_remote("sys", "user")
        assert ei.value.dependency == "llm"
        assert "大模型" in ei.value.detail
