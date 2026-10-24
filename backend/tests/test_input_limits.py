# SPDX-License-Identifier: Apache-2.0
"""输入质量边界单测（#9：schema 约束 + ingest 卡口 + 上传大小配置化）。

三层防线各司其职：
  · pydantic schema —— API 路径的超长/越界/空值 → 422（曾经的 PG DataError
    500 与 title[:255] 静默截断在这里变成明确错误）
  · ingest 卡口 —— 内部路径（重新入档表单 content 等）→ ValueError → 400
  · MAX_UPLOAD_MB —— 上传字节上限配置化（原两处硬编码 20MB）
"""
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import ingest
from app.config import MAX_DOC_CHARS
from app.ingest import ingest_document, reingest_document
from app.main import app
from app.routers.admin import UserIn
from app.schemas import ChatIn, DocCreateIn, DocUpdateIn, LoginIn
from app.security import create_token

client = TestClient(app)


def _auth(db, user):
    # user_factory 只 flush 不 commit——TestClient 的请求走新 session，
    # 看不到未提交数据（SQLite 跨连接不可见）。这里显式提交让用户"落地"。
    db.commit()
    return {"Authorization": f"Bearer {create_token(user)}"}


# ---------------------------------------------------------------------------
# LoginIn：长度约束（曾经的超长 username 在 PG 侧是 DataError 500）
# ---------------------------------------------------------------------------


def test_login_rejects_empty_username():
    with pytest.raises(ValidationError):
        LoginIn(username="", password="x" * 8)


def test_login_rejects_overlong_username():
    with pytest.raises(ValidationError):
        LoginIn(username="x" * 65, password="x" * 8)


def test_login_rejects_overlong_password():
    with pytest.raises(ValidationError):
        LoginIn(username="someone", password="x" * 257)


def test_login_api_returns_422_for_overlong_username():
    """API 级：无 token 也走得完 body 校验（login 无鉴权依赖）。"""
    r = client.post("/api/v1/auth/login",
                    json={"username": "x" * 65, "password": "whatever12"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# DocCreateIn / DocUpdateIn
# ---------------------------------------------------------------------------


def test_doc_create_rejects_empty_title():
    with pytest.raises(ValidationError):
        DocCreateIn(title="", content="正文")


def test_doc_create_rejects_overlong_title():
    with pytest.raises(ValidationError):
        DocCreateIn(title="标" * 201, content="正文")


def test_doc_create_rejects_empty_content():
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="")


def test_doc_create_rejects_overlong_content():
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="x" * (MAX_DOC_CHARS + 1))


def test_doc_create_clearance_bounds():
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="正文", clearance=4)
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="正文", clearance=-1)
    DocCreateIn(title="标题", content="正文", clearance=0)   # 边界值放行
    DocCreateIn(title="标题", content="正文", clearance=3)


def test_doc_create_rejects_overlong_tags_and_doctype():
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="正文", tags="t" * 201)
    with pytest.raises(ValidationError):
        DocCreateIn(title="标题", content="正文", doc_type="d" * 33)


def test_doc_update_rejects_empty_title_but_allows_none():
    with pytest.raises(ValidationError):
        DocUpdateIn(title="")
    DocUpdateIn(title=None)  # 不更新 = 合法
    with pytest.raises(ValidationError):
        DocUpdateIn(title="标" * 201)
    with pytest.raises(ValidationError):
        DocUpdateIn(clearance=99)


# ---------------------------------------------------------------------------
# ChatIn.top_k：夹 0–50
# ---------------------------------------------------------------------------


def test_chat_top_k_bounds():
    with pytest.raises(ValidationError):
        ChatIn(query="问题", top_k=-1)
    with pytest.raises(ValidationError):
        ChatIn(query="问题", top_k=9999)
    ChatIn(query="问题", top_k=0)   # 0 = 用默认 TOP_K
    ChatIn(query="问题", top_k=50)


def test_chat_api_returns_422_for_overlarge_top_k(db, user_factory):
    u = user_factory("tk99", clearance=3, roles=["research"])
    r = client.post("/api/v1/chat", json={"query": "测试", "top_k": 9999},
                    headers=_auth(db, u))
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# UserIn：用户名格式 / 口令下限 / 密级范围
# ---------------------------------------------------------------------------


def test_userin_rejects_short_and_overlong_username():
    with pytest.raises(ValidationError):
        UserIn(username="ab")
    with pytest.raises(ValidationError):
        UserIn(username="x" * 65)


def test_userin_rejects_blank_username():
    """曾经的洞：空 username 只 strip 不校验，能过唯一约束且可登录。"""
    with pytest.raises(ValidationError):
        UserIn(username="")
    with pytest.raises(ValidationError):
        UserIn(username="   ")


def test_userin_rejects_illegal_username_chars():
    for bad in ("a b", "用户名!", "user/name", "a\tb"):
        with pytest.raises(ValidationError):
            UserIn(username=bad)


def test_userin_accepts_cjk_and_dotted_usernames():
    UserIn(username="张三丰")         # \w 走 unicode，兼容中文名
    UserIn(username="a.b-c@d")        # 企业常见形态
    UserIn(username="research01")


def test_userin_password_min_length_but_empty_means_default():
    with pytest.raises(ValidationError, match="8 位"):
        UserIn(username="someone", password="short")
    UserIn(username="someone", password="")            # 留空 = 默认初始口令
    UserIn(username="someone", password="12345678")


def test_userin_clearance_and_display_name_bounds():
    with pytest.raises(ValidationError):
        UserIn(username="someone", clearance=4)
    with pytest.raises(ValidationError):
        UserIn(username="someone", display_name="n" * 65)


def test_doc_create_api_returns_422_for_overlong_title(db, user_factory):
    u = user_factory("t99", clearance=3, roles=["research"])
    r = client.post("/api/v1/docs",
                    json={"title": "标" * 201, "content": "正文"},
                    headers=_auth(db, u))
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# ingest 卡口：内部路径的最后一道（schema 管不到这里）
# ---------------------------------------------------------------------------


def test_ingest_rejects_overlong_content(db, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_DOC_CHARS", 50)
    with pytest.raises(ValueError, match="上限"):
        ingest_document(db, title="标题", content="x" * 51)


def test_ingest_accepts_content_at_limit(db, monkeypatch):
    """边界值放行：卡口拦"超限"，不拦"顶格"。"""
    from sqlalchemy import select

    from app.models import Chunk

    monkeypatch.setattr(ingest, "MAX_DOC_CHARS", 50)
    doc = ingest_document(db, title="标题", content="x" * 50)
    chunks = db.execute(
        select(Chunk).where(Chunk.doc_id == doc.id)).scalars().all()
    assert doc.id and len(chunks) >= 1


def test_ingest_rejects_overlong_title(db):
    """曾经的静默截断 title[:255] → 明确拒绝。"""
    with pytest.raises(ValueError, match="标题过长"):
        ingest_document(db, title="标" * 256, content="正文")


def test_ingest_rejects_empty_content(db):
    with pytest.raises(ValueError, match="为空"):
        ingest_document(db, title="标题", content="   ")


def test_reingest_rejects_overlong_content(db, doc_factory, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_DOC_CHARS", 50)
    doc = doc_factory(title="旧文档")
    with pytest.raises(ValueError, match="上限"):
        reingest_document(db, doc, content="x" * 51)


def test_reingest_rejects_empty_content(db, doc_factory):
    doc = doc_factory(title="旧文档")
    with pytest.raises(ValueError, match="为空"):
        reingest_document(db, doc, content="")


# ---------------------------------------------------------------------------
# 上传大小边界：MAX_UPLOAD_MB 配置化（原 docs.py 两处硬编码 20MB）
# ---------------------------------------------------------------------------


def test_upload_size_limit_is_configurable(db, user_factory, monkeypatch):
    """把上限压到 0MB，一个字节的文件都应被 413——证明读的是配置不是硬编码。"""
    from app import config

    monkeypatch.setattr(config, "MAX_UPLOAD_MB", 0)
    u = user_factory("up99", clearance=3, roles=["research"])
    r = client.post(
        "/api/v1/docs/upload",
        files={"file": ("a.txt", b"hello", "text/plain")},
        data={"title": "小文件", "clearance": "1"},
        headers=_auth(db, u),
    )
    assert r.status_code == 413
    assert "0MB" in r.json()["detail"]
