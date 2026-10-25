# SPDX-License-Identifier: AGPL-3.0-only
"""pytest 全局夹具：把每一条 DB 用例都隔离到**独立 schema**（真实 PostgreSQL）。

#21 迁移说明：本文件此前把 DATABASE_URL 重定向到临时 SQLite 文件库。SQLite
降级链路移除后，测试基建改为连真实 PostgreSQL + pgvector——既覆盖真正的
向量检索路径（`<=>` 算子 / HNSW / vector 列维度校验），也让"能跑不能测"
的双栈分歧彻底消失。

隔离模型（每用例一套独立 schema）：
  · 每条用例建 `t_<uuid>` schema，连接级 `SET search_path` 把非限定表名
    引到该 schema；用例结束 DROP SCHEMA CASCADE 回收。
  · schema 切换必须配 `engine.dispose()`：search_path 是连接级状态，池化
    连接会带着上一个用例的 schema 复用。dispose 关掉旧连接，迫使下次取连
    接时按当前 schema 重新 SET。
  · search_path 带 `, public`：pgvector 扩展（vector 类型）装在 public，
    不含它 `vector(24)` 列建不出来。

为什么仍写在 conftest：`app.config` 在**模块导入时**固化 DATA_DIR /
DATABASE_URL，`app.db` 导入时即建 engine。pytest 先导入 conftest 再收集
测试模块，这里是唯一可靠的注入点。

离线确定性（与迁移前口径一致）：
  · DATA_DIR / DATABASE_URL → setdefault 语义：CI 注入优先，无注入走默认
  · LLM/EMBED Key 强制置空 + EMBED_REQUIRE_API_KEY=false：方案 B 的放行
    开关；向量由本文件的 fake embedder 供给（monkeypatch `embedder._remote`），
    语义与旧本地哈希向量一致（同词同分量），保证既有断言行为不变
  · EMBED_DIM=24：小维度 vector(24) 列，建表/写入都快
  · PII_NER_URL 置空，关闭 NER 外呼
"""
import hashlib
import json
import math
import os
import re
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import event, text

BACKEND_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# 环境变量必须在任何 `import app.*` 之前落定
# --------------------------------------------------------------------------
# DATA_DIR：setdefault——CI 注入（runner.temp）优先，本地无注入则临时目录
os.environ.setdefault("DATA_DIR", str(Path(tempfile.mkdtemp(prefix="finrag-pytest-")) / "data"))
# DATABASE_URL：默认连本机测试库 finrag_test；CI 由 service 容器注入同名形态。
# 密码必须 URL-encode：项目口令含 '@'，不编码会被 psycopg 当成 userinfo/host
# 分隔符（解析成 host=Nul8280@127.0.0.1 然后 DNS 失败）——用 quote() 动态
# 构造，将来换口令也不会再踩这个坑。
_PG_PASSWORD = quote("Fin@Rag2026", safe="")
os.environ.setdefault(
    "DATABASE_URL",
    f"postgresql+psycopg://finrag:{_PG_PASSWORD}@127.0.0.1:5432/finrag_test",
)
os.environ["LLM_API_KEY"] = ""
os.environ["EMBED_API_KEY"] = ""
os.environ["EMBED_REQUIRE_API_KEY"] = "false"
os.environ["EMBED_DIM"] = "24"
os.environ["PII_NER_URL"] = ""
# 固定 40 字节：pyjwt 对 <32 字节的 HS256 密钥发 InsecureKeyLengthWarning，
# 每轮测试都刷一遍噪音；长度本身不影响任何断言。
os.environ["JWT_SECRET"] = "pytest-fixed-jwt-secret-0123456789abcdef"
os.environ["JWT_SECRET_OLD"] = ""
os.environ["AUDIT_BATCH_TIMEOUT"] = "0.05"
# 审计外置 sink 在测试里强制关闭（不是 setdefault，是覆盖）：
# `backend/.env` 里若为演示打开了 AUDIT_ANCHOR_EXTERNAL_FILE，锚点比对会把
# "外置序号 440 > 空库 0" 判成"尾行被截断"，resume_chain 于是同步写一条告警
# 审计行——所有与"链尾序号"相关的用例都会被这条额外行带偏（曾真实发生：
# 期望 4 行、实际 5 行）。外置 sink 的能力由 test_audit_anchors 里的
# `anchor_file` fixture 用 monkeypatch 显式打开，这里必须保证默认是关的。
os.environ["AUDIT_ANCHOR_EXTERNAL_FILE"] = ""
os.environ["AUDIT_ANCHOR_URL"] = ""

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# 当前用例的 schema 名：连接建立时由下面的 connect 事件读取并 SET search_path。
_CURRENT_SCHEMA: str | None = None


# --------------------------------------------------------------------------
# schema 隔离基建
# --------------------------------------------------------------------------

def _install_search_path_hook(engine) -> None:
    """每次连接被**取出**时把 search_path 指向当前用例 schema（public 兜底放 vector 类型）。

    为什么挂在 `checkout` 而不是 `connect`：`SET search_path` 在 PostgreSQL 里
    是事务性设置。连接建立时执行，若该连接随后被回滚（查询失败 / 会话
    rollback / 池归还时的 reset），设置会一并撤销，连接就带着默认
    `"$user", public` 回到池里；下一次借用它的会话（登录计数、审计守护线程等
    独立 Session）会落到 public，看到的是"表不存在"。挂在 checkout 上每次借用
    都重新设置，回滚最多影响本次借用，不会污染后续用例。
    """

    @event.listens_for(engine, "checkout")
    def _set_search_path(dbapi_conn, _rec, _proxy):  # noqa: ANN001
        if not _CURRENT_SCHEMA:
            return
        cur = dbapi_conn.cursor()
        try:
            cur.execute(f'SET search_path TO "{_CURRENT_SCHEMA}", public')
        finally:
            cur.close()


def _fresh_schema(engine) -> str:
    """建一个空 schema 并把引擎切过去；返回 schema 名。"""
    global _CURRENT_SCHEMA
    from app.db import Base

    name = f"t_{uuid.uuid4().hex[:12]}"
    _CURRENT_SCHEMA = name
    # 必须先 dispose：池化连接带着旧 schema 的 search_path，不关就会串味
    engine.dispose()
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{name}"'))
    # 新 schema 本来就是空的，drop/create 走一遍是为了与原实现语义对齐
    # （drop_all 在空 schema 上是空操作，开销可忽略）
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return name


def _drop_schema(engine, name: str) -> None:
    with engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))
    engine.dispose()


# --------------------------------------------------------------------------
# fake embedder：替身注入点（#21 后本地哈希向量通道已移除）
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"[a-zA-Z0-9]+|[\u4e00-\u9fff]")


def _fake_remote(texts: list[str]) -> list[list[float]]:
    """确定性词袋向量：同文本永远同向量，共享词汇的文本余弦更高。

    与 #21 前本地哈希向量同口径（词频散列 + L2 归一化），保证既有测试的
    断言行为不变；确定性还让"同文档同 chunk 两次入库向量一致"这类断言稳。
    """
    from app.config import EMBED_DIM

    out = []
    for t in texts:
        toks = _TOKEN.findall(t.lower())
        vec = [0.0] * EMBED_DIM
        for tok in toks:
            h = int(hashlib.md5(tok.encode("utf-8")).digest()[:8].hex(), 16)
            vec[h % EMBED_DIM] += 1.0
        n = math.sqrt(sum(v * v for v in vec)) or 1.0
        out.append([v / n for v in vec])
    return out


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _cleanup_tmp_root():
    """会话结束后回收临时 DATA_DIR（CI 注入 runner.temp 时同样安全）。"""
    yield
    data_dir = os.environ.get("DATA_DIR", "")
    if data_dir and "finrag-pytest-" in data_dir:
        shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def tmp_data_dir() -> Path:
    return Path(os.environ["DATA_DIR"])


@pytest.fixture(autouse=True)
def _isolate_between_tests():
    """每条用例前后的全局状态复位。

    policy 的部门树缓存是**进程级**的（DEPT_CACHE_TTL=5s），跨用例会串味：
    上一条用例建的部门树可能让下一条用例的 dept_chain 读到不存在的 id。
    audit 的异步消费线程也要在用例结束后排空，避免写穿到下一条用例的库。
    """
    from app import audit, policy

    policy.invalidate_dept_cache()
    yield
    policy.invalidate_dept_cache()
    audit.flush_audit(timeout=2.0)


@pytest.fixture(scope="session")
def engine():
    """测试库引擎（DATABASE_URL 由本模块重定向到 finrag_test）。"""
    from app.db import engine as _engine

    _install_search_path_hook(_engine)
    return _engine


@pytest.fixture(autouse=True)
def _fake_embedder():
    """给 embedder 单例注入替身 `_remote`（实例属性，对所有 import 方生效）。

    api_mode 置 True：检索侧的 is_reliable / intent 锚句阈值按"真实向量"
    口径走，与迁移前（有 Key 时）行为一致。

    刻意不依赖 monkeypatch：本 fixture 是 autouse，若走 monkeypatch 会把它的
    实例化时点提前到各测试文件的参数 fixture（如 test_audit 的 chain）之前，
    teardown 逆序后 chain 先于 monkeypatch 恢复——那时测试里替换的进程内
    状态（audit._audit_q 等）还没还原，teardown 逻辑会撞上半恢复状态。
    手动 save/restore 保持原有 fixture 时序。
    """
    from app.embed import embedder

    orig_remote = embedder.__dict__.get("_remote")
    orig_api = embedder.api_mode
    embedder._remote = _fake_remote
    embedder.api_mode = True
    try:
        yield embedder
    finally:
        if orig_remote is None:
            embedder.__dict__.pop("_remote", None)  # 还原成类方法
        else:
            embedder._remote = orig_remote
        embedder.api_mode = orig_api


@pytest.fixture
def db(engine):
    """每条用例一个独立 schema + 一个 Session。"""
    from sqlalchemy.orm import sessionmaker

    schema = _fresh_schema(engine)
    Session = sessionmaker(
        bind=engine, autoflush=False, future=True, expire_on_commit=False
    )
    session = Session()
    try:
        yield session
    finally:
        try:
            session.rollback()
        except Exception:
            pass
        session.close()
        # 先排空异步审计再删 schema：消费线程可能还握着一条待落库的行，
        # 表被 CASCADE 掉之后它只能打印 "relation audit_logs does not exist"，
        # 虽不影响用例结果，但会让每次跑测试的 stderr 都带一条假故障。
        from app import audit
        audit.flush_audit(timeout=2.0)
        _drop_schema(engine, schema)


# --------------------------------------------------------------------------
# 模型工厂：统一在 conftest 里，避免各用例重复造轮子
# --------------------------------------------------------------------------


@pytest.fixture
def dept_factory(db):
    from app.models import Department, new_id

    def _make(name: str, parent_id: str | None = None):
        d = Department(id=new_id(), name=name, code=name, parent_id=parent_id)
        db.add(d)
        db.flush()
        return d

    return _make


@pytest.fixture
def user_factory(db):
    from app.models import User, new_id

    def _make(username: str, clearance: int = 1, dept_id: str | None = None,
              roles: list[str] | None = None):
        u = User(
            id=new_id(), username=username, display_name=username,
            clearance=clearance, dept_id=dept_id,
            roles=json.dumps(roles or []), pwd_hash="x", salt="y",
        )
        db.add(u)
        db.flush()
        return u

    return _make


@pytest.fixture
def doc_factory(db):
    from app.models import Document, new_id

    def _make(title: str = "测试文档", clearance: int = 1, acl_mode: str = "dept",
              owner_dept_id: str | None = None, status: str = "ready",
              created_at=None):
        d = Document(
            id=new_id(), title=title, clearance=clearance, acl_mode=acl_mode,
            owner_dept_id=owner_dept_id, status=status, doc_type="txt",
            created_at=created_at,
        )
        db.add(d)
        db.flush()
        return d

    return _make


@pytest.fixture
def acl_factory(db):
    from app.models import DocAcl, new_id

    def _make(doc_id: str, subject_type: str, subject_key: str,
              effect: str = "allow", expires_at=None):
        a = DocAcl(
            id=new_id(), doc_id=doc_id, subject_type=subject_type,
            subject_key=subject_key, effect=effect, expires_at=expires_at,
        )
        db.add(a)
        db.flush()
        return a

    return _make


@pytest.fixture
def audit_factory(db):
    """直接插审计行，绕开 write_log() 的 ts=utcnow()。

    日报/时序的边界用例必须精确控制 UTC 自然日（含 00:00 整点），
    靠 sleep 对齐真实时间既慢又脆——这里显式指定 ts。
    不写 prev_hash/row_hash：这些行不进哈希链，也不触发异步消费线程。
    """
    from app.models import AuditLog, new_id

    def _make(ts, action: str = "search", decision: str = "allow",
              username: str = "tester", user_id: str = "", target_id: str = "",
              target_label: str = "", reason: str = "", query: str = "",
              detail: str = ""):
        row = AuditLog(
            id=new_id(), ts=ts, user_id=user_id, username=username,
            action=action, decision=decision, target_id=target_id,
            target_label=target_label, query=query, reason=reason, detail=detail,
        )
        db.add(row)
        db.flush()
        return row

    return _make


@pytest.fixture
def chunk_factory(db):
    from app.models import Chunk, new_id

    def _make(doc_id: str, seq: int = 0, content: str = "正文",
              clearance: int | None = None):
        c = Chunk(
            id=new_id(), doc_id=doc_id, seq=seq, content=content,
            content_len=len(content), clearance=clearance,
        )
        db.add(c)
        db.flush()
        return c

    return _make
