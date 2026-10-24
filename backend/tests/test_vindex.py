# SPDX-License-Identifier: Apache-2.0
"""vindex.py —— 向量索引保障（此前零覆盖）。

索引缺失不会让系统报错，只会让检索静默变慢：切片上万后全表精确扫描的
延迟能从毫秒级掉到秒级，表现为"问答突然很卡"，而所有功能测试依旧全绿
——典型的静默降质事故。本文件钉住三件事：

  · DDL 形状（HNSW + vector_cosine_ops + m/ef_construction）不被改坏；
  · 行数超阈值时**不**在启动时建索引（HNSW 建索引锁表，业务高峰建等于事故）；
  · 任何失败都只告警不抛——索引是加速项，不该让服务起不来。

分支用例用替身 Session 复现，不依赖测试账号是否具备建扩展的权限。
"""
import pytest

from app import vindex
from app.vindex import INDEX_NAME, _hnsw_ddl, _version_tuple, ensure_vector_index


# ------------------------------------------------------------------ 纯函数


def test_hnsw_ddl_shape():
    """防：索引被改成 IVFFlat / 忘了 IF NOT EXISTS / 丢了余弦算子类。

    · IF NOT EXISTS：启动期幂等，重复启动不能报"索引已存在"；
    · vector_cosine_ops：与检索侧 `<=>` 同算子，建错算子的索引不会被用到
      （检索继续全表扫描，且没人报错）。
    """
    ddl = _hnsw_ddl()
    assert "IF NOT EXISTS" in ddl
    assert f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON chunks" in ddl
    assert "USING hnsw" in ddl
    assert "vector_cosine_ops" in ddl
    assert "m=16" in ddl and "ef_construction=64" in ddl


@pytest.mark.parametrize("raw,expected", [
    ("0.7.4", (0, 7, 4)),
    ("0.5", (0, 5)),
    ("0.5.0.1", (0, 5, 0)),
    ("", ()),
    ("not-a-version", ()),
    ("a.b.c", ()),
])
def test_version_tuple_parsing(raw, expected):
    """防：版本号解析失败把老版本误判成新版，漏掉 iterative scan 告警。"""
    assert _version_tuple(raw) == expected


# ------------------------------------------------------------------ 替身 Session


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeSession:
    """只实现 ensure_vector_index 用到的 execute/commit/rollback。

    fail_on 指定哪些语句抛异常，用来复现"扩展不可用""建索引失败"两条
    只告警不抛的分支——真实库里需要改权限才能触发，代价太高。
    """

    def __init__(self, *, version="0.7.4", rows=0, fail_on=()):
        self.version = version
        self.rows = rows
        self.fail_on = fail_on
        self.calls: list[str] = []

    def execute(self, sql, *a, **kw):
        s = str(sql)
        self.calls.append(s)
        if "CREATE EXTENSION" in s:
            if "extension" in self.fail_on:
                raise RuntimeError("permission denied to create extension")
            return _Result(None)
        if "extversion" in s:
            return _Result(self.version)
        if "count(*) FROM chunks" in s:
            return _Result(self.rows)
        if "CREATE INDEX" in s:
            if "index" in self.fail_on:
                raise RuntimeError("could not create index")
            return _Result(None)
        return _Result(None)

    def commit(self):
        self.calls.append("COMMIT")

    def rollback(self):
        self.calls.append("ROLLBACK")


def test_extension_unavailable_only_warns():
    """防：pgvector 未预装时启动直接崩——索引是加速项，不该拖垮服务。"""
    db = _FakeSession(fail_on=("extension",))
    result = ensure_vector_index(db)  # 不得抛出
    assert result["skipped"] == "extension_unavailable"


def test_index_creation_failure_only_warns():
    """防：建索引失败（锁冲突/权限）被当成启动失败，服务起不来。"""
    db = _FakeSession(rows=0, fail_on=("index",))
    result = ensure_vector_index(db)
    assert result["created"] is False
    assert result["skipped"] == ""
    assert "ROLLBACK" in db.calls


def test_too_many_rows_skips_auto_build(monkeypatch):
    """防：业务高峰在几万行上启动即建 HNSW——建索引锁表，等于自造事故。

    正确姿势是低峰跑 `python run.py build-index`，所以这里必须跳过。
    """
    monkeypatch.setattr(vindex, "HNSW_AUTO_BUILD_MAX", 0)
    db = _FakeSession(rows=100)
    result = ensure_vector_index(db)
    assert result["skipped"] == "too_many_rows"
    assert result["rows"] == 100
    assert not any("CREATE INDEX" in c for c in db.calls)


def test_builds_index_when_within_limit(monkeypatch):
    """防：阈值判断写反，导致小库永远不建索引（检索一直全表扫描）。"""
    monkeypatch.setattr(vindex, "HNSW_AUTO_BUILD_MAX", 50000)
    db = _FakeSession(rows=10, version="0.7.4")
    result = ensure_vector_index(db)
    assert result["created"] is True
    assert result["version"] == "0.7.4"
    assert any(c.startswith("CREATE INDEX") for c in db.calls)


def test_old_pgvector_version_still_proceeds(capsys, monkeypatch):
    """防：<0.5.0 的无 iterative scan 版本被静默当成没问题。

    带权限过滤的 HNSW 在老版本上会漏召回——属于"答不全但不报错"，
    必须有告警让运维看见。
    """
    monkeypatch.setattr(vindex, "HNSW_AUTO_BUILD_MAX", 50000)
    db = _FakeSession(rows=1, version="0.4.2")
    result = ensure_vector_index(db)
    captured = capsys.readouterr()
    assert result["created"] is True, "老版本仍要建索引，只告警不阻断"
    assert "0.4.2" in captured.err and "iterative scan" in captured.err


# ------------------------------------------------------------------ 真实 PG 联通


def test_ensure_vector_index_never_raises_on_real_db(db):
    """防：本模块任何分支抛异常都会把启动闸顶穿（索引不该有这个权力）。"""
    result = ensure_vector_index(db)  # 真实库：成功/告警都得自己消化
    assert isinstance(result, dict)
    assert "skipped" in result
