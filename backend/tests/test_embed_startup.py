# SPDX-License-Identifier: Apache-2.0
"""embed 启动期校验单测（#21 前置决策：方案 B + 维度一致性）。

覆盖两条启动闸：
  · require_embedding_key —— 无 Key 时的三态（配了通过 / 没配且放行通过 /
    没配且拒绝抛 RuntimeError）
  · check_dimension_consistency —— PG 列维度五态（一致 / 不一致拒绝 /
    无列跳过 / 类型不可解析跳过 / introspection 失败只告警）
外加 lifespan 接线：无 Key 时 lifespan 必须炸在 init_db 之前。
"""
import asyncio

import pytest

from app import embed
from app.embed import check_dimension_consistency, require_embedding_key


class _FakeDb:
    """最小会话替身：只实现 execute(text(...)).scalar()。"""

    def __init__(self, result=None, exc=None):
        self._result, self._exc = result, exc

    def execute(self, *_a, **_k):
        if self._exc:
            raise self._exc
        return self

    def scalar(self):
        return self._result


# ---------------------------------------------------------------------------
# require_embedding_key：无 Key 三态
# ---------------------------------------------------------------------------


def test_key_configured_passes(monkeypatch):
    monkeypatch.setattr(embed, "EMBED_API_KEY", "sk-test")
    monkeypatch.setattr(embed, "EMBED_REQUIRE_API_KEY", True)
    require_embedding_key()  # 不抛即通过


def test_key_missing_refused(monkeypatch):
    monkeypatch.setattr(embed, "EMBED_API_KEY", "")
    monkeypatch.setattr(embed, "EMBED_REQUIRE_API_KEY", True)
    with pytest.raises(RuntimeError, match="EMBED_API_KEY"):
        require_embedding_key()


def test_key_missing_allowed_when_not_required(monkeypatch):
    """演示/回归基线显式放行（smoke、pytest 即此态）。"""
    monkeypatch.setattr(embed, "EMBED_API_KEY", "")
    monkeypatch.setattr(embed, "EMBED_REQUIRE_API_KEY", False)
    require_embedding_key()


# ---------------------------------------------------------------------------
# check_dimension_consistency：PG 列维度五态
# ---------------------------------------------------------------------------


def test_dimension_match_passes(monkeypatch):
    monkeypatch.setattr(embed.embedder, "dim", 24)
    check_dimension_consistency(_FakeDb(result="vector(24)"))


def test_dimension_mismatch_refuses(monkeypatch):
    monkeypatch.setattr(embed.embedder, "dim", 24)
    with pytest.raises(RuntimeError, match="维度"):
        check_dimension_consistency(_FakeDb(result="vector(1024)"))


def test_dimension_skipped_when_column_absent(monkeypatch):
    """全新库还没有 embedding 列：不校验，create_all 随后按当前维度建表。"""
    monkeypatch.setattr(embed.embedder, "dim", 24)
    check_dimension_consistency(_FakeDb(result=None))


def test_dimension_skipped_when_type_unparsable(monkeypatch):
    """列类型不是 vector(N) 形态（意外 schema）：不拦启动，只当没读到。"""
    monkeypatch.setattr(embed.embedder, "dim", 24)
    check_dimension_consistency(_FakeDb(result="text"))


def test_dimension_check_warns_on_introspection_failure(monkeypatch, capsys):
    """introspection 失败只告警不拦启动：查不到 ≠ 维度不符。"""
    monkeypatch.setattr(embed.embedder, "dim", 24)
    check_dimension_consistency(_FakeDb(exc=RuntimeError("boom")))
    assert "WARNING" in capsys.readouterr().err


def test_dimension_check_against_real_pg(db, monkeypatch):
    """真 PG 上的维度校验（回归 format_type 参数顺序缺陷）。

    历史缺陷：_column_vector_dim 把 format_type(atttypmod, atttypid) 写反
    （PG 签名是 (oid, integer)）→ UndefinedFunction → 被 except 吞成
    WARNING，"改 EMBED_DIM 不重建表被拒绝启动"这道闸空转。_FakeDb 替身
    走不到这条 SQL，必须真库真列（db 夹具已 create_all 出 vector(24)）。
    """
    monkeypatch.setattr(embed.embedder, "dim", 24)
    # 钉住 SQL 真的读到了列维度，而不是悄悄走了 None/告警分支
    assert embed._column_vector_dim(db) == 24
    check_dimension_consistency(db)  # 一致：不抛
    monkeypatch.setattr(embed.embedder, "dim", 1024)
    with pytest.raises(RuntimeError, match="维度"):
        check_dimension_consistency(db)


# ---------------------------------------------------------------------------
# lifespan 接线：无 Key 必须炸在 init_db 之前
# ---------------------------------------------------------------------------


def test_lifespan_refuses_without_key_before_init_db(monkeypatch):
    """接线级验证：lifespan 一进门就撞密钥闸，init_db 等副作用都还没发生。"""
    from app import main

    monkeypatch.setattr(embed, "EMBED_API_KEY", "")
    monkeypatch.setattr(embed, "EMBED_REQUIRE_API_KEY", True)
    called = []
    monkeypatch.setattr(main, "init_db", lambda: called.append("init_db"))

    async def _run():
        async with main.lifespan(None):
            called.append("yield")

    with pytest.raises(RuntimeError, match="EMBED_API_KEY"):
        asyncio.run(_run())
    assert called == []  # init_db 未被调用：配置类失败不留半个库
