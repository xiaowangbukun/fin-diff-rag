# SPDX-License-Identifier: AGPL-3.0-only
"""retrieve.py —— 检索出口的越权/泄密防线（此前零覆盖）。

为什么必须先补这一块：retrieve.py 是"内容离开数据库"的唯一出口，
双校验架构（粗筛 SQL 下推 + 精校验逐条复核）和 Fail-Secure 降级通道都在
这里。它此前没有任何单元测试——意味着任何一次改动（比如新增召回通道、
调整 top_k、给 public_only 加条件）都可能悄悄打开一条越权口子，而套件
依旧全绿。

每条用例对应一个具体线上事故形态：
  · 密级硬门槛失效      → 密级 1 的用户读到机密级正文
  · 切片级密级下推失效  → 同文档内高密段落（段落级撕裂）被低密用户读到
  · deny 名单失效       → 被显式拒绝的人照样读到
  · 非就绪文档漏出      → 解析中/已归档文档比"列表里看不见、问答却能读"
  · public_only 口径放宽 → Fail-Secure 容灾时把内部文档当公开域吐出去
  · 防幻觉闸门失效      → 相关性不足仍生成答案，等于让模型编造监管口径
"""
import pytest

from app.embed import embedder
from app.models import Chunk, Document, new_id
from app.retrieve import (
    Hit, PUBLIC_CLEARANCE, extract_terms, is_reliable, public_only_search,
    search, unauthorized_probe,
)


# ------------------------------------------------------------------ 造数


def _doc(db, *, title="测试文档", clearance=1, acl_mode="open", status="ready",
         owner_dept_id=None):
    d = Document(
        id=new_id(), title=title, clearance=clearance, acl_mode=acl_mode,
        status=status, doc_type="txt", owner_dept_id=owner_dept_id,
    )
    db.add(d)
    db.flush()
    return d


def _chunk(db, doc, content, *, seq=0, clearance=None):
    """切片：embedding 走 conftest 注入的确定性替身，向量与查询同口径。"""
    c = Chunk(
        id=new_id(), doc_id=doc.id, seq=seq, content=content,
        content_len=len(content), clearance=clearance,
        embedding=embedder.embed_one(content),
    )
    db.add(c)
    db.flush()
    return c


# ------------------------------------------------------------------ 密级硬门槛


def test_search_blocks_document_above_user_clearance(db, user_factory):
    """防：密级 1 的用户读到机密（2）级文档正文——最直白的越权泄密。"""
    user = user_factory(username="u1", clearance=1)
    internal = _doc(db, title="内部授信政策", clearance=1, acl_mode="open")
    secret = _doc(db, title="机密授信政策", clearance=2, acl_mode="open")
    _chunk(db, internal, "同业存单授信额度与敞口口径说明")
    _chunk(db, secret, "同业存单授信额度与敞口口径说明（机密补充）")
    db.commit()

    hits, denied, verify = search(db, user, "同业存单授信额度", top_k=8)

    assert [h.doc_title for h in hits] == ["内部授信政策"]
    # 粗筛就该把机密文档排除在候选之外：accessible_docs 只数可见的
    assert verify["coarse"]["accessible_docs"] == 1
    assert verify["coarse"]["excluded"] == 1
    assert verify["fine"]["delivered"] == 1


def test_search_blocks_chunk_above_user_clearance(db, user_factory):
    """防：同文档内的高密段落被低密用户读到（段落级撕裂）。

    切片密级在 SQL 层就下推了（retrieve.py:112），所以高密切片根本进不了
    候选集——这里断言的是"下推真的生效"，而不是等它进来了再拦。
    """
    user = user_factory(username="u1", clearance=1)
    doc = _doc(db, title="风控手册", clearance=1, acl_mode="open")
    _chunk(db, doc, "常规风控流程与敞口计算口径", seq=0, clearance=None)
    _chunk(db, doc, "压力测试极端情形下的敞口上限", seq=1, clearance=2)
    db.commit()

    hits, _denied, _verify = search(db, user, "敞口", top_k=8)

    assert [h.seq for h in hits] == [0], "高密切片不得进入结果集"
    assert all(h.clearance <= user.clearance for h in hits)


def test_fine_grained_check_blocks_chunk_even_if_sql_pushdown_broken(db, user_factory):
    """防：第二道精校验是"最后一道"，下推被改坏时它必须还能挡住。

    白盒：直接构造一个越权的 Hit 喂给 search 的精校验环节（用替身
    _recall 绕开召回），证明即便候选集里混进了高密切片，出口仍会拦下
    并记入 denied（kind=chunk），而不是静默放行。
    """
    import app.retrieve as retrieve

    user = user_factory(username="u1", clearance=1)
    doc = _doc(db, title="风控手册", clearance=1, acl_mode="open")
    leaked = _chunk(db, doc, "压力测试极端情形下的敞口上限", seq=1, clearance=3)
    db.commit()

    rogue = Hit(
        chunk_id=leaked.id, doc_id=doc.id, doc_title=doc.title,
        clearance=3, seq=1, content=leaked.content, vec_score=0.99,
    )
    orig_recall = retrieve._recall
    retrieve._recall = lambda *a, **kw: [rogue]  # 模拟下推失效
    try:
        hits, denied, _verify = search(db, user, "敞口", top_k=8)
    finally:
        retrieve._recall = orig_recall

    assert hits == [], "精校验必须拦下越权切片，一个字都不给"
    assert denied and denied[0]["kind"] == "chunk"
    assert "切片密级不足" in denied[0]["reason"]


# ------------------------------------------------------------------ ACL / 生命周期


def test_search_respects_deny_acl(db, user_factory, acl_factory):
    """防：显式 deny 名单失效——被点名拒绝的人照样读到文档。"""
    user = user_factory(username="u1", clearance=1, roles=["research"])
    doc = _doc(db, title="受限客户名单", clearance=1, acl_mode="open")
    _chunk(db, doc, "重点观察客户名单与授信敞口")
    acl_factory(doc_id=doc.id, subject_type="user", subject_key=user.id,
                effect="deny")
    db.commit()

    hits, _denied, verify = search(db, user, "客户名单", top_k=8)

    assert hits == []
    assert verify["coarse"]["accessible_docs"] == 0, "deny 必须在 SQL 粗筛阶段就生效"


def test_search_skips_non_ready_document(db, user_factory):
    """防：解析中/已归档文档"列表里看不到、问答却能读出来"的口径缝隙。"""
    user = user_factory(username="u1", clearance=1)
    parsing = _doc(db, title="解析中的年报", clearance=1, acl_mode="open",
                   status="parsing")
    archived = _doc(db, title="已归档年报", clearance=1, acl_mode="open",
                    status="archived")
    _chunk(db, parsing, "年报合并口径与商誉减值说明")
    _chunk(db, archived, "年报合并口径与商誉减值说明")
    db.commit()

    hits, _denied, verify = search(db, user, "商誉减值", top_k=8)

    assert hits == []
    assert verify["coarse"]["accessible_docs"] == 0


def test_search_respects_top_k(db, user_factory):
    """防：top_k 失效导致单轮超额披露（绕过防拼图的单轮配额）。"""
    user = user_factory(username="u1", clearance=1)
    doc = _doc(db, title="长文档", clearance=1, acl_mode="open")
    for i in range(5):
        _chunk(db, doc, f"敞口计算口径说明第{i}段", seq=i)
    db.commit()

    hits, _denied, _verify = search(db, user, "敞口计算口径", top_k=2)

    assert len(hits) == 2


# ------------------------------------------------------------------ Fail-Secure 降级


def test_public_only_search_excludes_internal_open_docs(db):
    """防：容灾降级把"内部但 acl_mode=open"的文档当公开域吐出去。

    口径极易被误解：open 只表示"全公司可见"，不等于"可对外公开"。
    Fail-Secure 通道的准入是 密级 <= 0 **且** open，两者缺一不可。
    """
    public = _doc(db, title="公开披露指引", clearance=0, acl_mode="open")
    internal_open = _doc(db, title="内部全员通知", clearance=1, acl_mode="open")
    _chunk(db, public, "信息披露口径与投资者关系问答")
    _chunk(db, internal_open, "信息披露口径与投资者关系问答（内部版）")
    db.commit()

    hits, denied, verify = public_only_search(db, "信息披露口径", top_k=8)

    assert [h.doc_title for h in hits] == ["公开披露指引"]
    assert denied == []
    assert verify["mode"] == "public_only"


def test_public_only_search_blocks_high_clearance_chunk_in_public_doc(db):
    """防：公开文档里夹带的高密切片在降级通道被当成公开内容。"""
    doc = _doc(db, title="公开披露指引", clearance=0, acl_mode="open")
    _chunk(db, doc, "信息披露基本口径", seq=0, clearance=None)
    _chunk(db, doc, "未披露的监管问询细节", seq=1, clearance=2)
    db.commit()

    hits, _denied, _verify = public_only_search(db, "信息披露", top_k=8)

    assert [h.seq for h in hits] == [0]
    assert all(h.clearance <= PUBLIC_CLEARANCE for h in hits)


def test_public_only_search_takes_no_user_identity(db, user_factory):
    """防：降级通道被塞进用户身份，演变成"绕过 Fail-Secure 的越权后门"。

    签名层面钉死：public_only_search 接的是 (db, query, top_k)，
    拿不到任何 user——异常链路下想越权也无从下手。
    """
    import inspect

    params = list(inspect.signature(public_only_search).parameters)
    assert params == ["db", "query", "top_k"]


# ------------------------------------------------------------------ 越权统计旁路


def test_unauthorized_probe_returns_counts_without_content(db, user_factory,
                                                            dept_factory):
    """防：越权命中统计把不可见文档的内容/标题漏给普通用户（拼图导航仪）。"""
    user = user_factory(username="u1", clearance=1)
    other_dept = dept_factory(name="并购组")
    secret = _doc(db, title="绝密并购标的清单", clearance=3, acl_mode="dept",
                  owner_dept_id=other_dept.id)
    _chunk(db, secret, "并购标的估值区间与交易结构安排")
    db.commit()

    probe = unauthorized_probe(db, user, "并购标的估值")

    assert probe["total"] == 1
    assert probe["by_level"] == {"绝密": 1}
    # 只给数量与密级分布：不得夹带任何内容/标题/文档标识
    assert "并购标的" not in str(probe["by_level"].keys())
    assert set(probe) == {"total", "by_level"}


# ------------------------------------------------------------------ 防幻觉闸门


def test_is_reliable_false_on_empty_hits():
    """防：没有任何依据却照样生成答案——模型编造监管口径。"""
    assert is_reliable([], 1) is False


def test_is_reliable_accepts_strong_vector_in_api_mode():
    """防：真实向量语义命中被本地哈希时代的"关键词为准"口径误杀。"""
    hit = Hit("c1", "d1", "t", 1, vec_score=0.9, kw_hits=0)
    assert is_reliable([hit], 3) is True


def test_is_reliable_requires_keyword_evidence_in_local_mode(monkeypatch):
    """防：本地（低区分度）向量下仅凭相似度放行，答非所问还以为正常。"""
    from app import embed as embed_mod

    monkeypatch.setattr(embed_mod.embedder, "api_mode", False)
    weak = Hit("c1", "d1", "t", 1, vec_score=0.9, kw_hits=0)
    strong = Hit("c2", "d2", "t", 1, vec_score=0.0, kw_hits=2)

    assert is_reliable([weak], 2) is False, "本地模式关键词不足必须拒答"
    assert is_reliable([strong], 2) is True


def test_is_reliable_rejects_single_weak_keyword(monkeypatch):
    """防：只中一个通用词（如"公司"）就当作有依据。"""
    from app import embed as embed_mod

    monkeypatch.setattr(embed_mod.embedder, "api_mode", False)
    generic = Hit("c1", "d1", "t", 1, vec_score=0.0, kw_hits=1)
    assert is_reliable([generic], 1) is False


# ------------------------------------------------------------------ 检索通道本身


def test_vector_recall_uses_pgvector_operator(db, user_factory):
    """防：#21 后唯一向量通道（`<=>` + CAST AS vector）悄悄退化或报错。

    这条断言的是"PG 真检索跑得通"：同文本向量余弦距离≈0 → 相似度≈1。
    若有人把 SQL 改回字符串拼接、或维度对不上，这里会第一批炸。
    """
    user = user_factory(username="u1", clearance=1)
    doc = _doc(db, title="同业存单", clearance=1, acl_mode="open")
    _chunk(db, doc, "同业存单的利率风险敞口计量方法")
    db.commit()

    hits, _denied, _verify = search(db, user, "同业存单的利率风险敞口计量方法",
                                    top_k=1)

    assert len(hits) == 1
    assert hits[0].vec_score > 0.95, "同文本应近乎完全相似，说明向量通道正常"


def test_extract_terms_drops_stopwords_and_dedups():
    """防：停用词占满 term 位导致关键词召回退化（静默降质）。"""
    terms = extract_terms("请帮我查询一下公司的公司的同业存单额度")
    assert "公司" in terms
    assert terms.count("公司") == 1
    assert all(t not in terms for t in ("请", "帮我", "一下"))
    assert all(len(t) >= 2 for t in terms)


@pytest.mark.parametrize("query", ["", "   "])
def test_search_empty_query_short_circuits(db, user_factory, query):
    """防：空查询走进召回链路后出现不可预期的全量返回。"""
    user = user_factory(username="u1", clearance=1)
    hits, denied, verify = search(db, user, query, top_k=8)
    assert (hits, denied) == ([], [])
    assert verify["fine"]["delivered"] == 0
