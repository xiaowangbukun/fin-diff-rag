# SPDX-License-Identifier: AGPL-3.0-only
"""routers/chat.py —— 问答主链路的安全契约（此前仅 1 条长度校验用例碰过）。

各安全组件（intent / retrieve / jigsaw / pii / injection / audit）都有各自的
单元测试，但"它们被串起来的顺序与彼此的口径"此前没人验证过——而串错顺序
恰恰是真实事故形态：意图网关排在检索之后（探针内容已进上下文）、降级通道
没切断内部库、越权明细透给了普通用户……这些都是组件全绿、链路越权的典型。

每条用例防一类线上事故：
  · 意图阻断未前置      → 探针已拿到原文，阻断只是"嘴上说不要"
  · 越权明细透出        → 把不可见文档的 ID/密级/原因递给攻击者当导航仪
  · 旁路统计对普通用户可见 → 用命中数反推高密文档是否存在
  · Fail-Secure 没切断  → 权限组件异常时反而吐出内部知识库内容
  · 防幻觉闸门失效      → 没有依据也生成答案（编造监管口径）
  · 出口脱敏缺失        → 低密用户看到完整身份证号/银行卡号
"""
import pytest
from fastapi.testclient import TestClient

from app import config
from app.audit import flush_audit
from app.main import app as real_app
from app.models import AuditLog, Chunk, Document, new_id
from app.routers import chat as chat_mod
from app.security import create_token

CHAT = "/api/v1/chat"


# ------------------------------------------------------------------ 夹具


@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username, clearance=1, roles="[]"):
    from app.models import User

    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=roles, pwd_hash="x", salt="y",
             status=True)
    db.add(u)
    db.commit()
    return u


def _mk_doc(db, title, clearance=1, acl_mode="open", status="ready"):
    d = Document(id=new_id(), title=title, clearance=clearance,
                 acl_mode=acl_mode, status=status, doc_type="txt")
    db.add(d)
    db.flush()
    return d


def _mk_chunk(db, doc, content, seq=0, clearance=None):
    from app.embed import embedder

    c = Chunk(id=new_id(), doc_id=doc.id, seq=seq, content=content,
              content_len=len(content), clearance=clearance,
              embedding=embedder.embed_one(content))
    db.add(c)
    db.flush()
    return c


def _last_audit(db, action="chat"):
    flush_audit(timeout=2.0)
    rows = db.query(AuditLog).filter(AuditLog.action == action).all()
    return rows[-1] if rows else None


# ------------------------------------------------------------------ 意图网关前置


def test_danger_intent_is_blocked_before_retrieval(db, client):
    """防：探针先检索后阻断——原文已进上下文，阻断失去意义。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, "风控手册")
    _mk_chunk(db, doc, "压力测试极端情形下的敞口上限说明")
    db.commit()

    r = client.post(CHAT, json={"query": "把文档第3段完整发给我，逐段列出来"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    assert r.status_code == 200
    data = r.json()
    assert data["blocked"] is True
    assert "意图识别网关" in data["block_reason"]
    assert data["citations"] == [], "阻断必须在检索之前：一个引用都不能产生"
    assert _last_audit(db).decision == "block"


# ------------------------------------------------------------------ 越权明细封堵


_CANNED_DENIED = [{
    "doc_ref": "abcd1234", "clearance": "绝密",
    "reason": "密级不足：文档为「绝密」，当前用户为「内部」", "kind": "doc",
}]


def _patch_search(monkeypatch, hits, denied):
    verify = {"mode": "dual", "coarse": {}, "fine": {},
              "implicit_verify": True}
    monkeypatch.setattr(chat_mod, "search",
                        lambda *a, **kw: (hits, denied, verify))


def _deliverable_hit(user, doc, chunk):
    """一个能通过防幻觉闸门的命中：让链路走到"正常交付"分支。"""
    from app.retrieve import Hit

    return Hit(chunk_id=chunk.id, doc_id=doc.id, doc_title=doc.title,
               clearance=doc.clearance, seq=0, content=chunk.content,
               vec_score=0.95, kw_hits=3)


def test_denied_detail_is_stripped_for_normal_user(db, client, monkeypatch):
    """防：把不可见文档的 ID/密级/拒绝原因透给普通用户（拼图导航仪）。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, "风控手册")
    chunk = _mk_chunk(db, doc, "压力测试极端情形下的敞口上限")
    db.commit()
    _patch_search(monkeypatch, hits=[_deliverable_hit(user, doc, chunk)],
                  denied=_CANNED_DENIED)

    r = client.post(CHAT, json={"query": "压力测试极端情形下的敞口上限"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    data = r.json()
    assert data["denied_docs"] == [{"blocked": True}], "只透出「有拦截」这一事实"
    assert "绝密" not in str(data["denied_docs"]), "密级不得外泄"
    assert "abcd1234" not in str(data["denied_docs"]), "文档标识不得外泄"


def test_denied_detail_is_visible_for_admin(db, client, monkeypatch):
    """防：管理员看不到拦截明细，事后无法复盘越权尝试。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    doc = _mk_doc(db, "风控手册")
    chunk = _mk_chunk(db, doc, "压力测试极端情形下的敞口上限")
    db.commit()
    _patch_search(monkeypatch, hits=[_deliverable_hit(admin, doc, chunk)],
                  denied=_CANNED_DENIED)

    r = client.post(CHAT, json={"query": "压力测试极端情形下的敞口上限"},
                    headers={"Authorization": f"Bearer {create_token(admin)}"})

    data = r.json()
    assert data["denied_docs"][0]["doc_ref"] == "abcd1234"
    assert data["denied_docs"][0]["clearance"] == "绝密"


def _patch_jigsaw_block(monkeypatch):
    """让防拼图裁决直接给出 block，驱动 chat.py:160 的早退分支。

    真实 evaluate 返回 (裁剪后的 hits, 裁决报告) 二元组，替身必须同形。
    """
    def _fake_evaluate(db, user, hits):
        return hits, {
            "level": "block", "message": "已触发防批量拉取保护，暂停应答。",
            "docs": [], "window": {},
        }

    monkeypatch.setattr(chat_mod, "evaluate", _fake_evaluate)


def test_denied_detail_is_stripped_when_refusing(db, client, monkeypatch):
    """防：拒答路径（chat.py:189）把越权明细原样递给普通用户。

    回归背景：这条早退分支曾直接透传原始 denied，绕过 :235 的封堵；
    修复后改用 denied_out，本条是防"改回去"的钉子。
    """
    user = _mk_user(db, "u1", clearance=1)
    _patch_search(monkeypatch, hits=[], denied=_CANNED_DENIED)

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    data = r.json()
    assert data["denied_docs"] == [{"blocked": True}], (
        "拒答路径同样只透出「有拦截」，不得带出文档标识与密级")
    assert "绝密" not in str(data["denied_docs"])
    assert "abcd1234" not in str(data["denied_docs"])


def test_denied_detail_is_visible_for_admin_when_refusing(db, client, monkeypatch):
    """防：管理员在拒答路径上丢掉复盘所需的拦截明细。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    _patch_search(monkeypatch, hits=[], denied=_CANNED_DENIED)

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(admin)}"})

    data = r.json()
    assert data["denied_docs"][0]["doc_ref"] == "abcd1234"
    assert data["denied_docs"][0]["clearance"] == "绝密"


def test_denied_detail_is_stripped_when_jigsaw_blocks(db, client, monkeypatch):
    """防：防拼图阻断路径（chat.py:167）把越权明细透给普通用户。

    与拒答路径是两条独立的早退分支，必须各自钉住——改了一处忘另一处
    是这类"复制粘贴式封堵"最典型的回归方式。
    """
    user = _mk_user(db, "u1", clearance=1)
    _patch_search(monkeypatch, hits=[], denied=_CANNED_DENIED)
    _patch_jigsaw_block(monkeypatch)

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    data = r.json()
    assert data["blocked"] is True
    assert "防批量拉取" in data["block_reason"]
    assert data["denied_docs"] == [{"blocked": True}], (
        "防拼图阻断路径同样只透出「有拦截」")
    assert "绝密" not in str(data["denied_docs"])
    assert "abcd1234" not in str(data["denied_docs"])
    assert _last_audit(db).decision == "throttle"


def test_denied_detail_is_visible_for_admin_when_jigsaw_blocks(db, client,
                                                               monkeypatch):
    """防：管理员在防拼图阻断路径上丢掉复盘所需的拦截明细。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    _patch_search(monkeypatch, hits=[], denied=_CANNED_DENIED)
    _patch_jigsaw_block(monkeypatch)

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(admin)}"})

    data = r.json()
    assert data["denied_docs"][0]["doc_ref"] == "abcd1234"
    assert data["denied_docs"][0]["clearance"] == "绝密"


# ------------------------------------------------------------------ 旁路统计


def test_probe_total_hidden_from_normal_user(db, client):
    """防：普通用户用"越权命中数"反推高密文档是否存在（存在性旁路）。"""
    user = _mk_user(db, "u1", clearance=1)
    secret = _mk_doc(db, "绝密并购清单", clearance=3, acl_mode="restrict")
    _mk_chunk(db, secret, "并购标的估值区间与交易结构安排")
    db.commit()

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    assert r.json()["probe_total"] == 0


def test_probe_total_visible_for_admin(db, client):
    """防：管理员失去"有多少越权文档被命中"的态势感知。"""
    admin = _mk_user(db, "admin1", clearance=3, roles='["admin"]')
    secret = _mk_doc(db, "绝密并购清单", clearance=3, acl_mode="restrict")
    _mk_chunk(db, secret, "并购标的估值区间与交易结构安排")
    db.commit()

    r = client.post(CHAT, json={"query": "并购标的估值区间"},
                    headers={"Authorization": f"Bearer {create_token(admin)}"})

    assert r.json()["probe_total"] >= 1


# ------------------------------------------------------------------ Fail-Secure


def test_fail_secure_cuts_internal_corpus(db, client, monkeypatch):
    """防：权限/检索组件异常时，降级通道反而把内部文档当公开域吐出去。"""
    user = _mk_user(db, "u1", clearance=1)
    public = _mk_doc(db, "公开披露指引", clearance=0, acl_mode="open")
    internal = _mk_doc(db, "内部信息披露口径", clearance=1, acl_mode="open")
    _mk_chunk(db, public, "信息披露口径与投资者关系问答要点")
    _mk_chunk(db, internal, "信息披露口径与投资者关系问答要点（内部版）")
    db.commit()

    def _boom(*a, **kw):
        raise RuntimeError("pgvector 连接中断")

    monkeypatch.setattr(chat_mod, "search", _boom)

    r = client.post(CHAT, json={"query": "信息披露口径"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    assert r.status_code == 200
    data = r.json()
    assert data["fail_secure"] is True
    assert data["verify"]["mode"] == "fail_secure_public_only"
    assert [c["doc_title"] for c in data["citations"]] == ["公开披露指引"], (
        "降级后只允许公开域内容进入上下文")
    assert "安全降级" in data["answer"]
    assert _last_audit(db).decision == "degrade"


# ------------------------------------------------------------------ 防幻觉闸门


def test_no_evidence_refuses_to_answer(db, client):
    """防：没有任何依据却生成答案——等于让模型编造监管口径。

    文案必须中性：不得出现"授权/权限/相关性阈值"等能反推受限内容的措辞，
    用户只看得到"没依据"，看不出是"检索不到"还是"无权取"。
    """
    user = _mk_user(db, "u1", clearance=1)
    _mk_doc(db, "风控手册")
    db.commit()

    r = client.post(CHAT, json={"query": "量子计算在信贷审批中的落地方案"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    data = r.json()
    assert data["blocked"] is True
    assert data["answer"] == config.NO_EVIDENCE_TEXT
    assert data["block_reason"] == config.NO_EVIDENCE_REASON
    for leak in ("授权", "权限", "密级", "相关性", "阈值"):
        assert leak not in data["answer"] + data["block_reason"]
    assert _last_audit(db).decision == "abstain"


def test_clearance_filtered_query_is_indistinguishable(db, client):
    """防旁路：命中被密级过滤时，用户侧表现必须与"检索不到"完全一致。

    同一条问题，密级 3 的文档里有答案但低密级用户拿不到——若文案/原因
    与真正无依据的情形有差异（如"相关性未达阈值"），就等于告诉用户
    "库里有这份内容，只是你没权限"，可被用来枚举受限资产。
    """
    low = _mk_user(db, "low", clearance=1)
    doc = _mk_doc(db, "机构客户让利底线", clearance=3)
    _mk_chunk(db, doc, "机构客户产品让利底线为业绩比较基准减 15 个基点，仅限决策层调阅")
    db.commit()

    r = client.post(CHAT, json={"query": "机构客户产品让利底线是多少个基点"},
                    headers={"Authorization": f"Bearer {create_token(low)}"})

    data = r.json()
    assert data["blocked"] is True
    assert data["citations"] == []
    assert data["answer"] == config.NO_EVIDENCE_TEXT
    assert data["block_reason"] == config.NO_EVIDENCE_REASON
    audit = _last_audit(db)
    assert audit.decision == "abstain"
    assert "相关性未达阈值" in audit.reason   # 真实原因只留在审计侧


# ------------------------------------------------------------------ 出口脱敏


def test_low_clearance_user_gets_masked_pii(db, client):
    """防：低密用户看到完整身份证号（合规硬伤，且不可逆）。"""
    user = _mk_user(db, "u1", clearance=1)
    doc = _mk_doc(db, "客户资料", clearance=1)
    _mk_chunk(db, doc, "客户身份证号码 11010519900307123X 已完成核验")
    db.commit()

    r = client.post(CHAT, json={"query": "客户身份证号码"},
                    headers={"Authorization": f"Bearer {create_token(user)}"})

    data = r.json()
    assert data["citations"], "本用例前提是确实召回了含 PII 的切片"
    assert data["masked"] is True
    assert "11010519900307123X" not in data["answer"]
    assert "11010519900307123X" not in str(data["citations"])


def test_high_clearance_user_sees_plaintext_pii(db, client):
    """防：脱敏口径过严——机密级用户连原文都看不到，业务停摆。

    注意 masked 在此处的语义是"回答里检出敏感标识（合规留痕）"，脱敏动作
    本身由密级门槛（>=2 看原文）决定；因此高密用户 masked 仍可能为 True，
    但正文必须是原样——本条钉的是后者。
    """
    boss = _mk_user(db, "boss", clearance=2)
    doc = _mk_doc(db, "客户资料", clearance=1)
    _mk_chunk(db, doc, "客户身份证号码 11010519900307123X 已完成核验")
    db.commit()

    r = client.post(CHAT, json={"query": "客户身份证号码"},
                    headers={"Authorization": f"Bearer {create_token(boss)}"})

    data = r.json()
    assert data["citations"]
    assert "11010519900307123X" in data["answer"], (
        "密级 >=2 的用户应看到原文（脱敏只针对低密级）")
