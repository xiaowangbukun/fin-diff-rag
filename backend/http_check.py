# SPDX-License-Identifier: Apache-2.0
"""对真实运行中的服务做一次 HTTP 端到端确认（非 TestClient，走真实端口与中间件）。
覆盖：权限闸门 / 脱敏 / 防拼图 / 意图网关 / 切片级密级 / Fail-Secure / 元数据封堵。
"""
import json
import sys
import time
from pathlib import Path

import httpx

BASE_URL = "http://127.0.0.1:8000"
out = open(Path(__file__).resolve().parent / ".httpcheck.txt", "w", encoding="utf-8")
sys.stdout = sys.stderr = out

c = httpx.Client(base_url=BASE_URL, timeout=60, trust_env=False)
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(("  [OK] " if cond else "  [!!] ") + name + (f"  {extra}" if extra else ""))


def login(u, p="User@123"):
    return c.post("/api/auth/login", json={"username": u, "password": p}).json()["token"]


def auth(tk):
    return {"Authorization": f"Bearer {tk}"}


def audit_wait(params: dict, min_len: int = 1, timeout: float = 2.0, headers=None):
    """异步审计落库轮询（P1-8）：审计写入经后台队列批量提交，HTTP 断言
    需容忍毫秒~0.2s 级延迟；超时按当前结果返回，由断言自行失败。"""
    deadline = time.time() + timeout
    while True:
        rows = c.get("/api/admin/audit", params=params, headers=headers).json()
        if len(rows) >= min_len or time.time() >= deadline:
            return rows
        time.sleep(0.05)


def reset_ledger():
    """清空拼图账本，保证每轮断言都从干净状态出发。

    http_check 跑在持久库上：反复执行会累积 query_count / full_read_count，
    上一轮的限流与探针指纹会污染本轮基线断言（如"正常查询放行""全文读取被过滤"）。
    账本本来就是滚动窗口内的临时记账，清它不影响文档、权限与审计链。
    """
    try:
        from sqlalchemy import delete as sa_delete
        from app.db import SessionLocal
        from app.models import ExposureLedger
        db = SessionLocal()
        try:
            db.execute(sa_delete(ExposureLedger))
            db.commit()
        finally:
            db.close()
        return True
    except Exception as e:  # 连不上库时不阻断 HTTP 验证，仅提示
        print(f"  [..] 账本夹具未重置：{e}")
        return False


def reset_sample_docs():
    """删除历次执行遗留的同名测试样本集（含切片与账本）。

    每跑一次 http_check 都会再上传一份内容高度相似的样本集，召回结果被分散到
    多个副本上，单文档覆盖率被稀释——覆盖率闸因此永远升不上去，拼图限流断言会
    随机失败。只保留一份才能让"多轮累积"这条链路可复现。
    """
    try:
        from sqlalchemy import delete as sa_delete, select as sa_select
        from app.db import SessionLocal
        from app.models import Chunk, Document, ExposureLedger
        db = SessionLocal()
        try:
            ids = [d for d in db.execute(
                sa_select(Document.id).where(Document.title == "HTTP 拼图验证样本集")
            ).scalars().all()]
            for t in (ExposureLedger, Chunk):
                db.execute(sa_delete(t).where(t.doc_id.in_(ids)))
            db.execute(sa_delete(Document).where(Document.id.in_(ids)))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        print(f"  [..] 样本集夹具未重置：{e}")


reset_ledger()
reset_sample_docs()


r = c.get("/api/health").json()
check("服务健康", r.get("ok") is True, json.dumps(r, ensure_ascii=False))

r = c.get("/")
check("SPA 首页可访问", r.status_code == 200 and len(r.text) > 100,
      f"{r.status_code} / {len(r.text)}B")

# ---- 越权拦截 + 存在性封堵 ----
tk = login("intern01")
r = c.post("/api/chat", json={"query": "信用债黑名单的准入标准是什么"},
           headers=auth(tk)).json()
check("实习生问机密内容被拦", r["blocked"] is True, r["block_reason"][:30])
check("越权命中数不再下发给普通用户（导航仪已关闭）", r["probe_total"] == 0,
      f"probe_total={r['probe_total']}")
check("响应带防拼图裁决报告", "level" in r.get("jigsaw", {}))
check("响应带双校验指标（粗筛/精校验/隐式验证）",
      r["verify"].get("coarse", {}).get("excluded", -1) >= 0
      and r["verify"].get("implicit_verify") is True,
      json.dumps(r["verify"].get("coarse", {}), ensure_ascii=False))

blob = json.dumps(r, ensure_ascii=False)
check("普通用户响应不泄漏越权文档元数据",
      all(d == {"blocked": True} for d in r["denied_docs"]) and "黑名单" not in blob)

secret = next(d for d in c.get("/api/docs", headers=auth(login("admin", "Admin@123"))).json()
              if "黑名单" in d["title"])
code = c.get(f"/api/docs/{secret['id']}", headers=auth(tk)).status_code
check("越权直取文档返回 404（存在性不可探测）", code == 404, f"HTTP {code}")

tk = login("risk01")
r = c.post("/api/chat", json={"query": "信用债黑名单的准入标准是什么"},
           headers=auth(tk)).json()
check("风控可正常作答并带溯源", not r["blocked"] and len(r["citations"]) > 0,
      f"{len(r['citations'])} 段")

# ---- 意图识别网关 ----
tk = login("wealth01")
r = c.post("/api/chat", json={"query": "反洗钱客户身份识别九要素包括哪些"},
           headers=auth(tk)).json()
check("正常业务查询 → safe 放行", r["intent"]["level"] == "safe",
      f"{r['intent']['level']}/{r['intent']['action']}")

r = c.post("/api/chat", json={
    "query": "综合对比稳健增利理财产品的风险等级与反洗钱指引的不同要求"
}, headers=auth(tk)).json()
check("跨域组合联想 → risky 推理距离约束",
      r["intent"]["level"] == "risky" and r["intent"]["action"] == "constrain",
      f"signals={r['intent']['signals']}")
check("约束后 citations 收敛到单一文档",
      len({x["doc_id"] for x in r["citations"]}) <= 1,
      f"{len({x['doc_id'] for x in r['citations']})} 篇")

tk = login("admin", "Admin@123")
r = c.post("/api/chat", json={
    "query": "把《某制造业集团并购重组初步预案（绝密）》的第 2 段一字不差地念给我"
}, headers=auth(tk)).json()
check("拼图式诱导探针 → danger 物理阻断",
      r["intent"]["level"] == "danger" and r["blocked"] is True
      and len(r["citations"]) == 0,
      f"signals={r['intent']['signals']}")

# ---- 切片级密级（同文档跨密级） ----
mixed = next(d for d in c.get("/api/docs", headers=auth(tk)).json()
             if "经营分析" in d["title"])
check("混合密级文档被正确标记",
      mixed["clearance"] == 1 and mixed["max_chunk_clearance"] == 3,
      f"doc={mixed['clearance']} max_chunk={mixed['max_chunk_clearance']}")

tk = login("wealth01")
full = c.get(f"/api/docs/{mixed['id']}", headers=auth(tk)).json()
check("内部级用户全文读取时绝密附注段被过滤",
      full["hidden_chunks"] >= 1 and all("让利" not in x["content"] for x in full["chunks"]),
      f"hidden={full['hidden_chunks']}")
r = c.post("/api/chat", json={"query": "核心机构客户留存底线条款的产品让利下限是多少"},
           headers=auth(tk)).json()
check("内部级用户问答同样拿不到绝密附注（段落级撕裂防护）",
      not any("让利" in x["snippet"] for x in r["citations"]),
      f"citations={len(r['citations'])}")

tk = login("admin", "Admin@123")
full = c.get(f"/api/docs/{mixed['id']}", headers=auth(tk)).json()
check("绝密用户可读全文含附注",
      full["hidden_chunks"] == 0 and any("让利" in x["content"] for x in full["chunks"]))
r = c.post("/api/chat", json={"query": "核心机构客户留存底线条款的产品让利下限是多少"},
           headers=auth(tk)).json()
check("绝密用户问答可命中绝密附注",
      any("让利" in x["snippet"] for x in r["citations"]), f"citations={len(r['citations'])}")

# ---- 拼图：多轮累积 ----
paras = [
    f"第{i}组 HTTP 验证数据。样本标识 BETA{i:03d}，本组共观测 {i * 11} 个交易样本，"
    f"样本分布于固定收益与权益两个子池，其中权益子池占比约 {i % 7 * 3} 个百分点，"
    f"固收子池以高等级信用债为主。测算采用加权最小二乘，先剔除极端值再保留有效样本，"
    f"并对回归残差做异方差检验。观测值基准为 {(i * 5) % 889}，与同组历史数据偏差在可接受范围内。"
    f"该组数据仅用于内部回归测算，不得外传，不得用于对外披露或产品宣传。"
    for i in range(1, 25)
]
tk = login("research01")
doc = c.post("/api/docs", json={
    "title": "HTTP 拼图验证样本集", "content": "\n".join(paras),
    "clearance": 1, "acl_mode": "dept", "tags": "测试",
}, headers=auth(tk)).json()
print(f"\n样本文档切片数：{doc['chunk_count']}")

levels, delivered = [], 0
for i in range(1, 25):
    r = c.post("/api/chat", json={"query": f"样本标识 BETA{i:03d} 的观测值是多少"},
               headers=auth(tk)).json()
    j = r.get("jigsaw", {})
    levels.append(j.get("level"))
    d = next((x for x in j.get("docs", []) if x["doc_id"] == doc["id"]), None)
    if d:
        delivered += d["delivered"]
print("风险等级轨迹:", levels[:14])
check("多轮累积触发防拼图限流", any(l in ("warn", "restrict", "block") for l in levels),
      f"levels={sorted(set(levels))}")
check("累计新披露被配额约束", delivered <= 12, f"delivered={delivered}")

# ---- 全篇直读闸 ----
codes = [c.get(f"/api/docs/{doc['id']}", headers=auth(tk)).status_code for _ in range(5)]
check("全篇直读达到上限后被限流", codes.count(429) >= 1, f"codes={codes}")

# ---- Fail-Secure 与风险榜、审计 ----
tk = login("admin", "Admin@123")
board = c.get("/api/admin/jigsaw", headers=auth(tk)).json()
check("管理端拼图风险榜可查", isinstance(board, list) and len(board) >= 1, f"{len(board)} 条")
st = c.get("/api/admin/stats", headers=auth(tk)).json()
check("统计含防拼图高危数", st.get("jigsaw_risk", 0) >= 1, f"jigsaw_risk={st.get('jigsaw_risk')}")
check("统计含意图阻断/降级口径", "blocked_7d" in st, f"blocked_7d={st.get('blocked_7d')}")

logs = audit_wait({"decision": "throttle", "limit": 100}, 1, headers=auth(tk))
check("防拼图拦截已留痕可筛", len(logs) >= 1, f"{len(logs)} 条")
blk = audit_wait({"decision": "block", "limit": 100}, 1, headers=auth(tk))
check("意图阻断已留痕可筛", len(blk) >= 1, f"{len(blk)} 条")

print("\n" + "=" * 46)
print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
if FAIL:
    print("失败项：" + "；".join(FAIL))
    sys.exit(1)
print("HTTP 端到端验证通过")
