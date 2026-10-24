# SPDX-License-Identifier: Apache-2.0
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..audit import write_log
from ..config import (
    FAIL_SECURE_ENABLED, INJECT_BLOCK_OUTPUT, JIGSAW_RECALL_FACTOR, LEVEL_NAMES,
    MAX_CONTEXT_CHARS, MAX_QUERY_CHARS, NO_EVIDENCE_REASON, NO_EVIDENCE_TEXT, TOP_K,
)
from ..db import get_db
from ..injection import scan_injection
from ..intent import classify as classify_intent
from ..jigsaw import effective_risk, evaluate, is_high_risk
from ..models import User
from ..pii import mask, redact_for_level, scan
from ..retrieve import (
    extract_terms, is_reliable, public_only_search, search, unauthorized_probe,
)
from ..schemas import ChatIn, ChatOut, Citation
from ..security import current_user
from .auth import client_ip
from .. import llm

router = APIRouter(prefix="/chat", tags=["智能问答"])

# 无依据拒答：文案与原因统一中性（见 config.NO_EVIDENCE_TEXT）。
# 用户侧看不到"授权/相关性阈值"等口径，避免反推受限内容是否存在。
REFUSE = NO_EVIDENCE_TEXT
DEGRADE_REFUSE = (
    "安全降级中：权限或检索组件异常，内部知识库已按 Fail-Secure 规范切断，"
    "本轮亦无公开域依据，按「宁可不答，绝不越权」策略不予作答。"
)
INJECT_REFUSE = (
    "检测到本轮回答包含疑似提示注入内容，已按安全策略拦截。"
    "请尝试调整提问方式；如确认是知识库文档被投毒，请联系安全管理员核查。"
)

# 审计 decision 优先级：安全事件 > 合规硬留痕 > 注入标记 > 限流 > 约束 > 正常。
# flag 置于 mask 之后：mask 是已确认的敏感信息外泄（合规硬留痕项，最优先）；
# flag 是"疑似注入"的安全信号——比限流/约束更值得运营关注（可能对应攻击
# 尝试或投毒文档），但严重度不及已确认的脱敏事件，故列在 mask 之后。
_DECISION_ORDER = ["degrade", "block", "mask", "flag", "throttle", "constrain", "allow"]


def _pick_decision(*present: str) -> str:
    for d in _DECISION_ORDER:
        if d in present:
            return d
    return "allow"


@router.post("", response_model=ChatOut)
def chat(body: ChatIn, request: Request,
         user: User = Depends(current_user), db: Session = Depends(get_db)):
    query = (body.query or "").strip()
    if not query:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "问题不能为空")
    if len(query) > MAX_QUERY_CHARS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"问题过长（超过 {MAX_QUERY_CHARS} 字符）")

    # ================= 第零道：账号风险分拦截（P1-7）=================
    # 放在意图网关之前：最便宜的门最先。账号已因长期异常访问模式进入人工审核，
    # 再去做意图分类和向量检索纯属浪费——直接隔离，等人工复位。
    if is_high_risk(user):
        reason = (
            f"账号访问模式异常（长期累计拉取风险分 "
            f"{effective_risk(user.risk_score, user.last_risk_ts)}），"
            f"已转为人工审核，期间暂停问答。如需恢复请联系合规管理员。"
        )
        log = write_log(db, user=user, action="chat", query=query,
                        decision="throttle", reason=reason, ip=client_ip(request),
                        detail=json.dumps({"risk": user.risk_score}, ensure_ascii=False))
        return ChatOut(
            answer="该账号的访问模式已被判定为异常，已转人工审核，暂停应答。",
            blocked=True, block_reason="长期累计异常访问：已转人工审核",
            jigsaw={"level": "none", "message": "", "docs": [], "window": {}},
            intent={"level": "safe", "action": "pass", "signals": [], "message": ""},
            audit_id=log.id,
        )

    top_k = body.top_k if body.top_k and body.top_k > 0 else TOP_K
    terms = extract_terms(query)
    ip = client_ip(request)
    is_admin = "admin" in user.role_list()

    # ================= 第一道：前置意图识别网关 =================
    # Safe → 放行；Risky → 推理距离约束；Danger（拼图式诱导探针）→ 物理阻断，
    # 不进入检索链路，从源头截断诱导套取。
    intent = classify_intent(db, user, query)
    if intent["level"] == "danger":
        log = write_log(
            db, user=user, action="chat", query=query, decision="block",
            reason=f"意图网关阻断：{'；'.join(intent['signals'])}", ip=ip,
            detail=json.dumps({"intent": intent}, ensure_ascii=False),
        )
        return ChatOut(
            answer=intent["message"], blocked=True,
            block_reason="意图识别网关：拼图式诱导探针，已物理阻断",
            intent=intent, audit_id=log.id,
        )

    # ================= 第二道：双校验检索（粗筛 + 精校验） =================
    # 多召回：防拼图裁剪会占用名额。若只按 top_k 召回，一篇被限流的文档
    # 就会挤掉其他文档的位置，把整轮回答拖空——那是限流误伤，不是安全收益。
    fail_secure = False
    try:
        hits, denied, verify = search(db, user, query, top_k * JIGSAW_RECALL_FACTOR)
    except Exception as e:
        # Fail-Secure：权限/检索组件异常 → 切断内部知识库，降级到公开域。
        # 宁可答非所问或保持沉默，也绝不能多吐出一个越权字。
        if not FAIL_SECURE_ENABLED:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "检索组件异常")
        fail_secure = True
        verify = {"mode": "fail_secure", "coarse": {}, "fine": {}, "implicit_verify": False}
        try:
            hits, denied, verify = public_only_search(db, query, top_k)
            verify["mode"] = "fail_secure_public_only"
        except Exception:
            log = write_log(
                db, user=user, action="chat", query=query, decision="degrade",
                reason=f"Fail-Secure：检索组件异常（{type(e).__name__}），内部知识库已切断",
                ip=ip, detail=json.dumps({"error": type(e).__name__}, ensure_ascii=False),
            )
            return ChatOut(
                answer=DEGRADE_REFUSE, blocked=True,
                block_reason="Fail-Secure：权限/检索组件异常，已降级断联",
                fail_secure=True, intent=intent, audit_id=log.id,
            )

    # 元数据明文泄漏封堵：越权文档的 ID/密级/原因对普通用户是强旁路信号，
    # 只透出"有拦截"这个事实；完整明细仅管理员可见（审计侧永远全量）。
    # 刻意定义在两条早退分支之前——早退路径也要按同一口径封堵（曾漏：
    # 防拼图阻断 / 无依据拒答 两处直接透传原始 denied，见 test_chat_pipeline）。
    denied_out = denied if is_admin else [{"blocked": True} for _ in denied]

    # ================= 第三道：防拼图累积暴露裁决 =================
    hits, jig = evaluate(db, user, hits)

    # ================= 推理距离约束（Risky）：切断因果串联 =================
    # 跨域组合联想题只保留得分最高的单一文档，禁止把多篇文档的碎片
    # 放进同一个提示词让模型做归纳推断——大模型的归纳能力本身就是攻击面。
    # 必须放在拼图裁决之后：账本要看到完整候选集才能识别"新碎片"，
    # 提前裁剪会把已见碎片顶成唯一候选，覆盖率闸将永远看不到真正的新碎片。
    constrained = intent["level"] == "risky" and len(hits) > 0
    if constrained:
        top_doc = hits[0].doc_id
        hits = [h for h in hits if h.doc_id == top_doc][:1]

    hits = hits[:top_k]

    # 越权命中统计是强旁路信号：告诉攻击者"你这个问题命中了几篇绝密文档"，
    # 等于给拼图攻击装了导航仪。仅对管理员开放，普通用户恒为 0（审计仍留全量）。
    probe = (unauthorized_probe(db, user, query)
             if (is_admin and not fail_secure) else {"total": 0, "by_level": {}})

    # ---- 防拼图 block：短窗口额度耗尽（L3）或近 N 日累计超限（L5）----
    # block_reason 取引擎给出的真实原因：两道闸的处置方式不同（短窗口熬过去即可，
    # 长周期要观察 7 天），笼统标成"时间窗额度耗尽"会让运维误判严重级别。
    if jig.get("level") == "block":
        _msg = jig.get("message") or "已触发防批量拉取保护，暂停应答。"
        log = write_log(
            db, user=user, action="chat", query=query, decision="throttle",
            reason=_msg, ip=ip,
            detail=json.dumps({"jigsaw": jig, "probe": probe}, ensure_ascii=False),
        )
        return ChatOut(
            answer=_msg,
            blocked=True, block_reason=_msg,
            jigsaw=jig, denied_docs=denied_out, probe_total=int(probe.get("total", 0)),
            intent=intent, verify=verify, fail_secure=fail_secure, audit_id=log.id,
        )

    throttled = jig.get("level") in ("warn", "restrict")

    # ---- 无任何可用依据：区分"相关性不足"与"被防拼图裁掉" ----
    # 真实原因只进审计；block_reason 走中性文案（NO_EVIDENCE_REASON），
    # 否则用户能靠"相关性未达阈值"反推：库里有相关资料但自己无权取。
    if not hits or not is_reliable(hits, len(terms)):
        throttled_empty = throttled and not hits
        reason = ("防拼图保护：相关但该内容已在本时间窗内充分披露，不再重复供给"
                  if throttled_empty
                  else "检索相关性未达阈值，已拒答")
        user_reason = (
            (jig.get("message") or "相关内容已在本时间窗内充分披露，不再重复供给")
            if throttled_empty else NO_EVIDENCE_REASON
        )
        decision = ("throttle" if throttled
                    else "degrade" if fail_secure else "abstain")
        log = write_log(
            db, user=user, action="chat", query=query, decision=decision,
            reason=reason, ip=ip,
            detail=json.dumps({"jigsaw": jig, "probe": probe, "denied": denied,
                               "intent": intent}, ensure_ascii=False),
        )
        return ChatOut(
            answer=REFUSE, blocked=True, block_reason=user_reason, jigsaw=jig,
            denied_docs=denied_out, probe_total=int(probe.get("total", 0)),
            intent=intent, verify=verify, fail_secure=fail_secure, audit_id=log.id,
        )

    contexts: list[tuple[str, str, str]] = []
    citations: list[Citation] = []
    total, masked = 0, False
    for h in hits:
        content, n = redact_for_level(h.content, user.clearance)
        if n:
            masked = True
        if contexts and total + len(content) > MAX_CONTEXT_CHARS:
            break
        label = str(len(contexts) + 1)
        contexts.append((label, h.doc_title, content))
        total += len(content)
        citations.append(Citation(
            doc_id=h.doc_id, doc_title=h.doc_title, clearance=h.clearance,
            clearance_name=LEVEL_NAMES.get(h.clearance, ""), seq=h.seq,
            score=round(h.score, 4), snippet=content[:200],
        ))

    answer, degraded = llm.answer(query, contexts)

    # 出口二次扫描：防止模型生成/复述敏感标识
    out_hits = scan(answer)
    if out_hits:
        masked = True
        if user.clearance < 2:
            answer, _ = mask(answer)

    # 限流/约束/降级时把提示附在答案尾部，让使用者明确知道为何内容变少
    if throttled and jig.get("message"):
        answer = f"{answer}\n\n> ⚠️ 防拼图保护：{jig['message']}"
    if constrained:
        answer = (f"{answer}\n\n> ⚠️ 推理距离约束：{intent['message']}")
    if fail_secure:
        answer = (f"{answer}\n\n> ⚠️ 安全降级：权限/检索组件异常，"
                  f"本次仅基于 Public 公开域作答，未连接内部知识库。")

    # 出口注入扫描（P1-4）：模型生成/复述的内容里出现"忽略规则/输出提示词"
    # 类话术 → 标记留痕；INJECT_BLOCK_OUTPUT=true 时直接替换为安全拒答。
    # 默认不拦截：正则误报不应把正常业务回答一刀切掉（宁标记，不误伤）。
    inject_hits = scan_injection(answer)
    inject_flag = inject_hits > 0
    if inject_flag and INJECT_BLOCK_OUTPUT:
        answer = INJECT_REFUSE

    # decision 语义分离：脱敏是合规硬留痕项，不能被限流状态覆盖掉
    decision = _pick_decision(
        "degrade" if fail_secure else "",
        "mask" if masked else "",
        "flag" if inject_flag else "",
        "throttle" if throttled else "",
        "constrain" if constrained else "",
    )
    reason = (f"命中{len(citations)}段 / 拦截越权{len(denied)}篇"
              + (f" / 越权候选{probe.get('total', 0)}篇" if is_admin else "")
              + (f" / 防拼图：{jig['message']}" if throttled else "")
              + (" / 推理距离约束" if constrained else "")
              + (" / Fail-Secure 降级" if fail_secure else "")
              + (f" / 检出疑似提示注入 {inject_hits} 处" if inject_flag else ""))
    log = write_log(
        db, user=user, action="chat", query=query,
        decision=decision,
        target_label="；".join(dict.fromkeys(c.doc_title for c in citations))[:255],
        reason=reason,
        ip=ip,
        detail=json.dumps({
            "citations": [c.model_dump() for c in citations],
            "denied": denied, "probe": probe, "degraded": degraded, "jigsaw": jig,
            "intent": intent, "verify": verify, "fail_secure": fail_secure,
            "inject_hits": inject_hits,
        }, ensure_ascii=False),
    )
    return ChatOut(
        answer=answer, citations=citations, masked=masked, degraded=degraded,
        denied_docs=denied_out, probe_total=int(probe.get("total", 0)),
        jigsaw=jig, intent=intent, verify=verify, fail_secure=fail_secure,
        inject_flag=inject_flag, audit_id=log.id,
    )
