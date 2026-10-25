# SPDX-License-Identifier: AGPL-3.0-only
"""敏感信息识别与脱敏。

P1-5 扩展：在身份证/银行卡/手机号/邮箱/统一社会信用代码之外，新增
护照、港澳居民居住证、金融金额（上下文）、内网 IP、云密钥、JWT 六类；
并支持 PII_EXTRA_PATTERNS 环境变量注入自定义正则（启动时追加到
PATTERNS 尾部，解析失败只告警不阻断），以及可选的 NER 兜底
（PII_NER_URL，正则未命中时才调用，3s 超时、失败静默）。
"""
import json
import re
import sys
from dataclasses import dataclass

import httpx

from .config import LLM_MODEL, PII_EXTRA_PATTERNS, PII_NER_URL

# 顺序即优先级：scan() 按序匹配，命中区间后续模式跳过（occupied 去重）。
# 具体模式必须排在通用模式之前——18 位身份证要先于"银行卡/金融金额"的
# 15-19 位宽数字匹配，否则一串身份证号会被误判成金额；
# 港澳居民居住证（810000/820000 前缀 16 位）先于银行卡，同位长时归类更准。
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("身份证", re.compile(r"(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("护照", re.compile(r"(?<![A-Z0-9])[EGHMT]\d{8}(?![A-Z0-9])")),
    ("港澳居民居住证", re.compile(r"(?<!\d)8[12]0000\d{10}(?!\d)")),
    ("银行卡", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)")),
    ("手机号", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("邮箱", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("统一社会信用代码", re.compile(r"(?<!\w)[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}(?!\w)")),
    ("金融金额", re.compile(r"(?<!\d)\d{12,19}(?!\d)")),
    ("内网IP", re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")),
    ("云密钥", re.compile(r"(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
]

# 命中"银行卡"时若前后出现了这些关键词才认定，降低误报
_CARD_CTX = re.compile(r"(卡号|银行卡|账户|账号|开户|结算|储蓄|credit|account)", re.I)
# 命中"金融金额"的上下文：只有出现在资金语义附近的长数字才认定，
# 避免把订单号、样本编号等无害长数字一律当敏感信息
_AMOUNT_CTX = re.compile(r"(余额|转账|汇款|到账|金额|赔付|结算)", re.I)


@dataclass
class Hit:
    kind: str
    value: str
    start: int
    end: int


def _compile_extra(raw: str) -> list[tuple[str, re.Pattern]]:
    r"""解析 PII_EXTRA_PATTERNS（JSON 数组），启动时追加到 PATTERNS 尾部。

    支持两种条目：纯正则字符串（类型名记"自定义敏感信息"），或
    {"kind": "类型名", "pattern": "正则"}。JSON 里反斜杠必须双写
    （\\d 而非 \d）。解析失败只打印告警——自定义规则是增强项，
    坏配置绝不能阻断服务启动。
    """
    out: list[tuple[str, re.Pattern]] = []
    if not raw:
        return out
    try:
        items = json.loads(raw)
        if isinstance(items, str):
            items = [items]
        if not isinstance(items, list):
            raise ValueError("顶层必须是数组")
        for it in items:
            if isinstance(it, str):
                kind, src = "自定义敏感信息", it
            elif isinstance(it, dict) and it.get("pattern"):
                kind = str(it.get("kind") or "自定义敏感信息")
                src = str(it["pattern"])
            else:
                continue
            out.append((kind, re.compile(src)))
    except Exception as e:
        print(f"[pii] PII_EXTRA_PATTERNS 解析失败，已忽略该配置：{e}", file=sys.stderr)
    return out


PATTERNS.extend(_compile_extra(PII_EXTRA_PATTERNS))


def _ner_scan(text: str) -> list[Hit]:
    """可选 NER 兜底：正则未命中时调外部 NER 服务（OpenAI 兼容 chat 协议）。

    约定服务返回 JSON 数组：[{"kind": 类型, "value": 原文
    (, "start": 起点, "end": 终点)}, ...]；缺 start/end 时按 value 回查定位。
    3s 超时、非 200、格式不符、任何异常一律静默返回 []——
    NER 只是正则的补充通道，绝不能成为主链路的故障点或延迟源。
    """
    if not PII_NER_URL or not text:
        return []
    try:
        r = httpx.post(
            PII_NER_URL.rstrip("/") + "/chat/completions",
            json={
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content":
                        "你是敏感信息识别服务。找出用户文本中的敏感实体，"
                        "只输出 JSON 数组，每项为 {\"kind\": 类型, \"value\": 原文, "
                        "\"start\": 起点, \"end\": 终点}；没有则输出 []。"},
                    {"role": "user", "content": text},
                ],
                "temperature": 0,
            },
            timeout=3,
        )
        if r.status_code != 200:
            return []
        content = r.json()["choices"][0]["message"]["content"] or ""
        items = json.loads(content)
        hits: list[Hit] = []
        for it in items if isinstance(items, list) else []:
            value = str(it.get("value") or "")
            if not value:
                continue
            start, end = it.get("start"), it.get("end")
            if not isinstance(start, int) or not isinstance(end, int):
                idx = text.find(value)
                if idx < 0:
                    continue
                start, end = idx, idx + len(value)
            hits.append(Hit(str(it.get("kind") or "NER识别"), value, start, end))
        return hits
    except Exception:
        return []


def scan(text: str) -> list[Hit]:
    hits: list[Hit] = []
    occupied: list[tuple[int, int]] = []
    for kind, pat in PATTERNS:
        for m in pat.finditer(text or ""):
            s, e = m.span()
            if any(s < oe and os_ < e for os_, oe in occupied):
                continue
            if kind == "银行卡":
                ctx = text[max(0, s - 12):e + 12]
                if not _CARD_CTX.search(ctx):
                    continue
            if kind == "金融金额":
                ctx = text[max(0, s - 12):e + 12]
                if not _AMOUNT_CTX.search(ctx):
                    continue
            occupied.append((s, e))
            hits.append(Hit(kind, m.group(), s, e))
    # 正则零命中时才走 NER 兜底（默认关闭）：不增加已有链路的任何延迟
    if not hits:
        hits = _ner_scan(text or "")
    return sorted(hits, key=lambda h: h.start)


def mask_value(v: str) -> str:
    n = len(v)
    if n <= 4:
        return "*" * n
    if n <= 8:
        return v[:1] + "*" * (n - 2) + v[-1:]
    return v[:3] + "*" * (n - 7) + v[-4:]


def mask(text: str) -> tuple[str, int]:
    """按位置从后往前替换，返回 (脱敏文本, 命中数)。"""
    hits = scan(text)
    if not hits:
        return text, 0
    out = list(text)
    for h in reversed(hits):
        out[h.start:h.end] = list(mask_value(h.value))
    return "".join(out), len(hits)


def redact_for_level(text: str, user_clearance: int) -> tuple[str, int]:
    """密级 >=2（机密/绝密）的用户可看原文，低密级一律脱敏后返回。"""
    if user_clearance >= 2:
        return text, 0
    return mask(text)
