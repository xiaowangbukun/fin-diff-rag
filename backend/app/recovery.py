# SPDX-License-Identifier: AGPL-3.0-only
"""一次性恢复码（备用码）：TOTP 绑定的自助恢复通道。

定位：手机丢失/换机时，用户不必等管理员重置就能登录一次，然后在安全
设置里重新绑定验证器；恢复码用完即废，且管理员重置仍是最终出口。

安全口径：
  · 高熵：12 个字符取自 32 字母表（去掉 0/O/1/I 等易混字符）= 60 bit，
    暴力枚举不可行；因此不需要 PBKDF2 那样的慢哈希——用服务端密钥做
    HMAC-SHA256 即可（密文泄露也推不出码，且验证是常数时间，不会把
    登录拖成 10 × 60 万次迭代）。
  · 只存摘要，不存明文；只在生成/重新生成时一次性返回给用户。
  · 用一次即标记 used_at，重放同一个码无效；全部用完即拒绝，提示找
    管理员重置（避免"最后一个码被反复试"）。
  · 换绑/解绑 TOTP、管理员重置第二因子都会清空恢复码——否则旧码会成为
    绕过新验证器的后门。
"""
import hashlib
import hmac
import json
import secrets
from datetime import datetime

from . import config as cfg

# 去掉 0/O/1/I/L 等易错字符，避免用户手抄出错（手抄错误率比熵更重要）
ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
GROUPS, GROUP_LEN = 3, 4
CODE_LEN = GROUPS * GROUP_LEN


def _key() -> bytes | None:
    raw = (cfg.MFA_SECRET_KEY or "").strip() or (cfg.JWT_SECRET or "").strip()
    if not raw:
        return None
    return hashlib.sha256(("finrag-recovery|" + raw).encode("utf-8")).digest()


def available() -> bool:
    return _key() is not None


def normalize(code: str) -> str:
    """容忍小写、空格、连字符（用户从纸上抄进来的样子）。

    只保留 ASCII 字母数字：`str.isalnum()` 对中文/全角字符也返回 True，
    而 _digest 侧按 ASCII 编码——不过滤就会把"用户把恢复码位置填了中文"
    变成 500（UnicodeEncodeError），而不是一次正常的 401。
    """
    return "".join(ch for ch in (code or "").upper()
                   if ("A" <= ch <= "Z") or ("0" <= ch <= "9"))


def _digest(key: bytes, code: str) -> str:
    return hmac.new(key, normalize(code).encode("ascii"), hashlib.sha256).hexdigest()


def _raw_code() -> str:
    chars = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LEN))
    return "-".join(chars[i:i + GROUP_LEN] for i in range(0, CODE_LEN, GROUP_LEN))


def generate(count: int | None = None) -> tuple[list[str], str]:
    """生成一组恢复码；返回 (明文列表, 待入库的 JSON)。只调用一次即丢明文。"""
    key = _key()
    if key is None:
        raise RuntimeError(
            "未配置 MFA_SECRET_KEY（且 JWT_SECRET 为空），无法生成恢复码。")
    n = cfg.RECOVERY_CODE_COUNT if count is None else count
    codes = [_raw_code() for _ in range(max(1, n))]
    blob = {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "codes": [{"h": _digest(key, c), "used_at": ""} for c in codes],
    }
    return codes, json.dumps(blob)


def parse(blob: str | None) -> dict:
    """解析入库 JSON；损坏/为空一律当"没有恢复码"，不让登录 500。"""
    if not blob:
        return {"generated_at": "", "codes": []}
    try:
        data = json.loads(blob)
    except (TypeError, ValueError):
        return {"generated_at": "", "codes": []}
    if not isinstance(data, dict) or not isinstance(data.get("codes"), list):
        return {"generated_at": "", "codes": []}
    codes = [c for c in data["codes"] if isinstance(c, dict) and c.get("h")]
    return {"generated_at": data.get("generated_at", ""), "codes": codes}


def remaining(blob: str | None) -> int:
    return sum(1 for c in parse(blob)["codes"] if not c.get("used_at"))


def total(blob: str | None) -> int:
    return len(parse(blob)["codes"])


def consume(blob: str | None, code: str) -> tuple[bool, str, int]:
    """校验并消耗一个恢复码；返回 (是否通过, 新的入库 JSON, 剩余可用数)。

    即使命中也要把整张表比完（常数时间遍历），避免"第几个码"从耗时泄漏。
    """
    key = _key()
    data = parse(blob)
    if key is None or not normalize(code) or not data["codes"]:
        return False, blob or "", remaining(blob)
    target = _digest(key, code)
    hit = -1
    for idx, item in enumerate(data["codes"]):
        same = hmac.compare_digest(str(item.get("h", "")), target)
        if same and not item.get("used_at") and hit < 0:
            hit = idx
    if hit < 0:
        return False, blob or "", remaining(blob)
    data["codes"][hit]["used_at"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    new_blob = json.dumps(data)
    return True, new_blob, remaining(new_blob)


def clear() -> str:
    return ""
