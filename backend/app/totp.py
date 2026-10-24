# SPDX-License-Identifier: Apache-2.0
"""TOTP（RFC 6238）实现与密钥静态加密。

为什么自己实现而不引第三方库：算法只有 HMAC-SHA1 + 动态截断两段，标准
公开、实现可测（RFC 6238 附录 B 有官方测试向量，见 tests/test_totp.py）；
少一个依赖就少一次内网离线镜像的供应链审查。

安全口径：
  · 密钥随机 160 bit（base32），只在校验与绑定响应里短暂出现；
  · 静态加密后再入库（Fernet/AES-CBC+HMAC，密钥来自 MFA_SECRET_KEY 或
    由 JWT_SECRET 派生）；没有密钥材料时拒绝绑定，而不是明文存第二因子；
  · 校验用常量时间比较，且记录已用过的步长（totp_last_step）——同一个
    动态口令不能在有效窗口内重放第二次；
  · 允许前后各 TOTP_WINDOW_STEPS 个时间步的时钟漂移，再宽就是给爆破让路。
"""
import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

from . import config as cfg

_ENC_PREFIX = "enc:v1:"


def generate_secret(nbytes: int = 20) -> str:
    """生成 base32 密钥（无填充，兼容 Google Authenticator / 1Password）。"""
    return base64.b32encode(os.urandom(nbytes)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    s = (secret or "").strip().replace(" ", "").upper()
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad, casefold=True)


def step_at(at: float | None = None, period: int | None = None) -> int:
    return int((at if at is not None else time.time()) // (period or cfg.TOTP_PERIOD))


def code_at(secret: str, at: float | None = None, digits: int | None = None,
            period: int | None = None) -> str:
    """指定时刻的动态口令（RFC 4226 HOTP 的 TOTP 包装）。"""
    digits = digits or cfg.TOTP_DIGITS
    period = period or cfg.TOTP_PERIOD
    counter = step_at(at, period)
    mac = hmac.new(_decode_secret(secret), struct.pack(">Q", counter),
                   hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify(secret: str, code: str, at: float | None = None,
           window: int | None = None, last_step: int = 0,
           digits: int | None = None, period: int | None = None) -> int | None:
    """校验动态口令；通过返回命中的时间步，失败返回 None。

    last_step 是"上次成功用过的时间步"：重放同一口令会命中同一步，
    这里直接拒绝（RFC 6238 §5.2 的建议）。
    """
    code = (code or "").strip().replace(" ", "")
    digits = digits or cfg.TOTP_DIGITS
    if not code.isdigit() or len(code) != digits:
        return None
    window = cfg.TOTP_WINDOW_STEPS if window is None else window
    current = step_at(at, period)
    matched: int | None = None
    for offset in range(-window, window + 1):
        step = current + offset
        if step <= int(last_step or 0):
            continue
        candidate = code_at(secret, step * (period or cfg.TOTP_PERIOD),
                            digits, period)
        if hmac.compare_digest(candidate, code) and matched is None:
            matched = step
    return matched


def provisioning_uri(secret: str, account: str, issuer: str | None = None) -> str:
    """otpauth:// 供给 URI（前端可自行渲染二维码，或手抄密钥）。"""
    issuer = issuer or cfg.TOTP_ISSUER
    label = quote(f"{issuer}:{account}", safe="")
    params = (
        f"secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={cfg.TOTP_DIGITS}&period={cfg.TOTP_PERIOD}"
    )
    return f"otpauth://totp/{label}?{params}"


# ---------------- 密钥静态加密 ----------------

def _key_material() -> bytes | None:
    """Fernet 密钥：显式配置优先，否则由 JWT_SECRET 派生；都没有则返回 None。"""
    raw = (cfg.MFA_SECRET_KEY or "").strip()
    if raw:
        return raw.encode("ascii")
    if cfg.JWT_SECRET:
        digest = hashlib.sha256(
            ("finrag-totp|" + cfg.JWT_SECRET).encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)
    return None


def encryption_ready() -> bool:
    return _key_material() is not None


def seal(secret: str) -> str:
    """加密后入库；没有可用密钥时抛 RuntimeError（调用方转 503）。"""
    key = _key_material()
    if key is None:
        raise RuntimeError(
            "未配置 MFA_SECRET_KEY（且 JWT_SECRET 为空），无法安全存储动态口令密钥。"
        )
    token = Fernet(key).encrypt(secret.encode("ascii")).decode("ascii")
    return _ENC_PREFIX + token


def unseal(stored: str) -> str:
    """解密；兼容历史明文（无前缀）以便排障，但新写入一律加密。"""
    raw = (stored or "").strip()
    if not raw:
        return ""
    if not raw.startswith(_ENC_PREFIX):
        return raw
    key = _key_material()
    if key is None:
        raise RuntimeError("未配置 MFA_SECRET_KEY，无法解密已绑定的动态口令密钥。")
    try:
        return Fernet(key).decrypt(raw[len(_ENC_PREFIX):].encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise RuntimeError(
            "动态口令密钥解密失败：MFA_SECRET_KEY/JWT_SECRET 可能已轮换。"
            "请由管理员重置该账号的动态口令后重新绑定。"
        ) from exc


def is_enrolled(user) -> bool:
    return bool(getattr(user, "totp_confirmed_at", None))
