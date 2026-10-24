# SPDX-License-Identifier: Apache-2.0
"""口令强度策略：唯一的校验入口，登录改密与管理员设密共用同一口径。

为什么把策略从"长度 ≥8"抬到"12 位 + 三类字符"：
  · 该项目此前允许 admin 建号时留空 → 默认 Fin@123456，实测可直接登录；
  · 在线爆破虽有 loginthrottle 兜底，但口令一旦泄露（截图、复用、聊天记录），
    限流完全不设防。金融内网账号的最低要求是"拿到用户名也没法直接撞开"。

刻意不做的事：
  · 不强制"90 天更换"：强制轮换会催生 Spring2024! → Spring2025! 这类可预测
    变更，NIST SP 800-63B 明确反对；改密由事件触发（首登、泄露、管理员重置）。
  · 不保存口令历史（需要额外表与比对成本），只禁止"新口令 = 旧口令"。
"""
import re

# 常见弱口令（含本项目历史默认口令）：命中小写归一化后直接拒。
# 不追求完整字典——完整字典应由部署侧的 pwned 库/企业口令库补充。
WEAK_PASSWORDS = {
    "fin@123456", "fin@12345678", "admin@123", "admin@1234", "admin@123456",
    "password", "password1", "password123", "passw0rd", "12345678",
    "123456789", "1234567890", "qwerty123", "abc123456", "1qaz2wsx",
    "iloveyou", "welcome123", "letmein123", "user@123", "user@1234",
}

MIN_LEN, MAX_LEN = 12, 128
_MIN_CLASSES = 3
_CLASSES = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
    re.compile(r"[^A-Za-z0-9]"),
)

# 口令里不得包含用户名（长度 ≥3 才有意义，避免 "li" 这种短名误杀）
_MIN_USERNAME_PART = 3


class PasswordPolicyError(ValueError):
    """策略拒绝：消息可直接展示给用户（不含内部实现细节）。"""


def validate_password(password: str, username: str = "",
                      old_password: str | None = None) -> None:
    """不满足策略则抛 PasswordPolicyError；通过则静默返回。"""
    pwd = password or ""
    if len(pwd) < MIN_LEN:
        raise PasswordPolicyError(f"口令至少 {MIN_LEN} 位")
    if len(pwd) > MAX_LEN:
        raise PasswordPolicyError(f"口令最长 {MAX_LEN} 位")
    if old_password is not None and pwd == old_password:
        raise PasswordPolicyError("新口令不能与当前口令相同")

    classes = sum(1 for rx in _CLASSES if rx.search(pwd))
    if classes < _MIN_CLASSES:
        raise PasswordPolicyError(
            "口令需包含大写字母、小写字母、数字、符号中的至少三类")

    lowered = pwd.lower()
    if lowered in WEAK_PASSWORDS:
        raise PasswordPolicyError("该口令在常见弱口令列表中，请更换")

    name = (username or "").strip().lower()
    if len(name) >= _MIN_USERNAME_PART and name in lowered:
        raise PasswordPolicyError("口令不能包含用户名")

    # 连续/重复字符：AAAAAAAAAAAA / 123456789012 这类也能凑满长度与类别
    if len(set(lowered)) < 4:
        raise PasswordPolicyError("口令字符过于单一，请更换")
