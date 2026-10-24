# SPDX-License-Identifier: Apache-2.0
"""TOTP 原语测试：RFC 6238 官方向量 + 重放防护 + 密钥静态加密。"""
import base64

import pytest

from app import totp


# RFC 6238 附录 B 的种子是 ASCII "12345678901234567890"（SHA1 用例），
# 转成 base32 即为下面这串——用它跑官方时间点，证明我们的实现与标准一致。
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")

RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("at,expected", RFC_VECTORS)
def test_rfc6238_vectors(at, expected):
    assert totp.code_at(RFC_SECRET, at=at, digits=8) == expected


def test_six_digit_default_and_zero_padding():
    code = totp.code_at(RFC_SECRET, at=59)
    assert len(code) == 6 and code.isdigit()
    # 6 位是 8 位向量的末 6 位（截断规则一致）
    assert code == "287082"


def test_verify_accepts_current_code_and_returns_step():
    now = 1_700_000_000
    code = totp.code_at(RFC_SECRET, at=now)
    assert totp.verify(RFC_SECRET, code, at=now) == totp.step_at(now)


def test_verify_allows_one_step_drift_each_way():
    now = 1_700_000_000
    prev_code = totp.code_at(RFC_SECRET, at=now - 30)
    next_code = totp.code_at(RFC_SECRET, at=now + 30)
    assert totp.verify(RFC_SECRET, prev_code, at=now) is not None
    assert totp.verify(RFC_SECRET, next_code, at=now) is not None


def test_verify_rejects_two_steps_drift():
    now = 1_700_000_000
    stale = totp.code_at(RFC_SECRET, at=now - 90)
    assert totp.verify(RFC_SECRET, stale, at=now) is None


def test_verify_rejects_replay_of_used_step():
    now = 1_700_000_000
    code = totp.code_at(RFC_SECRET, at=now)
    step = totp.verify(RFC_SECRET, code, at=now)
    assert step is not None
    # 同一口令第二次提交必须失败：窗口内重放等于把一次性口令变成多次
    assert totp.verify(RFC_SECRET, code, at=now, last_step=step) is None


def test_verify_rejects_malformed_input():
    now = 1_700_000_000
    assert totp.verify(RFC_SECRET, "", at=now) is None
    assert totp.verify(RFC_SECRET, "abcdef", at=now) is None
    assert totp.verify(RFC_SECRET, "12345", at=now) is None


def test_provisioning_uri_contains_standard_params():
    uri = totp.provisioning_uri("ABCDEF234567", "alice")
    assert uri.startswith("otpauth://totp/")
    assert "secret=ABCDEF234567" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
    assert "issuer=FinRAG" in uri


def test_seal_roundtrip_and_ciphertext_not_plaintext():
    sealed = totp.seal("JBSWY3DPEHPK3PXP")
    assert sealed.startswith("enc:v1:")
    assert "JBSWY3DPEHPK3PXP" not in sealed
    assert totp.unseal(sealed) == "JBSWY3DPEHPK3PXP"


def test_unseal_keeps_legacy_plaintext_compat():
    assert totp.unseal("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"
    assert totp.unseal("") == ""


def test_seal_requires_key_material(monkeypatch):
    from app import config
    monkeypatch.setattr(config, "MFA_SECRET_KEY", "")
    monkeypatch.setattr(config, "JWT_SECRET", "")
    assert totp.encryption_ready() is False
    with pytest.raises(RuntimeError):
        totp.seal("JBSWY3DPEHPK3PXP")


def test_unseal_detects_wrong_key(monkeypatch):
    from app import config
    sealed = totp.seal("JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(config, "MFA_SECRET_KEY",
                        base64.urlsafe_b64encode(b"k" * 32).decode())
    with pytest.raises(RuntimeError):
        totp.unseal(sealed)
