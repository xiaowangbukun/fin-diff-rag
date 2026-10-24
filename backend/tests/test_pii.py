# SPDX-License-Identifier: Apache-2.0
"""pii.py —— 敏感信息识别与脱敏单元测试。

两条主线：
  · 命中：身份证/手机号/银行卡/邮箱/JWT/云密钥等必须检出；
  · 不误报：普通长数字（订单号、样本编号）不该一律当敏感信息——
    这是 pii.py 刻意加 _CARD_CTX / _AMOUNT_CTX 上下文判断的原因。
"""
import pytest

from app.pii import Hit, _compile_extra, mask, mask_value, redact_for_level, scan


def kinds(text: str) -> list[str]:
    return [h.kind for h in scan(text)]


# ------------------------------------------------------------------ 命中


@pytest.mark.parametrize(
    "text,expected_kind",
    [
        ("客户身份证号 11010519900307123X 已核验", "身份证"),
        ("身份证：31010119951212345X", "身份证"),
        ("手机号 13800138000 已停用", "手机号"),
        ("联系电话：15912345678", "手机号"),
        # 银行卡：19 位卡号 + 「卡号/银行卡」上下文
        ("银行卡号 6222021234567890123 已冻结", "银行卡"),
        ("请核对卡号 6222 0212 3456 7890 123 后重试", "银行卡"),
        ("联系邮箱 zhangsan@example.com", "邮箱"),
        ("内网接口地址 10.20.31.45 已下线", "内网IP"),
        ("192.168.1.100 为该网关地址", "内网IP"),
        ("泄露的密钥 AKIA IOSFODNN7EXAMPLE".replace(" ", ""), "云密钥"),
        ("sk-abcdefghij0123456789ABCDEFGHIJ", "云密钥"),
        ("请求头 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP", "JWT"),
    ],
)
def test_scan_detects_expected_kind(text, expected_kind):
    found = kinds(text)
    assert expected_kind in found, f"{text!r} 应检出 {expected_kind}，实际 {found}"


def test_scan_hit_carries_positions():
    text = "手机号 13800138000 已停用"
    hits = [h for h in scan(text) if h.kind == "手机号"]
    assert len(hits) == 1
    h = hits[0]
    assert isinstance(h, Hit)
    assert text[h.start:h.end] == "13800138000"


def test_scan_returns_sorted_by_start():
    text = "身份证 11010519900307123X，手机号 13800138000"
    hits = scan(text)
    starts = [h.start for h in hits]
    assert starts == sorted(starts)


def test_scan_does_not_double_count_overlapping_spans():
    """长数字满足多个模式时（身份证 vs 银行卡 vs 金融金额）只能记一次。"""
    text = "身份证 11010519900307123X"
    assert kinds(text).count("身份证") == 1
    assert "金融金额" not in kinds(text)


# ------------------------------------------------------------------ 不误报


@pytest.mark.parametrize(
    "text",
    [
        "订单编号 20240101000001 已生成",                 # 14 位裸数字，无资金上下文
        "本次抽样 2024101500001234 已入库",               # 16 位裸数字，无卡号上下文
        "报告编号 R2024-0012，页码 3 / 45",
        "会议时间是 2024 年 10 月 15 日下午 3 点",
        "资产规模 1,234,567.89 万元，较上年末增长 5.4%",
        "1 号 Qianlibao 账户、2 号备用金账户均已完成对账",
        "产品代码 PD2024001，期限 90 天，起投金额 1000 元",
    ],
)
def test_scan_no_false_positive_on_plain_numbers(text):
    assert kinds(text) == [], f"误报：{text!r} -> {kinds(text)}"


def test_bank_card_without_context_is_not_flagged():
    """没有「卡号/银行卡/账户」等上下文的长数字不该判成银行卡。"""
    found = kinds("流水号 6222021234567890123 请查收")
    assert "银行卡" not in found
    assert "金融金额" not in found


def test_amount_without_context_is_not_flagged():
    found = kinds("订单流水 0000123456789012 已确认")
    assert "金融金额" not in found


def test_amount_with_context_is_flagged():
    """同样是 12 位以上长数字，出现于「转账/余额」语义附近才认定。"""
    found = kinds("本次转账金额 12345678901234 元已提交")
    assert "金融金额" in found


# ------------------------------------------------------------------ 自定义规则


def test_compile_extra_plain_regex():
    out = _compile_extra(r'["HT-\\d{6}"]')
    assert len(out) == 1
    assert out[0][0] == "自定义敏感信息"
    assert out[0][1].search("HT-202401") is not None


def test_compile_extra_named_pattern():
    out = _compile_extra(r'[{"kind":"合同编号","pattern":"CT-\\d{8}"}]')
    assert len(out) == 1
    assert out[0][0] == "合同编号"


def test_compile_extra_empty():
    assert _compile_extra("") == []


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",            # 非 JSON
        '{"a": 1}',            # 顶层不是数组
        r'["[unclosed"]',      # 正则本身非法
    ],
)
def test_compile_extra_never_raises(raw):
    """坏配置只能告警，绝不能阻断服务启动（PII_EXTRA_PATTERNS 是增强项）。"""
    assert _compile_extra(raw) == []


def test_compile_extra_skips_malformed_items():
    out = _compile_extra('[123, null, {"pattern": "A\\\\d+"}, {"no_pattern": 1}]')
    assert len(out) == 1
    assert out[0][0] == "自定义敏感信息"


# ------------------------------------------------------------------ 脱敏


@pytest.mark.parametrize(
    "value,expected_len",
    [("", 0), ("1", 1), ("1234", 4), ("12345", 5), ("12345678", 8),
     ("123456789", 9), ("11010519900307123X", 18)],
)
def test_mask_value_preserves_length(value, expected_len):
    masked = mask_value(value)
    assert len(masked) == expected_len


def test_mask_value_short_is_fully_masked():
    assert mask_value("1234") == "****"
    assert mask_value("") == ""


def test_mask_value_medium_keeps_edges():
    assert mask_value("1234567") == "1*****7"


def test_mask_value_long_keeps_three_and_four():
    masked = mask_value("11010519900307123X")
    assert masked.startswith("110")
    assert masked.endswith("123X")
    assert "*" in masked


def test_mask_masks_inline_and_counts():
    text = "手机号 13800138000 已停用"
    masked, n = mask(text)
    assert n >= 1
    assert "13800138000" not in masked
    assert len(masked) == len(text)


def test_mask_returns_original_when_no_hit():
    text = "本季度营收同比增长 12.3%"
    masked, n = mask(text)
    assert (masked, n) == (text, 0)


def test_redact_for_level_high_clearance_sees_plaintext():
    text = "手机号 13800138000"
    out, n = redact_for_level(text, 2)
    assert (out, n) == (text, 0)


def test_redact_for_level_low_clearance_is_masked():
    text = "手机号 13800138000"
    out, n = redact_for_level(text, 1)
    assert n >= 1
    assert "13800138000" not in out


@pytest.mark.parametrize("text", ["", None])
def test_scan_handles_empty(text):
    assert scan(text) == []
