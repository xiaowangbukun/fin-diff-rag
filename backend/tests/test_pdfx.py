# SPDX-License-Identifier: AGPL-3.0-only
"""pdfx.py —— 解析质量标记与表格/多栏轻结构化单元测试。

只挑**纯函数**部分：质量检测（决定文档要不要标 low）、表格转 Markdown
（None 单元格不能变成字面量 "None"）、多栏重排启发式。真正的 PDF 解析
需要 pdfplumber 与真实文件，交给端到端脚本，不进单测。
"""
import pytest

from app.pdfx import _is_readable, _table_to_markdown, assess_quality


# ------------------------------------------------------------------ 质量检测


def test_assess_quality_empty_is_low():
    assert assess_quality("") == "low"


def test_assess_quality_whitespace_only_is_ok():
    """纯空白（非空串）走不到「无文本」分支，空格本身算可读 → ok。

    实际链路里 parse_pdf 会先 strip() 再进 _finalize，所以纯空白文档进不到
    这里；这条用例只是把「当前行为」钉住，防止有人顺手改坏。
    """
    assert assess_quality("   ") == "ok"


def test_assess_quality_normal_text_is_ok():
    text = ("本公司 2024 年度实现营业收入 123.45 亿元，同比增长 12.3%，"
            "归属于母公司股东的净利润同比增长 8.1%，加权平均净资产收益率为 11.4%。")
    assert assess_quality(text) == "ok"


def test_assess_quality_english_ok():
    assert assess_quality("The net interest margin improved to 2.35% this quarter.") == "ok"


def test_assess_quality_replacement_char_is_low():
    """U+FFFD 是编码错乱的显式指纹，出现即按不可读计。"""
    assert assess_quality("正常内容\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd") == "low"


def test_assess_quality_cid_marker_is_low():
    """(cid:N) 字面全是 ASCII 可读字符，但语义是「映射丢失」，必须计入不可读。"""
    marked = "(cid:12)(cid:34)(cid:56)(cid:78)"
    assert assess_quality(marked) == "low"


def test_assess_quality_threshold_boundary():
    """判定口径是 bad/len > 0.15：正好 15% 仍算 ok，越过才算 low。"""
    exactly = "\x00" * 15 + "a" * 85
    over = "\x00" * 20 + "a" * 80
    assert assess_quality(exactly) == "ok"
    assert assess_quality(over) == "low"


def test_assess_quality_cjk_punctuation_is_readable():
    assert assess_quality("这是一份财务报表，包含资产负债表、利润表、现金流量表。") == "ok"


# ------------------------------------------------------------------ 可读字符判定


@pytest.mark.parametrize(
    "ch,expected",
    [
        ("a", True), ("中", True), ("5", True), (" ", True),
        ("，", True), ("。", True), ("%", True),
        ("\ufffd", False), ("\x00", False), ("\x01", False),
        # 全角货币符号 ￥(U+FFE5) 现按可读计入（B4 修复）：它落在全角货币区
        # U+FFE0–U+FFE6，此前只放行 U+FF00–U+FF65，满篇金额的金融 PDF 会被
        # 误判成乱码（low）。本条曾以"已知口径取舍"钉住旧行为，随修复翻正。
        ("\uffe5", True),
    ],
)
def test_is_readable(ch, expected):
    assert _is_readable(ch) is expected


# ------------------------------------------------------------------ 表格 → Markdown


def test_table_to_markdown_basic_shape():
    rows = [["姓名", "金额", "日期"], ["张三", "100", "2024-01-01"]]
    md = _table_to_markdown(rows)
    lines = md.splitlines()
    assert lines[0] == "| 姓名 | 金额 | 日期 |"
    assert lines[1] == "| --- | --- | --- |"
    assert lines[2] == "| 张三 | 100 | 2024-01-01 |"


def test_table_to_markdown_none_cells_are_empty():
    """pdfplumber 对无字单元格给 None，直接拼接会输出字面量 "None"。"""
    rows = [["项目", "本期"], [None, "100"]]
    md = _table_to_markdown(rows)
    assert "None" not in md
    assert md.splitlines()[2] == "|  | 100 |"


def test_table_to_markdown_pads_ragged_rows():
    rows = [["a", "b", "c"], ["1"]]
    md = _table_to_markdown(rows)
    assert md.splitlines()[2] == "| 1 |  |  |"


def test_table_to_markdown_escapes_pipes_and_newlines():
    rows = [["名称"], ["含|竖线\n换行的内容"]]
    md = _table_to_markdown(rows)
    assert "\\|" in md
    assert "\n" not in md.splitlines()[-1]


def test_table_to_markdown_empty_returns_empty():
    assert _table_to_markdown([]) == ""
    assert _table_to_markdown(None) == ""


def test_table_to_markdown_single_row():
    md = _table_to_markdown([["只有一行"]])
    assert md.splitlines()[0] == "| 只有一行 |"
    assert len(md.splitlines()) == 2
