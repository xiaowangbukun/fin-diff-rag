# SPDX-License-Identifier: Apache-2.0
"""PDF 解析加固：表格结构化 / 多栏阅读顺序 / 提取质量检测 / 扫描件 OCR。

why: 原 PDF 分支只有 pypdf 纯文本流，三个硬伤——
  1) 解析异常被外层 try/except 吞成 "[解析失败] ..." 混进正文切片，
     伪文本会原样进向量库，检索时答非所问；
  2) 表格被拆成松散词流，"姓名 金额 日期 张三 100 ..." 结构全丢；
  3) 扫描件（无文本层）只能提出空文本，用户看不到原因，也无法补救。

设计：
- 可选依赖一律 try-import：pdfplumber / rapidocr-onnxruntime / pypdfium2。
  缺失时逐级降级——表格与多栏退化为 pypdf 纯文本，OCR 退化为明确拒绝，
  绝不因缺依赖而 500，也不伪造内容。
- 解析失败一律抛 ParseError（中文可读），由上传端点转 400，
  "[解析失败]" 伪文本再也不进正文。
- 表格只做 Markdown 管道表轻结构化（表头 + 分隔行 + 数据行），
  适配 LLM 上下文，不追求版式还原；按页内纵向位置插入正文流，页间保持顺序。
- 多栏恢复是指标启发式：word 的 x 区间聚栏 → 栏内按 top 排序 →
  栏间从左到右拼接；带"跨栏行多数"版式判别（表单/双语对照保持行完整）
  与"真分栏"显著性检查，单栏文档输出与原逐行拼接一致。
"""
import io
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:  # 可选依赖：装了才有表格抽取 / 多栏坐标 / 渲染能力
    import pdfplumber  # type: ignore
except Exception:  # 缺依赖 → 整体降级到 pypdf 纯文本路径
    pdfplumber = None

try:
    import pypdfium2 as pdfium  # type: ignore
except Exception:  # 缺渲染器 → OCR 不可用（识别引擎再好也看不到图）
    pdfium = None

try:
    from rapidocr_onnxruntime import RapidOCR  # type: ignore
except Exception:  # 缺识别引擎 → 扫描件明确拒绝而非静默丢内容
    RapidOCR = None


class ParseError(Exception):
    """解析失败（可读中文）。调用方应转成 4xx，绝不上送 5xx。"""


# ---------- 质量检测 ----------

# pdfminer 对"无 Unicode 映射"的字符输出字面量 (cid:N)——全是可读字符，
# 但它是编码错乱最典型的指纹，必须按不可读计入，否则乱码文档全判 ok。
_CID_RE = re.compile(r"\(cid:\d+\)")

# 常用标点白名单（ASCII + 中文标点 + 通用标点区间）。
# 设计为白名单而非黑名单：宁可把少见符号判为"不可读"触发人工核对，
# 也不要把控制字符/私用区/替换符放行——后者正是乱码的典型形态。
_ASCII_PUNCT = set("""!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~""")
_CJK_RANGES = ((0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0xF900, 0xFAFF))


def _is_cjk(ch: str) -> bool:
    return any(lo <= ord(ch) <= hi for lo, hi in _CJK_RANGES)


def _is_readable(ch: str) -> bool:
    """可读字符：空白 / 各类字母数字（含 CJK）/ 常用标点。"""
    if ch == "\ufffd":  # Unicode 替换符：乱码的显式指纹，永远不可读
        return False
    if ch.isspace() or ch.isalnum():
        return True
    if ch in _ASCII_PUNCT:
        return True
    code = ord(ch)
    if 0x3000 <= code <= 0x303F:  # CJK 标点（，。！？；：、等）
        return True
    if 0xFF00 <= code <= 0xFF65:  # 全角/半角形式（！～｡ 等）
        return True
    if 0xFFE0 <= code <= 0xFFE6:  # 全角货币符号（￠￡￢￣￤￥￦）
        # ￥（U+FFE5）落在全角货币区，不在 FF00–FF65 区间内。
        # 金融文档满篇都是金额符号，漏掉它会把正常财报判成乱码（low）。
        return True
    if 0x2010 <= code <= 0x2027:  # 连接号/破折线/引号/省略号
        return True
    return False


def assess_quality(text: str) -> str:
    """全文提取质量检测。

    判定规则（PRD）：可读字符比例 < 0.85 或含 U+FFFD → "low"，否则 "ok"。
    为什么按比例而非逐字：编码错乱的 PDF 往往大部分字符仍可读，
    只有替换符/控制字符/(cid:N) 掺在里面，比例能抓住"整体可疑"的信号。
    """
    if not text:
        return "low"
    # (cid:N) 每个标记折算成一个不可读字符：它字面全是可读符号，
    # 但语义上是"这个字的 Unicode 映射丢了"，正是乱码的指纹。
    marked = _CID_RE.sub("\x00", text)
    bad = sum(1 for ch in marked if not _is_readable(ch))
    return "low" if bad / len(marked) > 0.15 else "ok"


# ---------- 表格 → Markdown 管道表 ----------

_TABLE_STRATEGIES: tuple[dict, ...] = (
    # 1) 全框线表格（金融报告主流版式）
    {"vertical_strategy": "lines", "horizontal_strategy": "lines"},
    # 2) 只有竖线 / 只有横线的表格
    {"vertical_strategy": "lines", "horizontal_strategy": "text",
     "min_words_horizontal": 1, "text_tolerance": 3},
    {"vertical_strategy": "text", "horizontal_strategy": "lines",
     "min_words_vertical": 2, "text_tolerance": 3},
)


def _usable_table(table) -> bool:
    """过滤误报与退化形状：至少 2 行 2 列才有结构化价值。

    单列表/单行表转成 Markdown 只会添噪音；正文被误判成的"表格"
    通常也是这种退化形状，一刀切掉最安全。
    """
    try:
        rows = table.extract()
    except Exception:
        return False
    if not rows or len(rows) < 2:
        return False
    return max((len(r) for r in rows), default=0) >= 2


def _page_tables(page) -> list:
    """按策略依次尝试抽表，返回第一个有可用结果的策略的表列表。

    why 不全量混用：lines 与 text 策略会对同一区域给出重叠结果，
    混用会产生重复表格；"第一个有效策略胜出"足够且行为可预测。
    """
    for settings in _TABLE_STRATEGIES:
        try:
            tables = [t for t in page.find_tables(table_settings=settings)
                      if _usable_table(t)]
        except Exception:
            continue
        if tables:
            return tables
    return []


def _table_to_markdown(rows: list) -> str:
    """pdfplumber 表格 → Markdown 管道表。

    空单元格统一为空串（pdfplumber 对无字单元格给 None，
    直接拼接会输出字面量 "None"）；单元格内换行与竖线转义，
    否则会撑破表格结构。
    """
    if not rows:
        return ""

    def norm(cell) -> str:
        s = "" if cell is None else str(cell)
        s = s.replace("\r", " ").replace("\n", " ").strip()
        return s.replace("|", "\\|")

    table = [[norm(c) for c in row] for row in rows]
    width = max(len(r) for r in table)
    table = [r + [""] * (width - len(r)) for r in table]  # 参差行补齐，保护表格形状
    header, body = table[0], table[1:]
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * width) + " |",
    ]
    lines += ["| " + " | ".join(r) + " |" for r in body]
    return "\n".join(lines)


# ---------- 多栏阅读顺序恢复 ----------

_COL_GAP_MIN = 12.0     # 分栏间隙阈值（磅）：小于此视为同行拉伸/制表位，不判分栏
_COL_MIN_SHARE = 0.20   # 栏内行数占比下限：低于此视为页眉页脚/边注，不触发重排
_LINE_TOP_TOL = 3.0     # 同一行的 top 容差（磅）


def _cluster_lines(words: list[dict]) -> list[list[dict]]:
    """按 top 聚行：垂直方向相差容差内的词视为同一行，行内按 x0 排序。"""
    lines: list[list[dict]] = []
    for w in sorted(words, key=lambda w: (w["top"], w["x0"])):
        if lines and abs(w["top"] - lines[-1][0]["top"]) <= _LINE_TOP_TOL:
            lines[-1].append(w)
        else:
            lines.append([w])
    return lines


def _cluster_columns(words: list[dict]) -> list[tuple[float, float]]:
    """word 的 x 区间做重叠合并 → 候选栏（从左到右）。

    合并阈值即分栏间隙：行内词间距通常 < 8pt，栏间空隙通常 ≥ 15pt，
    12pt 是两者之间的折中；单栏文档所有区间连成一片，天然得到 1 栏。
    """
    spans = sorted((w["x0"], w["x1"]) for w in words)
    merged: list[list[float]] = []
    for x0, x1 in spans:
        if merged and x0 - merged[-1][1] <= _COL_GAP_MIN:
            merged[-1][1] = max(merged[-1][1], x1)
        else:
            merged.append([x0, x1])
    return [(m[0], m[1]) for m in merged]


def _col_of(word: dict, columns: list[tuple[float, float]]) -> int:
    """word 归属的栏（按 x0 落在哪个栏区间）。"""
    for i, (x0, x1) in enumerate(columns):
        if x0 - 0.5 <= word["x0"] <= x1 + 0.5:
            return i
    return 0


def _join_words(line_words: list[dict]) -> str:
    """同行拼接：CJK 边界不插空格（中文无词间空格），其余补一个空格。"""
    parts: list[str] = []
    for i, w in enumerate(line_words):
        if i:
            prev, cur = line_words[i - 1]["text"], w["text"]
            if not (_is_cjk(prev[-1]) and _is_cjk(cur[0])):
                parts.append(" ")
        parts.append(w["text"])
    return "".join(parts)


def _reorder_columns(words: list[dict]) -> str:
    """多栏阅读顺序恢复：栏内按 top 排序，栏间按 x 从左到右拼接。

    why: 双栏 PDF 按流式提取会把左右栏文字逐行交错，检索时上下文被搅碎。
    启发式三道保险，保证非多栏文档行为不变：
      1) 候选栏数 < 2 → 直接逐行拼接（单栏文档天然走这条）；
      2) 版式判别——多数行横跨多栏 → 表单/双语对照/表格型版式，
         "标签-值"本就该在同一行读，逐行拼接即是正确顺序，按栏拆反而不对；
      3) "真分栏"显著性——每个非主栏至少容纳 20% 的词，
         排除页脚页码/边注造成的假分栏（它们的词数占比很低）。
    """
    if not words:
        return ""
    lines = _cluster_lines(words)
    plain = "\n".join(_join_words(lw) for lw in lines)
    columns = _cluster_columns(words)
    if len(columns) < 2:
        return plain
    spanning = sum(1 for lw in lines
                   if len({_col_of(w, columns) for w in lw}) > 1)
    if spanning * 2 > len(lines):
        return plain
    counts = [0] * len(columns)
    for w in words:
        counts[_col_of(w, columns)] += 1
    if sum(1 for c in counts if c / len(words) >= _COL_MIN_SHARE) < 2:
        return plain
    blocks: list[str] = []
    for ci in range(len(columns)):
        col_words = sorted((w for w in words if _col_of(w, columns) == ci),
                           key=lambda w: (w["top"], w["x0"]))
        blocks.append("\n".join(_join_words(lw) for lw in _cluster_lines(col_words)))
    return "\n\n".join(b for b in blocks if b)


# ---------- 单页内容组装 ----------

def _page_content(page) -> str:
    """单页内容：表格区剔词 → 多栏重排正文 + 表格 Markdown 按纵向位置混排。

    插入策略：表格词先从正文流里剔除（避免同一内容出现两遍），
    表格 Markdown 与正文块一起按 top 排序输出——保持页内相对位置，
    页间顺序由外层逐页拼接天然保证。
    """
    tables = _page_tables(page)
    words = page.extract_words()
    if tables:
        boxes = [_pad_bbox(t.bbox) for t in tables]
        words = [w for w in words
                 if not any(_bbox_hit(w, b) for b in boxes)]
    body = _reorder_columns(words)
    blocks: list[tuple[float, str]] = []
    if body.strip():
        blocks.append((min(w["top"] for w in words), body))
    for t in tables:
        md = _table_to_markdown(t.extract())
        if md:
            blocks.append((t.bbox[1], md))
    blocks.sort(key=lambda b: b[0])
    return "\n\n".join(text for _, text in blocks)


def _pad_bbox(bbox: tuple[float, float, float, float],
              pad: float = 1.0) -> tuple[float, float, float, float]:
    """表格 bbox 外扩：多删半个字好过漏删一个字——重复内容比丢边缘词更伤检索。"""
    return (bbox[0] - pad, bbox[1] - pad, bbox[2] + pad, bbox[3] + pad)


def _bbox_hit(word: dict, box: tuple[float, float, float, float]) -> bool:
    return (word["x0"] < box[2] and word["x1"] > box[0]
            and word["top"] < box[3] and word["bottom"] > box[1])


# ---------- OCR（扫描件） ----------

_SCAN_PAGE_MIN = 5    # 单页提取文本少于此 → 视为无文本层，尝试 OCR
_SCAN_DOC_MIN = 50    # 全文少于此 → 疑似扫描件（PRD 口径）

_ocr_engine = None
_ocr_probed = False


def _get_ocr_engine():
    """惰性初始化 OCR 引擎（首次调用才加载 ONNX 模型，约数百毫秒）。"""
    global _ocr_engine, _ocr_probed
    if _ocr_probed:
        return _ocr_engine
    _ocr_probed = True
    if RapidOCR is not None:
        try:
            _ocr_engine = RapidOCR()
        except Exception:
            _ocr_engine = None
    return _ocr_engine


def _ocr_available() -> bool:
    """OCR 可用 = 识别引擎 + 渲染器都在（缺一个都跑不动扫描件）。"""
    return _get_ocr_engine() is not None and pdfium is not None


def _ocr_image(image) -> str:
    """单页图像 OCR → 文本（低置信度行丢弃，防把水印/噪点识别成正文）。"""
    engine = _get_ocr_engine()
    if engine is None or image is None:
        return ""
    try:
        import numpy as np  # rapidocr 依赖 opencv，numpy 必然可用

        arr = np.asarray(image.convert("RGB"))[:, :, ::-1].copy()  # RGB → BGR
        result, _ = engine(arr)
    except Exception:
        return ""
    if not result:
        return ""
    texts = [str(item[1]).strip() for item in result
             if len(item) >= 3 and float(item[2]) >= 0.5]
    return "\n".join(t for t in texts if t)


def _pdfium_doc(source):
    """打开 pdfium 文档（渲染器缺失或打开失败 → None）。bytes/路径均可。"""
    if pdfium is None:
        return None
    try:
        return pdfium.PdfDocument(
            source if isinstance(source, (bytes, bytearray)) else str(source)
        )
    except Exception:
        return None


def _ocr_pdf(source, page_count: int) -> str:
    """逐页渲染 + OCR。渲染失败的页面跳过（部分识别好过整体失败）。"""
    document = _pdfium_doc(source)
    if document is None or _get_ocr_engine() is None:
        return ""
    try:
        parts: list[str] = []
        for i in range(min(page_count, len(document))):
            parts.append(_ocr_one_page(document, i))
        return "\n\n".join(p for p in parts if p.strip())
    except Exception:
        return ""
    finally:
        _close_quietly(document)


def _close_quietly(document) -> None:
    """关闭 pdfium 文档（长驻服务反复上传扫描件，不能漏句柄）。"""
    try:
        document.close()
    except Exception:
        pass


def _ocr_one_page(document, index: int) -> str:
    """渲染单页并 OCR；渲染失败返回空串（由调用方决定是否降级）。"""
    try:
        pil = document[index].render(scale=2.0).to_pil()
    except Exception:
        return ""
    return _ocr_image(pil)


# ---------- 解析主流程 ----------

@contextmanager
def _open_pdfplumber(source) -> Iterator:
    """pdfplumber 上下文：路径/字节均可。"""
    if isinstance(source, (str, Path)):
        pdf = pdfplumber.open(str(source))
    else:
        pdf = pdfplumber.open(io.BytesIO(bytes(source)))
    try:
        yield pdf
    finally:
        pdf.close()


def _finalize(text: str, source, page_count: int,
              ocr_used: bool = False) -> tuple[str, str]:
    """收尾：文本量达标 → 质检；不达标 → OCR 兜底或明确拒绝（扫描件）。"""
    text = text.strip()
    if text and (len(text) >= _SCAN_DOC_MIN or ocr_used):
        return text, ("ocr" if ocr_used else assess_quality(text))
    if _ocr_available() and not ocr_used:
        ocr_text = _ocr_pdf(source, page_count)
        if ocr_text.strip():
            return ocr_text.strip(), "ocr"
    if _ocr_available():
        raise ParseError("PDF 解析失败：已启用 OCR 但仍未识别到文本（可能为空白页）")
    raise ParseError("该 PDF 无文本层（疑似扫描件），请上传文本版或启用 OCR")


def _parse_with_pdfplumber(source) -> tuple[str, str]:
    """pdfplumber 路径：逐页表格 + 多栏 + 质量检测，空页按页补 OCR。"""
    with _open_pdfplumber(source) as pdf:
        pages = pdf.pages
        if not pages:
            raise ParseError("PDF 解析失败：文件中没有页面")
        texts: list[str] = []
        ocr_used = False
        doc = _pdfium_doc(source) if _ocr_available() else None
        try:
            for i, page in enumerate(pages):
                try:
                    page_text = _page_content(page)
                except Exception as e:
                    raise ParseError(
                        f"PDF 解析失败：第 {i + 1} 页内容提取异常（{_reason(e)}）"
                    ) from e
                if len(page_text.strip()) < _SCAN_PAGE_MIN and doc is not None:
                    # 混合文档（部分页是扫描插图/扫描附录）：按页补 OCR，
                    # 已成功的页标 ocr_used，质量标记为 "ocr" 而非 "ok"。
                    ocr_text = _ocr_one_page(doc, i)
                    if ocr_text.strip():
                        page_text = ocr_text
                        ocr_used = True
                texts.append(page_text)
        finally:
            if doc is not None:
                _close_quietly(doc)
    text = "\n\n".join(t for t in texts if t.strip())
    return _finalize(text, source, len(pages), ocr_used)


def _parse_with_pypdf(source) -> tuple[str, str]:
    """pypdf 兜底路径：无表格/无多栏，但保持"失败可读、空文本有说法"。"""
    from pypdf import PdfReader

    stream = io.BytesIO(bytes(source)) if isinstance(source, (bytes, bytearray)) \
        else str(source)
    try:
        reader = PdfReader(stream)
    except Exception as e:
        raise ParseError(f"PDF 解析失败：{_reason(e)}") from e
    if reader.is_encrypted:
        try:
            reader.decrypt("")  # 仅所有者密码（无用户密码）的 PDF 可无损解开
        except Exception as e:
            raise ParseError(
                "PDF 解析失败：文件已加密，请移除密码后上传"
            ) from e
    pages = list(reader.pages)
    if not pages:
        raise ParseError("PDF 解析失败：文件中没有页面")
    texts: list[str] = []
    for i, page in enumerate(pages):
        try:
            texts.append(page.extract_text() or "")
        except Exception as e:
            raise ParseError(
                f"PDF 解析失败：第 {i + 1} 页提取异常（{_reason(e)}）"
            ) from e
    return _finalize("\n".join(texts), source, len(pages))


def _reason(e: Exception) -> str:
    """底层异常 → 中文可读原因（加密/损坏分类提示，其余截断原文）。"""
    msg = (str(e) or e.__class__.__name__).strip()
    low = msg.lower()
    if "encrypt" in low or "password" in low:
        return "文件已加密，请移除密码后上传"
    if any(k in low for k in ("damaged", "corrupt", "eof", "syntax",
                              "not a pdf", "xref", "trailer", "no objects",
                              "stream")):
        return "文件结构损坏或不是有效的 PDF"
    return msg[:120]


def parse_pdf(source) -> tuple[str, str]:
    """PDF 解析主入口 → (全文文本, 质量标记)。

    质量标记：ok=正常 / low=可读比例低（疑似乱码，建议核对原文）/
    ocr=扫描件 OCR 来源。任何真实解析失败抛 ParseError，绝不返回伪文本。
    """
    if pdfplumber is not None:
        try:
            return _parse_with_pdfplumber(source)
        except ParseError:
            raise
        except Exception:
            pass  # pdfplumber 自身异常 → 落 pypdf 兜底（ corrupt 文件两边都会失败）
    return _parse_with_pypdf(source)


def capabilities() -> dict[str, bool]:
    """当前 PDF 能力面（供健康检查与测试分支判断，不触发模型加载）。"""
    return {
        "pdfplumber": pdfplumber is not None,
        "pypdfium2": pdfium is not None,
        "ocr": RapidOCR is not None,
    }
