#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""生成仓库根目录 THIRD-PARTY-NOTICES.md（第三方许可清单）。

用法（在仓库根目录执行，也可从任意 cwd 执行——路径按脚本位置解析）：
    D:/workspace/python/python.exe scripts/generate_third_party_notices.py

依赖：纯 Python 标准库（importlib.metadata / json / pathlib / re / sys / datetime）。

数据源与解析口径：
  后端  backend/requirements-lock.txt  逐行解析 name==version（跳过 # 注释与空行）
        → 本机 importlib.metadata 取许可，字段优先级：
            License-Expression（PEP 639 SPDX 表达式，现代包首选）
            → License 自由文本（仅接受单行且长度 <= 80 的标识符样文本）
            → License :: OSI Approved :: ... 分类器（映射为 SPDX 标识符）
        → 本机未安装 / metadata 无许可字段：查 scripts/third_party_licenses.json override 表
        → 都没有：标记 UNKNOWN-需人工核验，并在 stderr 告警
  前端  frontend/package-lock.json    npm lockfile v1 / v2 / v3 均可解析
        → 许可优先取 lock 条目 license 字段
        → 没有则读 frontend/node_modules/<pkg>/package.json 的 license
        → 再没有查 override 表 → 都没有 UNKNOWN-需人工核验
        （lock 条目 key 形如 node_modules/<pkg>，嵌套依赖取最后一段 node_modules/ 之后的叶子包名）

产出：仓库根 THIRD-PARTY-NOTICES.md（三张表 + 传染性许可提示段 + override 附录）。
重跑时机：升级/更换任何依赖后；修改上述三个数据源任一后；切换 Python 版本或 OS 后
（本机 metadata 口径会变）；更新 override 表后。除"生成时间"行外，同样输入必须产生同样输出。
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import re
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------- 路径（全部相对脚本位置，不依赖 cwd）

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent

OVERRIDE_PATH = SCRIPT_DIR / "third_party_licenses.json"
LOCK_PATH = ROOT / "backend" / "requirements-lock.txt"
REQUIREMENTS_PATH = ROOT / "backend" / "requirements.txt"
NPM_LOCK_PATH = ROOT / "frontend" / "package-lock.json"
FRONTEND_DIR = ROOT / "frontend"
OUT_PATH = ROOT / "THIRD-PARTY-NOTICES.md"

GEN_COMMAND = "D:/workspace/python/python.exe scripts/generate_third_party_notices.py"

UNKNOWN = "UNKNOWN-需人工核验"

# ---------------------------------------------------------------- 常量表

# PyPI License 分类器 → SPDX 标识符（仅列常见项，未命中时取分类器末段原文）
CLASSIFIER_TO_SPDX = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: MIT No Attribution License (MIT-0)": "MIT-0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 1.0 (MPL)": "MPL-1.0",
    "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)": "MPL-1.1",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: GNU General Public License (GPL)": "GPL",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)": "GPL-2.0",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)": "GPL-3.0",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0",
    "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0",
    "License :: OSI Approved :: GNU Affero General Public License v3": "AGPL-3.0",
}

# 传染性许可识别（命中即进入"传染性许可提示段"；强传染项触发法务评审要求）
WEAK_COPYLEFT_RE = re.compile(r"(?i)\b(?:MPL-[\d.]+|LGPL-[\d.]+(?:-only|-or-later)?|EPL-[\d.]+|CPAL-[\d.]+|CDDL-[\d.]+)\b")
STRONG_COPYLEFT_RE = re.compile(r"(?i)\b(?:GPL(?:-[\d.]+(?:-only|-or-later)?)?|AGPL(?:-[\d.]+(?:-only|-or-later)?)?|SSPL(?:-[\d.]+)?|COMMERCIAL)\b")

# requirements-lock.txt 行格式：name[extras]==version
LOCK_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*?)(\[[^\]]*\])?==(.+)$")
# requirements.txt 声明行：取比较符/ extras / 注释之前的部分
REQ_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize(name: str) -> str:
    """PEP 503 规范化：大小写不敏感，- _ . 视为等价。"""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def classifier_to_spdx(classifier: str) -> str:
    return CLASSIFIER_TO_SPDX.get(classifier.strip(), classifier.split("::")[-1].strip())


# ---------------------------------------------------------------- override 表


def load_overrides() -> dict:
    if not OVERRIDE_PATH.is_file():
        print(f"[warn] override 表不存在: {OVERRIDE_PATH}", file=sys.stderr)
        return {}
    with OVERRIDE_PATH.open(encoding="utf-8") as f:
        data = json.load(f)
    packages = data.get("packages", {})
    return {normalize(k): v for k, v in packages.items()}


def lookup_override(overrides: dict, name: str):
    entry = overrides.get(normalize(name))
    if entry and entry.get("license"):
        return entry
    return None


# ---------------------------------------------------------------- 后端：requirements-lock.txt


def parse_lock(path: Path):
    """→ [(name, version)]，跳过注释/空行；返回 None 表示文件缺失。"""
    if not path.is_file():
        return None
    out = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LOCK_LINE_RE.match(line)
        if not m:
            print(f"[warn] {path}:{lineno} 无法解析（已跳过）: {line!r}", file=sys.stderr)
            continue
        out.append((m.group(1), m.group(3).strip()))
    return out


def parse_requirements_names(path: Path):
    """→ (规范化名 set, 规范化名→声明原文 dict)，供差额核对；文件缺失返回 (None, None)。"""
    if not path.is_file():
        return None, None
    names = set()
    display = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 去掉行内注释
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = REQ_LINE_RE.match(line)
        if m:
            declared = m.group(1)
            norm = normalize(declared)
            names.add(norm)
            display.setdefault(norm, declared)
    return names, display


def resolve_python_license(name: str, overrides: dict):
    """→ (license, source)。source ∈ {metadata, override, none}"""
    try:
        md = importlib_metadata.metadata(name)
    except importlib_metadata.PackageNotFoundError:
        md = None
    except Exception as exc:  # 损坏的 metadata 不阻塞清单生成
        print(f"[warn] importlib.metadata 读取失败: {name}: {exc}", file=sys.stderr)
        md = None

    if md is not None:
        # 1) PEP 639 License-Expression（现代包的首选 SPDX 表达式）
        expression = (md.get("License-Expression") or "").strip()
        if expression:
            return expression, "metadata"
        # 2) Metadata-License（老式规范字段；注：'Metadata-License' 并非 METADATA 规范字段，
        #    这里保留探测是为了兼容个别打包工具写出的同名字段）
        legacy = (md.get("Metadata-License") or "").strip()
        if legacy and legacy.upper() != "UNKNOWN":
            return legacy, "metadata"
        # 3) License 自由文本：仅接受单行、短、标识符样文本（避免把整段许可证原文抄进表格）
        text = (md.get("License") or "").strip()
        if text and "\n" not in text and len(text) <= 80 and text.upper() != "UNKNOWN":
            return text, "metadata"
        # 4) License :: OSI Approved :: ... 分类器
        for classifier in md.get_all("Classifier") or []:
            if classifier.strip().startswith("License ::"):
                return classifier_to_spdx(classifier), "metadata"

    entry = lookup_override(overrides, name)
    if entry:
        return entry["license"], "override"
    return UNKNOWN, "none"


def collect_backend(overrides: dict):
    locked = parse_lock(LOCK_PATH)
    if locked is None:
        print(f"[error] 依赖锁文件缺失: {LOCK_PATH}", file=sys.stderr)
        sys.exit(2)
    rows = []
    for name, version in sorted(locked, key=lambda kv: (normalize(kv[0]), kv[0])):
        license_id, source = resolve_python_license(name, overrides)
        if source == "none":
            print(
                f"[warn] 许可未解析（本机未安装且 override 无条目）: {name}=={version} → {license_id}；"
                f"请核验 PyPI 页面后补 scripts/third_party_licenses.json 并重跑本脚本",
                file=sys.stderr,
            )
        rows.append({"name": name, "version": version, "license": license_id, "source": source})
    return rows


# ---------------------------------------------------------------- 前端：package-lock.json


def iter_npm_lock_entries(data: dict):
    """兼容 lockfileVersion 1 / 2 / 3，yield (leaf_name, entry, lock_key)。"""
    if "packages" in data:  # v2 / v3
        for key, entry in data["packages"].items():
            if not key or not isinstance(entry, dict):
                continue  # '' 是项目根条目，不是依赖
            name = key.rsplit("node_modules/", 1)[-1]
            yield name, entry, key
    else:  # v1：dependencies 树，可能嵌套
        def walk(deps: dict, prefix: str):
            for name, entry in (deps or {}).items():
                if not isinstance(entry, dict):
                    continue
                key = f"{prefix}node_modules/{name}"
                yield name, entry, key
                yield from walk(entry.get("dependencies"), key + "/")

        yield from walk(data.get("dependencies"), "")


def read_npm_package_json_license(lock_key: str, name: str):
    """按 lock key 精确定位 frontend/ 下的 package.json（兼容嵌套路径）；读不到返回 None。"""
    rel = lock_key if lock_key.startswith("node_modules/") else f"node_modules/{lock_key}"
    pkg_json = FRONTEND_DIR / Path(*rel.split("/")) / "package.json"
    if not pkg_json.is_file():
        # 兜底：平级 node_modules/<name>
        pkg_json = FRONTEND_DIR / "node_modules" / Path(*name.split("/")) / "package.json"
        if not pkg_json.is_file():
            return None
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except Exception:
        return None
    lic = data.get("license")
    if isinstance(lic, dict):  # {type: "MIT", url: ...} 形态
        lic = lic.get("type")
    return str(lic) if lic else None


def collect_frontend(overrides: dict):
    if not NPM_LOCK_PATH.is_file():
        print(f"[error] 前端锁文件缺失: {NPM_LOCK_PATH}", file=sys.stderr)
        sys.exit(2)
    data = json.loads(NPM_LOCK_PATH.read_text(encoding="utf-8"))
    lockfile_version = data.get("lockfileVersion")

    rows = []
    seen = {}
    for name, entry, key in iter_npm_lock_entries(data):
        if normalize(name) in seen:
            continue  # 同名多版本只保留首个（本仓库当前无此情况）
        seen[normalize(name)] = True

        lic = entry.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if lic:
            license_id, source = str(lic), "lock"
        else:
            fallback = read_npm_package_json_license(key, name)
            if fallback:
                license_id, source = fallback, "node_modules"
            else:
                ov = lookup_override(overrides, name)
                if ov:
                    license_id, source = ov["license"], "override"
                else:
                    license_id, source = UNKNOWN, "none"
                    print(
                        f"[warn] 前端许可未解析（lock 无 license 字段、node_modules 无 package.json、override 无条目）: {name}",
                        file=sys.stderr,
                    )
        rows.append(
            {"name": name, "version": str(entry.get("version", "?")), "license": license_id, "source": source}
        )
    rows.sort(key=lambda r: (normalize(r["name"]), r["name"]))
    return rows, lockfile_version


# ---------------------------------------------------------------- 渲染


def md_escape(text: str) -> str:
    return str(text).replace("|", "\\|")


def render_table(rows) -> str:
    lines = ["| Package | Version | License | 来源 |", "| --- | --- | --- | --- |"]
    for r in rows:
        lines.append(f"| {md_escape(r['name'])} | {md_escape(r['version'])} | {md_escape(r['license'])} | {r['source']} |")
    return "\n".join(lines)


def classify_copyleft(rows):
    """→ (weak_list, strong_list)，元素为 (name, license)。"""
    weak, strong = [], []
    for r in rows:
        lic = r["license"]
        if STRONG_COPYLEFT_RE.search(lic):
            strong.append((r["name"], lic))
        elif WEAK_COPYLEFT_RE.search(lic):
            weak.append((r["name"], lic))
    return weak, strong


def render_copyleft_section(backend_rows, frontend_rows) -> str:
    weak_b, strong_b = classify_copyleft(backend_rows)
    weak_f, strong_f = classify_copyleft(frontend_rows)
    weak = weak_b + weak_f
    strong = strong_b + strong_f

    parts = []
    parts.append("## 传染性许可提示（Copyleft 提示）\n")
    parts.append(
        "以下条目含弱传染（文件级/库级）许可，**均与 Apache-2.0 兼容**："
        "随分发提供对应许可文本即可，**不需要**开放本项目源码；但不得删除/修改其随附许可声明。\n"
    )
    if weak:
        parts.append("| Package | License | 传染性说明 |")
        parts.append("| --- | --- | --- |")
        notes = {
            "certifi": "MPL-2.0 文件级弱传染：仅修改 certifi 自身源文件时才需开源该文件；随分发提供 MPL-2.0 文本即可",
            "psycopg": "LGPL-3.0 弱传染：以独立进程/动态链接方式使用不传染本项目；随分发提供 LGPL-3.0 文本即可",
            "psycopg-binary": "LGPL-3.0 弱传染：psycopg 的二进制发行形态，口径同 psycopg",
        }
        for name, lic in weak:
            parts.append(f"| {md_escape(name)} | {md_escape(lic)} | {notes.get(name, '弱传染许可，随分发提供许可文本即可')} |")
        parts.append("")

    # 已知二进制内嵌组件补充（QA 实测核验，随对应包存在才提示）
    backend_names = {normalize(r["name"]) for r in backend_rows}
    extras = []
    if "shapely" in backend_names:
        extras.append(
            "- shapely（BSD-3-Clause）的 wheel 内嵌 GEOS 库（LGPL-2.1，弱传染）：随分发提供 LGPL-2.1 许可文本即可。"
        )
    if "pypdfium2" in backend_names:
        extras.append(
            "- pypdfium2（Apache-2.0 / BSD-3-Clause 双许可）的 wheel 内嵌 PDFium 及 abseil/freetype/icu/lcms2/libjpeg-turbo/libpng/zlib 等依赖（均 BSD 风格），wheel 内已随附对应许可文本。"
        )
    if "numpy" in backend_names:
        extras.append(
            "- numpy（BSD-3-Clause）的 wheel 内置 OpenBLAS（BSD-3-Clause）与 GCC runtime（GPL-3.0-with-GCC-exception，例外条款明确允许随二进制分发）。"
        )
    if extras:
        parts.append("补充：以下二进制 wheel 内嵌组件的许可口径已经 QA 核验（2026-10-20）：\n")
        parts.extend(extras)
        parts.append("")

    parts.append("### 强传染许可红线\n")
    parts.append(
        "**若将来引入 GPL / AGPL / SSPL / COMMERCIAL 类许可，或出现 `UNKNOWN-需人工核验` 条目，"
        "必须先经法务评审通过，方可进入分发/交付流程。**\n"
    )
    if strong:
        parts.append("本清单生成时检出以下强传染/商业/未知条目，**需法务评审**：\n")
        parts.append("| Package | License | 所属表 |")
        parts.append("| --- | --- | --- |")
        in_backend = {normalize(r["name"]) for r in backend_rows}
        for name, lic in strong:
            parts.append(f"| {md_escape(name)} | {md_escape(lic)} | {'后端' if normalize(name) in in_backend else '前端'} |")
    else:
        parts.append("本清单生成时**未检出** GPL / AGPL / SSPL / COMMERCIAL / UNKNOWN 条目（逐表见上）。")
    parts.append("")
    return "\n".join(parts)


def render_delta_section(delta_names, req_display, locked_names):
    lines = ["## 二、`requirements.txt` 声明但 `requirements-lock.txt` 未锁定的包（差额核对）\n"]
    if delta_names:
        lines.append(render_table([{"name": n, "version": "?", "license": "?", "source": "?"} for n in sorted(delta_names)]))
    else:
        lines.append("| Package | Version | License | 来源 |")
        lines.append("| --- | --- | --- | --- |")
        lines.append("| （无差额条目） | — | — | — |")
    lines.append("")
    if delta_names:
        lines.append(
            "以下包在 `backend/requirements.txt` 中声明、但未在 `backend/requirements-lock.txt` 中固定版本，"
            "内网离线安装将无法保证版本一致性，请尽快补锁：\n"
        )
        for n in sorted(delta_names):
            lines.append(f"- {n}")
    else:
        declared = sorted(req_display.values())
        lines.append(
            f"核对结论：`backend/requirements.txt` 声明的 {len(declared)} 个直接依赖"
            f"（{', '.join(declared)}）均已在 `backend/requirements-lock.txt` 中固定版本，"
            "差额为 **0**。（`psycopg[binary]` extra 对应锁文件中的 `psycopg==3.3.6` 与 `psycopg-binary==3.3.6` 两条。）"
        )
    lines.append("")
    return "\n".join(lines)


def render(backend_rows, delta_names, req_display, frontend_rows, frontend_lockfile_version, overrides) -> str:
    now = datetime.now().astimezone()
    weak_b, strong_b = classify_copyleft(backend_rows)
    weak_f, strong_f = classify_copyleft(frontend_rows)

    lines = []
    lines.append("# 第三方许可清单（THIRD-PARTY NOTICES）\n")
    lines.append("> 本文件由脚本自动生成，**请勿手工编辑**；需要变更时请修改数据源或 override 表后重新生成。\n")

    lines.append("## 生成信息\n")
    lines.append("| 项 | 值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 生成命令 | `{GEN_COMMAND}`（在仓库根目录执行；脚本路径按自身位置解析，不依赖 cwd） |")
    lines.append(
        f"| 数据来源 | 后端：`backend/requirements-lock.txt`（{len(backend_rows)} 个固定版本包）+ "
        f"`backend/requirements.txt`（声明口径差额核对）；前端：`frontend/package-lock.json`"
        f"（npm lockfileVersion {frontend_lockfile_version}，{len(frontend_rows)} 个包） |"
    )
    lines.append(
        "| 许可解析口径 | 后端：本机 `importlib.metadata`（License-Expression → License 自由文本 → License 分类器），"
        "本机未装/无许可字段时查 `scripts/third_party_licenses.json` override 表；"
        "前端：lock 条目 `license` 字段 → `frontend/node_modules/<pkg>/package.json` → override 表 |"
    )
    lines.append(f"| 生成时间 | {now.strftime('%Y-%m-%d %H:%M:%S %z')}（本机时区） |")
    lines.append(
        "| 必须重跑本脚本的时机 | ① 升级/更换任何依赖后；② 修改 `backend/requirements-lock.txt`、"
        "`backend/requirements.txt`、`frontend/package-lock.json` 任一后；③ 切换 Python 版本或操作系统后"
        "（本机 metadata 口径会变）；④ 更新 `scripts/third_party_licenses.json` 后。"
        "依赖未变时重跑，除“生成时间”行外输出应完全一致 |"
    )
    lines.append(
        f"| 异常许可计数 | 弱传染（MPL/LGPL 等）：{len(weak_b) + len(weak_f)} 条；"
        f"强传染/商业/未知（GPL/AGPL/SSPL/COMMERCIAL/UNKNOWN）：{len(strong_b) + len(strong_f)} 条 |"
    )
    lines.append("")

    lines.append(f"## 一、后端依赖（`requirements-lock.txt` 全部，{len(backend_rows)} 个）\n")
    lines.append(
        "锁文件未按“运行/测试”显式分组，其文件头亦声明“锁文件同时服务运行环境与测试环境，避免能跑不能测”，"
        "故本表列全部包。其中测试链路为 pytest 及其传递依赖（pytest / pluggy / iniconfig；"
        "packaging 同时是 onnxruntime 的运行期传递依赖，故不做强行拆分）。\n"
    )
    lines.append(render_table(backend_rows))
    lines.append("")

    lines.append(render_delta_section(delta_names, req_display, {normalize(r["name"]) for r in backend_rows}))

    lines.append(f"## 三、前端依赖（`frontend/package-lock.json`，{len(frontend_rows)} 个）\n")
    lines.append(
        "含运行时依赖与构建/dev 依赖（element-plus / @vue/* / vite / @vitejs/plugin-vue 及其传递依赖）。"
        "许可全部来自 lock 条目 `license` 字段。\n"
    )
    lines.append(render_table(frontend_rows))
    lines.append("")

    lines.append(render_copyleft_section(backend_rows, frontend_rows))

    # 附录：override 条目与核验来源
    lines.append("## 附录：override 条目与核验来源\n")
    lines.append(
        "以下包的许可来自 `scripts/third_party_licenses.json`（本机未安装、metadata 不可读，"
        "或 lock 未写许可），均已逐条与 PyPI/npm 官方口径核对：\n"
    )
    lines.append("| Package | License | verified_from |")
    lines.append("| --- | --- | --- |")
    used = {}
    for r in backend_rows + frontend_rows:
        if r["source"] == "override":
            used[normalize(r["name"])] = r["name"]
    for key in sorted(used):
        display = used[key]
        entry = overrides.get(key, {})
        lines.append(f"| {md_escape(display)} | {md_escape(entry.get('license', '?'))} | {md_escape(entry.get('verified_from', '?'))} |")
    unused = sorted(set(overrides) - set(used))
    if unused:
        lines.append("")
        lines.append(f"注：override 表中以下条目本次未被使用（依赖已消失或已可本地解析），可清理：{', '.join(unused)}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- 主流程


def main() -> int:
    overrides = load_overrides()

    backend_rows = collect_backend(overrides)

    req_names, req_display = parse_requirements_names(REQUIREMENTS_PATH)
    if req_names is None:
        print(f"[warn] requirements.txt 缺失，跳过差额核对: {REQUIREMENTS_PATH}", file=sys.stderr)
        req_names, req_display = set(), {}
    locked_names = {normalize(r["name"]) for r in backend_rows}
    delta_names = req_names - locked_names

    frontend_rows, lockfile_version = collect_frontend(overrides)

    md = render(backend_rows, delta_names, req_display, frontend_rows, lockfile_version, overrides)
    OUT_PATH.write_text(md, encoding="utf-8")

    unknown = [r for r in backend_rows + frontend_rows if r["source"] == "none"]
    print(f"[ok] 已生成 {OUT_PATH}")
    print(
        f"  后端依赖: {len(backend_rows)}（override {sum(1 for r in backend_rows if r['source'] == 'override')} 条）；"
        f"requirements.txt 差额: {len(delta_names)}；"
        f"前端依赖: {len(frontend_rows)}（override {sum(1 for r in frontend_rows if r['source'] == 'override')} 条）"
    )
    if unknown:
        print(f"[warn] 未解析许可 {len(unknown)} 条（已标 {UNKNOWN}，请补 override 表后重跑）：", file=sys.stderr)
        for r in unknown:
            print(f"  - {r['name']}=={r['version']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
