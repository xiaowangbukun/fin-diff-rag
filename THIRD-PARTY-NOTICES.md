# 第三方许可清单（THIRD-PARTY NOTICES）

> 本文件由脚本自动生成，**请勿手工编辑**；需要变更时请修改数据源或 override 表后重新生成。

## 生成信息

| 项 | 值 |
| --- | --- |
| 生成命令 | `D:/workspace/python/python.exe scripts/generate_third_party_notices.py`（在仓库根目录执行；脚本路径按自身位置解析，不依赖 cwd） |
| 数据来源 | 后端：`backend/requirements-lock.txt`（56 个固定版本包）+ `backend/requirements.txt`（声明口径差额核对）；前端：`frontend/package-lock.json`（npm lockfileVersion 3，128 个包） |
| 许可解析口径 | 后端：本机 `importlib.metadata`（License-Expression → License 自由文本 → License 分类器），本机未装/无许可字段时查 `scripts/third_party_licenses.json` override 表；前端：lock 条目 `license` 字段 → `frontend/node_modules/<pkg>/package.json` → override 表 |
| 生成时间 | 2026-10-25 15:17:45 +0800（本机时区） |
| 必须重跑本脚本的时机 | ① 升级/更换任何依赖后；② 修改 `backend/requirements-lock.txt`、`backend/requirements.txt`、`frontend/package-lock.json` 任一后；③ 切换 Python 版本或操作系统后（本机 metadata 口径会变）；④ 更新 `scripts/third_party_licenses.json` 后。依赖未变时重跑，除“生成时间”行外输出应完全一致 |
| 异常许可计数 | 弱传染（MPL/LGPL 等）：3 条；强传染/商业/未知（GPL/AGPL/SSPL/COMMERCIAL/UNKNOWN）：0 条 |

## 一、后端依赖（`requirements-lock.txt` 全部，56 个）

锁文件未按“运行/测试”显式分组，其文件头亦声明“锁文件同时服务运行环境与测试环境，避免能跑不能测”，故本表列全部包。其中测试链路为 pytest 及其传递依赖（pytest / pluggy / iniconfig；packaging 同时是 onnxruntime 的运行期传递依赖，故不做强行拆分）。

| Package | Version | License | 来源 |
| --- | --- | --- | --- |
| alembic | 1.20.1 | MIT | metadata |
| annotated-doc | 0.0.5 | MIT | metadata |
| annotated-types | 0.8.0 | MIT | metadata |
| anyio | 4.15.1 | MIT | metadata |
| certifi | 2026.7.22 | MPL-2.0 | metadata |
| cffi | 2.1.1 | MIT-0 | metadata |
| charset-normalizer | 3.5.2 | MIT | metadata |
| click | 8.5.0 | BSD-3-Clause | metadata |
| colorama | 0.4.6 | BSD-3-Clause | metadata |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | metadata |
| et_xmlfile | 2.0.0 | MIT | metadata |
| fastapi | 0.143.1 | MIT | metadata |
| flatbuffers | 25.12.19 | Apache 2.0 | metadata |
| h11 | 0.16.0 | MIT | metadata |
| httpcore | 1.0.9 | BSD-3-Clause | metadata |
| httpx | 0.28.1 | BSD-3-Clause | metadata |
| idna | 3.20 | BSD-3-Clause | metadata |
| iniconfig | 2.3.1 | MIT | metadata |
| lxml | 6.1.3 | BSD-3-Clause | metadata |
| mako | 1.4.3 | MIT | metadata |
| markupsafe | 3.0.4 | BSD-3-Clause | metadata |
| numpy | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | metadata |
| onnxruntime | 1.31.0 | MIT License | metadata |
| opencv-python | 5.0.0.93 | Apache 2.0 | metadata |
| openpyxl | 3.1.5 | MIT | metadata |
| opentelemetry-api | 1.45.1 | Apache-2.0 | metadata |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | metadata |
| pdfminer.six | 20260107 | MIT | metadata |
| pdfplumber | 0.11.10 | MIT | metadata |
| pgvector | 0.5.1 | MIT | metadata |
| pillow | 12.3.0 | MIT-CMU | metadata |
| pluggy | 1.7.0 | MIT | metadata |
| protobuf | 7.36.2 | 3-Clause BSD License | metadata |
| psycopg | 3.3.6 | LGPL-3.0-only | metadata |
| psycopg-binary | 3.3.6 | LGPL-3.0-only | metadata |
| pyclipper | 1.4.0 | MIT | metadata |
| pycparser | 3.11 | BSD-3-Clause | metadata |
| pydantic | 2.14.1 | MIT | metadata |
| pydantic_core | 2.50.1 | MIT | metadata |
| Pygments | 2.21.0 | BSD-2-Clause | metadata |
| PyJWT | 2.15.1 | MIT | metadata |
| pypdf | 6.20.1 | BSD-3-Clause | metadata |
| pypdfium2 | 5.14.0 | BSD-3-Clause, Apache-2.0, dependency licenses | metadata |
| pytest | 9.1.1 | MIT | metadata |
| python-docx | 1.2.0 | MIT | metadata |
| python-multipart | 0.0.32 | Apache-2.0 | metadata |
| PyYAML | 6.0.3 | MIT | metadata |
| rapidocr-onnxruntime | 1.2.3 | Apache-2.0 | metadata |
| shapely | 2.2.0 | BSD-3-Clause | metadata |
| six | 1.17.0 | MIT | metadata |
| SQLAlchemy | 2.1.4 | MIT | metadata |
| starlette | 1.8.0 | BSD-3-Clause | metadata |
| typing_extensions | 4.16.0 | PSF-2.0 | metadata |
| typing-inspection | 0.4.4 | MIT | metadata |
| tzdata | 2026.5 | Apache-2.0 | metadata |
| uvicorn | 0.54.0 | BSD-3-Clause | metadata |

## 二、`requirements.txt` 声明但 `requirements-lock.txt` 未锁定的包（差额核对）

| Package | Version | License | 来源 |
| --- | --- | --- | --- |
| （无差额条目） | — | — | — |

核对结论：`backend/requirements.txt` 声明的 19 个直接依赖（PyJWT, alembic, cryptography, fastapi, httpx, openpyxl, pdfplumber, pgvector, psycopg, pydantic, pypdf, pypdfium2, pytest, python-docx, python-multipart, rapidocr-onnxruntime, sqlalchemy, tzdata, uvicorn）均已在 `backend/requirements-lock.txt` 中固定版本，差额为 **0**。（`psycopg[binary]` extra 对应锁文件中的 `psycopg==3.3.6` 与 `psycopg-binary==3.3.6` 两条。）

## 三、前端依赖（`frontend/package-lock.json`，128 个）

含运行时依赖与构建/dev 依赖（element-plus / @vue/* / vite / @vitejs/plugin-vue 及其传递依赖）。许可全部来自 lock 条目 `license` 字段。

| Package | Version | License | 来源 |
| --- | --- | --- | --- |
| @babel/helper-string-parser | 7.29.7 | MIT | lock |
| @babel/helper-validator-identifier | 7.29.7 | MIT | lock |
| @babel/parser | 7.29.9 | MIT | lock |
| @babel/types | 7.29.8 | MIT | lock |
| @ctrl/tinycolor | 4.2.1 | MIT | lock |
| @element-plus/icons-vue | 2.3.2 | MIT | lock |
| @esbuild/aix-ppc64 | 0.21.5 | MIT | lock |
| @esbuild/android-arm | 0.21.5 | MIT | lock |
| @esbuild/android-arm64 | 0.21.5 | MIT | lock |
| @esbuild/android-x64 | 0.21.5 | MIT | lock |
| @esbuild/darwin-arm64 | 0.21.5 | MIT | lock |
| @esbuild/darwin-x64 | 0.21.5 | MIT | lock |
| @esbuild/freebsd-arm64 | 0.21.5 | MIT | lock |
| @esbuild/freebsd-x64 | 0.21.5 | MIT | lock |
| @esbuild/linux-arm | 0.21.5 | MIT | lock |
| @esbuild/linux-arm64 | 0.21.5 | MIT | lock |
| @esbuild/linux-ia32 | 0.21.5 | MIT | lock |
| @esbuild/linux-loong64 | 0.21.5 | MIT | lock |
| @esbuild/linux-mips64el | 0.21.5 | MIT | lock |
| @esbuild/linux-ppc64 | 0.21.5 | MIT | lock |
| @esbuild/linux-riscv64 | 0.21.5 | MIT | lock |
| @esbuild/linux-s390x | 0.21.5 | MIT | lock |
| @esbuild/linux-x64 | 0.21.5 | MIT | lock |
| @esbuild/netbsd-x64 | 0.21.5 | MIT | lock |
| @esbuild/openbsd-x64 | 0.21.5 | MIT | lock |
| @esbuild/sunos-x64 | 0.21.5 | MIT | lock |
| @esbuild/win32-arm64 | 0.21.5 | MIT | lock |
| @esbuild/win32-ia32 | 0.21.5 | MIT | lock |
| @esbuild/win32-x64 | 0.21.5 | MIT | lock |
| @floating-ui/core | 1.8.0 | MIT | lock |
| @floating-ui/dom | 1.8.0 | MIT | lock |
| @floating-ui/utils | 0.2.12 | MIT | lock |
| @jridgewell/sourcemap-codec | 1.6.0 | MIT | lock |
| @napi-rs/lzma-linux-x64-gnu | 1.5.1 | MIT | lock |
| @popperjs/core | 2.11.8 | MIT | lock |
| @rollup/rollup-android-arm-eabi | 4.64.6 | MIT | lock |
| @rollup/rollup-android-arm64 | 4.64.6 | MIT | lock |
| @rollup/rollup-darwin-arm64 | 4.64.6 | MIT | lock |
| @rollup/rollup-darwin-x64 | 4.64.6 | MIT | lock |
| @rollup/rollup-freebsd-arm64 | 4.64.6 | MIT | lock |
| @rollup/rollup-freebsd-x64 | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-arm-gnueabihf | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-arm-musleabihf | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-arm64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-arm64-musl | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-loong64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-loong64-musl | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-ppc64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-ppc64-musl | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-riscv64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-riscv64-musl | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-s390x-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-x64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-linux-x64-musl | 4.64.6 | MIT | lock |
| @rollup/rollup-openbsd-x64 | 4.64.6 | MIT | lock |
| @rollup/rollup-openharmony-arm64 | 4.64.6 | MIT | lock |
| @rollup/rollup-win32-arm64-msvc | 4.64.6 | MIT | lock |
| @rollup/rollup-win32-ia32-msvc | 4.64.6 | MIT | lock |
| @rollup/rollup-win32-x64-gnu | 4.64.6 | MIT | lock |
| @rollup/rollup-win32-x64-msvc | 4.64.6 | MIT | lock |
| @types/estree | 1.0.9 | MIT | lock |
| @types/lodash | 4.17.26 | MIT | lock |
| @types/lodash-es | 4.17.12 | MIT | lock |
| @types/web-bluetooth | 0.0.21 | MIT | lock |
| @vitejs/plugin-vue | 5.2.4 | MIT | lock |
| @vue/compiler-core | 3.5.44 | MIT | lock |
| @vue/compiler-dom | 3.5.44 | MIT | lock |
| @vue/compiler-sfc | 3.5.44 | MIT | lock |
| @vue/compiler-ssr | 3.5.44 | MIT | lock |
| @vue/devtools-api | 6.6.4 | MIT | lock |
| @vue/reactivity | 3.5.44 | MIT | lock |
| @vue/runtime-core | 3.5.44 | MIT | lock |
| @vue/runtime-dom | 3.5.44 | MIT | lock |
| @vue/server-renderer | 3.5.44 | MIT | lock |
| @vue/shared | 3.5.44 | MIT | lock |
| @vueuse/core | 15.0.0 | MIT | lock |
| @vueuse/metadata | 15.0.0 | MIT | lock |
| @vueuse/shared | 15.0.0 | MIT | lock |
| agent-base | 6.0.2 | MIT | lock |
| async-validator | 4.2.5 | MIT | lock |
| asynckit | 0.4.0 | MIT | lock |
| axios | 1.20.0 | MIT | lock |
| call-bind-apply-helpers | 1.0.2 | MIT | lock |
| combined-stream | 1.0.8 | MIT | lock |
| csstype | 3.2.3 | MIT | lock |
| dayjs | 1.11.23 | MIT | lock |
| debug | 4.4.3 | MIT | lock |
| delayed-stream | 1.0.0 | MIT | lock |
| dunder-proto | 1.0.1 | MIT | lock |
| element-plus | 2.14.7 | MIT | lock |
| entities | 7.0.1 | BSD-2-Clause | lock |
| es-define-property | 1.0.1 | MIT | lock |
| es-errors | 1.3.0 | MIT | lock |
| es-object-atoms | 1.1.2 | MIT | lock |
| es-set-tostringtag | 2.1.0 | MIT | lock |
| esbuild | 0.21.5 | MIT | lock |
| estree-walker | 2.0.2 | MIT | lock |
| follow-redirects | 1.16.1 | MIT | lock |
| form-data | 4.0.6 | MIT | lock |
| fsevents | 2.3.3 | MIT | lock |
| function-bind | 1.1.2 | MIT | lock |
| get-intrinsic | 1.3.0 | MIT | lock |
| get-proto | 1.0.1 | MIT | lock |
| gopd | 1.2.0 | MIT | lock |
| has-symbols | 1.1.0 | MIT | lock |
| has-tostringtag | 1.0.2 | MIT | lock |
| hasown | 2.0.4 | MIT | lock |
| https-proxy-agent | 5.0.1 | MIT | lock |
| lodash | 4.18.1 | MIT | lock |
| lodash-es | 4.18.1 | MIT | lock |
| lodash-unified | 1.0.3 | MIT | lock |
| magic-string | 0.30.21 | MIT | lock |
| math-intrinsics | 1.1.0 | MIT | lock |
| memoize-one | 6.0.0 | MIT | lock |
| mime-db | 1.52.0 | MIT | lock |
| mime-types | 2.1.35 | MIT | lock |
| ms | 2.1.3 | MIT | lock |
| nanoid | 3.3.20 | MIT | lock |
| normalize-wheel-es | 1.2.0 | BSD-3-Clause | lock |
| picocolors | 1.1.1 | ISC | lock |
| postcss | 8.5.30 | MIT | lock |
| proxy-from-env | 2.1.0 | MIT | lock |
| rollup | 4.64.6 | MIT | lock |
| source-map-js | 1.2.2 | BSD-3-Clause | lock |
| vite | 5.4.21 | MIT | lock |
| vue | 3.5.44 | MIT | lock |
| vue-component-type-helpers | 3.3.13 | MIT | lock |
| vue-router | 4.6.4 | MIT | lock |

## 传染性许可提示（Copyleft 提示）

以下条目含弱传染（文件级/库级）许可，**均与 AGPL-3.0 兼容**（MPL-2.0 §3.3 明列 AGPL 为次级许可；LGPL-3.0 可升级为 GPL-3.0，再经 GPL-3.0 §13 与 AGPL 组合）：随分发提供对应许可文本即可，**不需要**为本项目开源；但不得删除/修改其随附许可声明。

| Package | License | 传染性说明 |
| --- | --- | --- |
| certifi | MPL-2.0 | MPL-2.0 文件级弱传染：仅修改 certifi 自身源文件时才需开源该文件；随分发提供 MPL-2.0 文本即可 |
| psycopg | LGPL-3.0-only | LGPL-3.0 弱传染：以独立进程/动态链接方式使用不传染本项目；随分发提供 LGPL-3.0 文本即可 |
| psycopg-binary | LGPL-3.0-only | LGPL-3.0 弱传染：psycopg 的二进制发行形态，口径同 psycopg |

补充：以下二进制 wheel 内嵌组件的许可口径已经 QA 核验（2026-10-20）：

- shapely（BSD-3-Clause）的 wheel 内嵌 GEOS 库（LGPL-2.1，弱传染）：随分发提供 LGPL-2.1 许可文本即可。
- pypdfium2（Apache-2.0 / BSD-3-Clause 双许可）的 wheel 内嵌 PDFium 及 abseil/freetype/icu/lcms2/libjpeg-turbo/libpng/zlib 等依赖（均 BSD 风格），wheel 内已随附对应许可文本。
- numpy（BSD-3-Clause）的 wheel 内置 OpenBLAS（BSD-3-Clause）与 GCC runtime（GPL-3.0-with-GCC-exception，例外条款明确允许随二进制分发）。

### 强传染许可红线

**本项目自身以 AGPL-3.0 发布：引入 GPL-3.0 / AGPL-3.0 依赖在法律上可组合（GPL-3.0 §13、AGPL-3.0 §13），但仍须在清单中登记；若引入 GPL-2.0-only / SSPL / COMMERCIAL 类许可，或出现 `UNKNOWN-需人工核验` 条目，必须先经法务评审通过，方可进入分发/交付流程。**

本清单生成时**未检出** GPL / AGPL / SSPL / COMMERCIAL / UNKNOWN 条目（逐表见上）。

## 附录：override 条目与核验来源

以下包的许可来自 `scripts/third_party_licenses.json`（本机未安装、metadata 不可读，或 lock 未写许可），均已逐条与 PyPI/npm 官方口径核对：

| Package | License | verified_from |
| --- | --- | --- |

注：override 表中以下条目本次未被使用（依赖已消失或已可本地解析），可清理：flatbuffers, numpy, onnxruntime, opencv-python, protobuf, psycopg, psycopg-binary, pyclipper, pyyaml, rapidocr-onnxruntime, shapely, six
