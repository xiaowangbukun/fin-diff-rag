# 金融企业级 RAG 知识库（全链路权限防泄密）

> 本项目基于 [Apache License 2.0](LICENSE) 发布

面向金融机构的检索增强问答系统。核心不是"能不能答出来"，而是**该看的能看到、不该看的永远出不去**——从文档入库、切片、建索引、检索、上下文装配、生成到出库，每个环节都带权限校验与审计留痕。

技术栈：FastAPI + Vue3 + PostgreSQL(pgvector) + OpenAI 兼容接口。
存储为 **PostgreSQL + pgvector**（唯一存储后端，演示同样需要先起 PG）；Embedding 必须接真实服务（未配 `EMBED_API_KEY` 默认拒绝启动）；LLM 未配置时答案退化为原文抽取式回答，权限/检索/审计全部照常。

---

## 一、全链路防泄密是怎么落地的

```
上传/录入 ──▶ 敏感信息扫描 ──▶ 语义切片（段落级密级探测）──▶ 向量化 ──▶ 入库（密级+ACL+归属部门）
                                                                        │
用户提问 ──▶ ⓿ 意图识别网关：正常查询放行 / 跨域组合→推理距离约束 / 拼图探针→物理阻断
            ├─ ① 权限前置过滤（SQL 下推：文档密级 / ACL / 部门树 / 切片级密级）
            ├─ ② 向量召回 + 关键词召回（并行，双校验架构第一道：粗筛）
            ├─ ③ RRF 融合 + 轻量 Rerank
            ├─ ④ 精校验（第二道）：逐条回库复核 + Top-K 密级校验 + 隐式向量验证
            ├─ ⑤ 防拼图裁决：按累积暴露量裁剪，必须在内容进入上下文之前完成
            ├─ ⑥ 按用户密级脱敏上下文（身份证/银行卡/手机号/邮箱）
            ├─ ⑦ 相关性闸门：不达标直接拒答，不让模型编
            ├─ ⑧ 生成（强制标注 [n] 引用）+ 出口二次扫描
            └─ ⑨ 审计落库（谁、何时、问了什么、命中哪些、拦了哪些、为何被裁）

任一环节异常（权限引擎/检索组件故障）──▶ Fail-Secure：切断内部知识库，降级仅检索 Public 公开域；
                                             公开域也不可用 → 安全拒答。宁可不答，绝不越权。
```

**权限判定规则**（优先级从高到低，文档级与切片级同时适用）

```
1. 命中 deny 主体（未过期）              → 拒绝
2. 有效密级 > 用户密级                    → 拒绝（硬门槛；有效密级 = max(文档密级, 切片密级)）
3. acl_mode = open                       → 允许
4. acl_mode = dept 且用户部门 ∈ 文档归属部门子树 → 允许
5. 命中 allow 主体（未过期）              → 允许
6. 其余                                   → 拒绝（默认拒绝，不放行）
```

---

## 一之二、企业级 RAG 权限防泄密四条核心准则（对照落地）

对应教学视频的「企业级 RAG 权限防泄密核心准则」，逐条说明在本系统中的落地方式与代码位置：

| 准则 | 落地实现 | 代码位置 |
|---|---|---|
| **颗粒度下沉**：控制基准从文档级重构至 Chunk 级，权限与物理存储解耦 | 切片可携带独立密级（`Chunk.clearance`，NULL=继承文档），有效密级 = max(文档, 切片)，在 SQL 层与文档级条件一并下推；同文档跨密级隔离，治"段落级撕裂" | `app/models.py` / `app/policy.py` `chunk_clearance_cond` / `app/ingest.py` `detect_chunk_clearance` |
| **双端闭环防线**：检索前置拦截 + 生成后置校验，缺一不可 | 前置：文档级标签 SQL 粗筛（快速排除 90% 无关切片）；后置：逐条回库复核 + Top-K 密级校验 + 隐式向量验证（不信任召回行明文字段）；生成后置：出口二次扫描 + 强制引用标注 | `app/retrieve.py` `search` / `app/routers/chat.py` |
| **隐式防线升级**：舍弃明文标签，转向向量空间对齐 + 前置意图熔断 | 越权文档的编号/密级/原因不下发给普通用户（存在性即敏感，直取统一 404）；探针识别不依赖文档标签明文，靠提问特征 + 服务端账本指纹 | `app/intent.py` / `app/routers/docs.py` `_mask_not_found` |
| **Fail-Secure 底线**：消除缓存时间窗，权限故障立刻降级断联，宁可不答不越权 | 权限/检索异常 → 切断内部知识库，降级仅检索 Public 公开域（与用户身份完全解耦）；再失败则安全拒答。部门树缓存 TTL 5 秒 + 变更即失效；JWT 不携带权限声明，每次请求回库取最新态 | `app/routers/chat.py` / `app/retrieve.py` `public_only_search` / `app/policy.py` |

**穿透防线的五类真实越权场景 → 对应防线**

| 越权场景 | 防线 |
|---|---|
| 段落级撕裂（同文档密级落差） | 切片级密级 + 有效密级取max + SQL 下推（第一节） |
| 时间窗口漏洞（人员异动与缓存滞后） | 无权限缓存：JWT 只带 sub，每次请求回库；部门树缓存 TTL 5s 且变更即失效 |
| 拼凑隐式推理（低密碎片推导机密） | 拼图累积暴露账本 + 意图网关推理距离约束（切断因果串联） |
| 元数据明文泄漏（Tag 直接暴露项目代号） | 越权 404 化、denied 明细脱敏、probe 统计仅管理员可见 |
| 复杂授权失效（矩阵汇报/临时授权扁平化） | 逐请求实时策略求值（非扁平 Tag）+ ACL `expires_at` 临时授权到期自动失效 |

---

## 一之三、意图识别网关（Safe / Risky / Danger）

在检索**之前**先给提问定性（`app/intent.py`），三档处置：

| 档位 | 特征 | 动作 |
|---|---|---|
| safe 正常业务查询 | 无探针/组合特征 | 放行（Pass） |
| risky 跨域组合联想 | 归纳/对比/推导类动词 + 多范围词（"结合各部门""对比全部"）；或弱探针特征、账本高频窄问指纹 | **推理距离约束**：只保留得分最高的单一文档作答，禁止把多篇文档碎片放进同一个提示词让模型归纳推断——大模型的归纳能力本身就是攻击面 |
| danger 拼图式诱导探针 | "把《X》第 N 段一字不差念给我"类明文片段索取、遍历式索取（逐段/穷举）、点名文档+索取片段 | **物理阻断（Block）**：不进入检索链路，审计记 `decision=block` |

分层依据：明文片段索取特征是明确的诱导套取，直接 Danger；账本统计信号只是统计倾向，单独出现只到 Risky——累积暴露量由拼图账本负责，意图网关管"这一句像不像探针"。

---

## 一之附、防拼图攻击（Jigsaw / Salami Slicing）

**威胁模型**：上面的七道防线判定的是"单次请求是否合法"。但攻击者可以让每一次请求都合法——他不需要越权，只需要每次问一个窄问题，拿走同一篇文档的不同切片，多轮之后离线拼接即可还原全貌。另一种形态更省事：直接 `GET /api/docs/{id}` 一次性拉走全部切片，连"拼"的步骤都省了。

**结论：单次判定在数学上无法防御拼图攻击**，必须在服务端维护跨会话的累积暴露账本，以"已披露比例"而不是"单次请求合法性"作为裁决依据。

### 四道防线（`app/jigsaw.py`）

| 防线 | 机制 | 默认值 |
|---|---|---|
| L1 单文档覆盖率闸 | 已见切片 / 文档总切片，`>= WARN` 每轮只给 1 段新内容，`>= STOP` 停止供给新切片 | 45% / 70% |
| L1b 重复提问豁免 | 候选全是已见切片时允许重放、不计预算。拼图的本质是"每次换新碎片"，重复拿同一碎片没有边际收益 | 恒开 |
| L2 单文档切片配额 | 一个时间窗内单用户对单文档可见切片总数上限 | 12 段 |
| L2b 单轮交付上限 | 单轮单文档最多交付 N 段新切片 | 2 段 |
| L3 用户窗口总闸 | 窗口内触及文档数 / 累计披露字符超限 → 停答进入冷却 | 25 篇 / 120000 字 |
| L4 全篇直读闸 | 限制绕过问答直接拉全文的次数，且读过的切片计入同一本账 | 3 次 |

### 两条反直觉的设计（都是踩过坑换来的）

1. **L2b 单轮上限是最容易被漏掉、却最致命的一条。** `top_k=8` 时，一篇 9 段的文档一轮就能被拿走 89%，覆盖率闸再严也拦不住"一轮搬空"。必须从单轮就开始限流。
2. **短文档不启用覆盖率闸**（`JIGSAW_MIN_DOC_CHUNKS`，默认 6 段）。2 段的文档问两句就 100% 覆盖，本身没有"可拼"的空间，启用只会把正常用户锁死——问第二遍就没答案了。

### 顺手关掉的一个"导航仪"

原实现会把"若关闭权限控制本会命中多少篇越权文档"返回给提问者。这个数字对攻击者是极强的旁路信号：他不需要拿到内容，只要观察到"这个问题命中 6 篇绝密"，就知道该往哪个方向继续拼。**现在该统计仅对管理员开放**，普通用户恒为 0（审计侧仍保留全量，安全运营不受影响）。

### 可观测性

- 问答响应体带 `jigsaw` 字段：`level`（none/warn/restrict/block）、`message`、每个文档的 `seen/total/coverage/delivered/capped`。
- 前端问答页有防拼图提示条，管理端有**拼图风险榜**（`GET /api/admin/jigsaw`），审计页可按 `decision=throttle` 筛出所有限流记录。
- 所有配置项在 `backend/app/config.py`，可用环境变量覆盖；`JIGSAW_ENABLED=false` 可整体关闭（仅建议联调时使用）。

### 已知边界

- **多账号合谋**（N 个低权限账号各取一块、线下合并）靠单账号账本挡不住，需要跨用户关联分析或离线 DLP 兜底，当前未实现。
- 覆盖率阈值是经验值，不同文档长度分布下需要按机构实际调。

---

## 二、目录结构

```
fin-rag/
├── docker-compose.yml          PostgreSQL + pgvector
├── .env.example                配置模板（复制为 .env）
├── start-backend.bat           一键启动后端
├── start-frontend.bat          一键启动前端
├── backend/
│   ├── app/
│   │   ├── config.py           全部环境变量可覆盖
│   │   ├── db.py               PostgreSQL 引擎（pgvector，唯一存储后端）
│   │   ├── models.py           部门/用户/文档/ACL/切片(含切片级密级)/暴露账本/审计/版本快照
│   │   ├── security.py         JWT + 密码哈希
│   │   ├── policy.py           权限引擎（核心）：密级/ACL/部门树/切片级/临时授权过期/就绪状态
│   │   ├── intent.py           意图识别网关（safe/risky/danger → 放行/约束/阻断）
│   │   ├── pii.py              敏感信息识别与脱敏
│   │   ├── injection.py        提示注入扫描（入库 + 问答出口双向）
│   │   ├── pdfx.py             PDF 解析加固：表格结构化/多栏/质量检测/OCR
│   │   ├── ingest.py           文档解析 + 语义切片 + 段落级密级探测 + 版本快照
│   │   ├── embed.py            向量化（远程 embedding；无 Key 拒绝启动）
│   │   ├── retrieve.py         双校验架构检索 + 公开域降级通道
│   │   ├── jigsaw.py           防拼图攻击引擎（累积暴露账本 + 长周期闸）
│   │   ├── llm.py              生成（远程 + 抽取式降级）
│   │   ├── audit.py            审计留痕（异步写入 + 哈希链 + 启动锚点）
│   │   ├── errors.py           全局异常语义（503 + Retry-After / 500 堆栈）
│   │   ├── approval.py         密级变更审批流（降密双人复核）
│   │   ├── monitor.py          运维日报（/api/admin/report/daily）
│   │   ├── metrics.py          安全指标监控（/api/admin/metrics）
│   │   ├── migrate.py          增量 schema 白名单（旧库无 Alembic 平滑升级）
│   │   ├── totp.py             TOTP 第二因子（RFC 6238 + 密钥 Fernet 加密入库）
│   │   ├── recovery.py         一次性恢复码（摘要存储、一码一用、整组重生成）
│   │   ├── oidc.py             OIDC 客户端（discovery / JWKS / PKCE / 验签）
│   │   ├── vindex.py           pgvector 向量索引保障（HNSW）
│   │   ├── seed.py             内置示例数据（含混合密级文档）
│   │   └── routers/            auth / docs / chat / admin
│   ├── tests/                  pytest 单测体系（697 例，每用例独立 schema 跑真实 PG；含 idp_stub.py 真 HTTP OIDC Provider）
│   ├── smoke.py                端到端冒烟（257 项断言）
│   ├── http_check.py           真实服务 HTTP 验证（26 项断言）
│   ├── requirements.txt        最低版本口径
│   ├── requirements-lock.txt   精确版本锁（pip freeze，供离线安装）
│   └── run.py
├── scripts/
│   ├── oidc_live_check.py      对运行中的服务跑真实 OIDC 授权码流程（可指向 Keycloak/Azure AD）
│   └── recovery_live_check.py  对运行中的服务跑恢复码全链路（跑完自动复原被测账号）
└── frontend/                   Vue3 + Element Plus 控制台
```

---

## 三、快速开始

### 前置要求（缺一不可）

| 依赖 | 要求 | 说明 |
|---|---|---|
| PostgreSQL | 14+ 且启用 pgvector 扩展 | HNSW 近似索引与 `vector_cosine_ops` 是 PG 侧能力；本机安装或 docker 均可 |
| Embedding 服务 | OpenAI 兼容接口 + `EMBED_API_KEY` | 未配置默认**拒绝启动**（方案 B，见下）；没有"无 Key 演示路径" |
| Python | 3.13 | 项目基线口径（依赖锁文件同版本，见「三之三」） |

### 第一步：准备数据库

本机已装 PostgreSQL + pgvector：

```sql
CREATE ROLE finrag LOGIN PASSWORD 'Fin@Rag2026';
CREATE DATABASE finrag OWNER finrag;
\c finrag
CREATE EXTENSION vector;
```

或用 docker 一把起（`pgvector/pgvector:pg16` 镜像自带扩展，无需单独装）：

```bash
docker run -d --name finrag-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 pgvector/pgvector:pg16
# 进入容器执行上面的建角色/建库/扩展 SQL（口令换成你自己的）
```

仓库根的 `docker-compose.yml` 同样是一把起 PG + pgvector（`docker compose up -d`）。

### 第二步：配置 .env

复制 `.env.example` 为 `.env`（放仓库根或 `backend/` 下均可，启动时自动读取），必填项：

```env
# 数据库连接串（必填）——口令含特殊字符必须 URL 编码，见下方说明
DATABASE_URL=postgresql+psycopg://finrag:Nzg%40Nul8280@127.0.0.1:5432/finrag
EMBED_API_KEY=sk-xxxxxx
```

> **口令必须 URL 编码**：连接串里的口令出现 `@ : / # ?` 等保留字符时必须 percent-encoding。项目示例口令 `Fin@Rag2026` 含 `@`——原样写进连接串时，psycopg 会把 `Nul8280@127.0.0.1` 当成主机名，报"无法解析主机"类连接错误；编码后为 `Nzg%40Nul8280`（`@` → `%40`）。

### 第三步：安装依赖并启动

```bash
cd fin-rag/backend
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python run.py --port 8000
```

Windows 也可双击仓库根的 `start-backend.bat`（自动建 venv + 装依赖；不再内置 `EMBED_REQUIRE_API_KEY=false` 放行——未配 `EMBED_API_KEY` 会按方案 B 明确拒绝启动，配好后启动）。两种方式都需要先配好 `.env` 里的 `DATABASE_URL`。

接口文档 http://127.0.0.1:8000/docs ，控制台需另起前端或用已构建的 dist。

> **embedding 方案 B（默认拒绝无 Key 启动）**：未配置 `EMBED_API_KEY` 时服务**拒绝启动**：向量通道只有远端 embedding 一种，没有"无 Key 也能跑"的旁路——无语义维度的向量一旦被当作检索依据，输出的就是"看似正常、实则无依据"的答案。仅离线测试/回归基线可显式放行（此时向量由测试替身供给）：`set EMBED_REQUIRE_API_KEY=false`（Windows）或 `export EMBED_REQUIRE_API_KEY=false`（Linux/macOS）；**生产环境禁止使用该放行**。

> `EMBED_DIM` 必须与所选 embedding 模型的输出维度一致（OpenAI text-embedding-3-small = 1536，多数中文模型 = 1024）。改维度需重建 `chunks` 表。

### 接大模型（可选）

`.env` 中配置任一 OpenAI 兼容服务即可：

```env
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_API_KEY=sk-xxxxxx
LLM_MODEL=deepseek-chat
EMBED_BASE_URL=https://api.xxx.com/v1
EMBED_API_KEY=sk-xxxxxx
EMBED_MODEL=text-embedding-v3
EMBED_DIM=1024
```

LLM 不配置时运行在"受限模式"：检索、权限、脱敏、审计全部照常工作，答案退化为原文抽取。**`EMBED_API_KEY` 生产必配**——不配默认拒绝启动（方案 B，见「三、快速开始」的说明）；仅离线测试/回归可 `EMBED_REQUIRE_API_KEY=false` 放行。

### 前端

```bash
cd frontend
npm install
npm run dev      # http://127.0.0.1:5173，已代理 /api 到 8000
npm run build    # 产出 dist/，后端会自动托管，直接访问 8000 即可
```

---

## 三之二、部署基线

单机同时运行后端服务与 PostgreSQL 的最低基线，也是容量边界表的口径前提：

| 项 | 基线 | 说明 |
|---|---|---|
| CPU / 内存 | 4 核 / 8GB | 后端（FastAPI 单 worker）+ PG 同机；`docker-compose.yml` 已给数据库设 `memory: 2g / cpus: 2.0` 上限，防止语料导入或大批量向量检索时数据库吃满内存把后端挤下去 |
| 磁盘 | ≥ 50GB | 语料原文 + 向量 + 审计日志。审计是 append-only 增长，长期运行最需要预留的一块 |
| 架构 | amd64 / arm64 均可 | 依赖全部为跨平台 wheel（onnxruntime / opencv 双架构均有发行包），无本地编译项 |
| Python | **3.13** | 项目基线口径：CI 与依赖锁文件（`requirements-lock.txt`，生成于 3.13.14）同版本。目标机换 Python 版本必须重新 `pip download`（wheel 不跨版本通用），3.15 缺 onnxruntime wheel 的注意见「三之三」 |
| 数据库 | PostgreSQL 14+ 且启用 pgvector 扩展 | HNSW 近似索引与 `vector_cosine_ops` 是 PG 侧能力；14+ 为验证口径，更低版本未测 |
| 大模型 / Embedding | 无外网环境走同网段机器 | `LLM_BASE_URL` / `EMBED_BASE_URL` 指向内网任一 OpenAI 兼容服务即可，代码不依赖公网。LLM 不配时答案退化为原文抽取（权限/检索/审计照常）；**EMBED_API_KEY 生产必配**——不配默认拒绝启动（方案 B），仅演示可 `EMBED_REQUIRE_API_KEY=false` 放行 |

### 生产必配检查清单

1. **`JWT_SECRET`（必须）**：`python -c "import secrets; print(secrets.token_hex(32))"` 生成，≥32 字节。多 worker 部署尤其必须——各进程随机密钥不互通，症状是"间歇性 401 且查不出原因"。推荐同时设 `ENFORCE_JWT_SECRET=true`：缺失即拒绝启动，把"忘了配"从运行时怪题变成启动即错。
2. **`EMBED_API_KEY`（必须）**：未配置默认在 lifespan 拒绝启动（`embed.require_embedding_key`）。`EMBED_REQUIRE_API_KEY=false` 仅限离线测试/回归基线（向量由测试替身供给），生产禁止。
3. **处理出厂口令（必须）**：种子数据默认注入 `admin/Admin@123` 与各业务角色 `User@123`（见下表），其中 admin 为**绝密**级——金融内网漏改等于全库开放。启动时若仍有账号使用出厂口令，日志会打 `[SECURITY]` 告警；建议设 `ENFORCE_PASSWORD_CHANGE=true`，检出即拒绝启动，把"忘了改"变成启动即错。演示账号的口令预填仅为本地演示方便（用户明确保留）；**管理员新建或重置口令的账号不在此列**——这些账号首次登录会被服务端强制改密（见「四」）。
4. **第二因子与企业单点登录（双适配，按需开启）**：两条路径可同时启用、互不冲突——本地账号走「口令 + TOTP 动态口令」，企业账号走「OIDC 授权码 + PKCE」。要点：
   - `MFA_ENABLED=true`（默认）只代表"允许绑定"；**是否强制绑定**由 `MFA_ENFORCE_ADMIN`（默认 false，建议生产置 true：admin 可见绝密）与 `MFA_ENFORCE_ALL`（默认 false）决定，未绑定者除绑定三件套外一律 403（`X-MFA-Setup-Required: 1`）。
   - TOTP 密钥：`MFA_SECRET_KEY`（Fernet key，64 字符 urlsafe base64）留空则由 `JWT_SECRET` 派生——派生意味着轮换 JWT 密钥会解不开已绑定密钥，**生产建议独立配置并纳入密钥管理**（KMS/密钥库），轮换前先让全员重新绑定。
   - OIDC：`OIDC_ENABLED=true` 时必须配齐 `OIDC_ISSUER` 与 `OIDC_CLIENT_ID`，否则**拒绝启动**（`oidc.require_config`）；回调地址在 IdP 侧登记为 `{站点}/api/auth/oidc/callback`（也可显式 `OIDC_REDIRECT_URI`）。账号默认必须先由管理员建好（`OIDC_JIT_PROVISION=false`），开启 JIT 才允许首登自动建号（默认密级 0、无本地口令，只能走 SSO）。
   - 恢复码：绑定即发放一组一次性备用码（`RECOVERY_CODE_COUNT`，默认 10；`RECOVERY_CODE_ENABLED` 可应急关闭），用户手机丢失/换机时可自助登录，不必找管理员；服务端只存摘要、一个码只能用一次。口径见「八」。
   - 若 IdP 已完成 MFA（Azure AD 条件访问 / Keycloak 认证流程），保持 `OIDC_TRUST_IDP_MFA=true`，本地不再叠加动态口令；需要"双因子叠加"的高敏场景再置 false。
   - **IdP claim → 本地权限（可选，默认关）**：确需由 IdP 统一管权限时开 `OIDC_CLAIM_SYNC=true`，并配 `OIDC_ROLE_CLAIM` + `OIDC_ROLE_MAP`（如 `fin_research:research,fin_risk:risk`）、按需配 `OIDC_CLEARANCE_CLAIM` + `OIDC_CLEARANCE_MAP`。务必保留 `OIDC_CLAIM_SYNC_MAX_CLEARANCE`（默认 1）与 `OIDC_CLAIM_SYNC_ALLOW_ADMIN=false`——这是"IdP 配错也不会自动升到绝密/管理员"的兜底；严格一致的环境可把 `OIDC_CLAIM_SYNC_UNKNOWN` 设为 `deny`（白名单外的 claim 值直接拒绝登录）。
   - 联调方式：`python tests/idp_stub.py 9110` 可起一个真实 HTTP 的 OIDC Provider（含 PKCE 与 RS256 签名），配合 `scripts/oidc_live_check.py` 对**运行中的服务**跑一遍授权码流程（`RAG_BASE=... IDP_USER=... IDP_PASSWORD=... python scripts/oidc_live_check.py`）；对接 Keycloak/Azure AD 时把 `OIDC_ISSUER` 换成真实 issuer，用法不变。pytest 侧 `tests/test_oidc_real_idp.py` 走同一套真实 HTTP 链路（不打桩协议函数）。
5. **审计锚点外置（防"双权限重写"，强烈建议生产配）**：把 `AUDIT_ANCHOR_EXTERNAL_FILE` 指向应用只写不读回、无删除权限的卷（WORM/日志卷），或把 `AUDIT_ANCHOR_URL` 指向 SIEM/日志网关（POST JSON，5 秒超时）。建议独立配置 `AUDIT_ANCHOR_HMAC_KEY`（别复用 `JWT_SECRET`），并确认接收端不返回可被应用改写的内容。上线后调一次 `POST /api/admin/audit/anchor` 验证链路，再用 `GET /api/admin/audit/anchor` 确认 `records≥1` 且 `bad_signature=0`。未配置时系统只用本地锚点，防不住同时拿到库写与磁盘写的攻击者（见「十」）。
6. **登录防爆破**：默认 `LOGIN_THROTTLE_BACKEND=auto` 即用 PG 共享计数（多 worker 生效，无需额外组件）；首次升级需确认 `login_attempts` 表已由 `init_db()` 建出。阈值 `LOGIN_MAX_FAILS=5` / `LOGIN_WINDOW_MINUTES=5` / `LOGIN_LOCK_MINUTES=15` 可按机构口令策略调整。
7. **巡检手段**：`GET /api/health` 的 `jwt_secret` 字段为 `configured` / `ephemeral`——脚本可断言其不为 `ephemeral`；`embed_mode` 应为 `api` 而非 `local`。
8. **第三方许可**：`THIRD-PARTY-NOTICES.md`（仓库根，`python scripts/generate_third_party_notices.py` 生成）——升级任何依赖后必须重跑；已知传染性许可 certifi（MPL-2.0）/ psycopg（LGPL-3.0）均与 Apache-2.0 兼容，随分发提供许可文本即可。

## 三之三、离线安装（内网无外网环境）

依赖锁文件 `backend/requirements-lock.txt` 是**精确版本**口径（pip freeze 产物，pytest / smoke / http_check 全套实测跑通），与 `requirements.txt` 的"最低版本"口径互补：

```bash
# ① 有网机器（操作系统、架构、Python 版本与目标机一致）：
pip download -r requirements-lock.txt -d wheels/

# ② 拷贝 wheels/ 到内网目标机后：
pip install --no-index --find-links=wheels/ -r requirements-lock.txt
```

- wheels 必须按目标机的**操作系统 + 架构 + Python 版本**分别准备，不能跨环境混用——wheel 不跨 Python 版本通用。锁文件头注明了生成环境（当前：Python 3.13.14 / Windows x64 / 2026-10-18）；目标机 Python 版本不一致时（例如 3.15），必须在目标机同版本 Python 上重新 `pip download`，"一份 wheels 走天下"是不成立的；
- Python 3.15 等新版本可能缺少 `onnxruntime` 的预编译 wheel（OCR 栈装不上）。此时 OCR 能力不可用：扫描件 PDF 会被明确拒绝并提示"上传文本版或启用 OCR"，**其余链路（解析/权限/检索/问答/审计）不受影响**；
- `rapidocr-onnxruntime` 体积较大（含 ONNX 模型），内网可按需裁掉——缺失时扫描件 OCR 自动降级为"明确拒绝并提示"，其余链路不受影响；
- 锁文件含 pytest 及其传递依赖：同一份 wheels 同时装出运行环境与测试环境，避免"能跑不能测"。

---

## 四、内置演示账号

| 账号 | 密码 | 部门 | 角色 | 密级 |
|---|---|---|---|---|
| admin | Admin@123 | 集团总部 | admin | 绝密 |
| research01 | User@123 | 研究所 | research | 机密 |
| risk01 | User@123 | 风险管理部 | risk | 机密 |
| compliance01 | User@123 | 合规部 | compliance | 机密 |
| wealth01 | User@123 | 财富管理部 | trader | 内部 |
| intern01 | User@123 | 研究所 | guest | 内部 |

内置文档 6 篇，覆盖 4 个密级：公开的产品说明书、内部的投资策略/反洗钱指引/经营分析材料、机密的信用债黑名单、绝密的并购预案。其中《财富管理部季度经营分析材料》是**混合密级样本**——正文为内部级，末尾"绝密附注"段在入库时被自动标记为绝密切片，用来演示同文档跨密级隔离。后两篇含手机号、身份证、银行卡等敏感数据。

> **演示账号与强制改密**：上表 6 个演示账号保留预填口令，登录后不弹强制改密（仅用于本地演示，生产部署按「二」的检查清单必须改掉或用 `ENFORCE_PASSWORD_CHANGE=true` 拦住）。**管理员在「用户与权限」里新建的账号、以及管理员重置过口令的账号，首次登录必须修改初始口令**：服务端对这两类账号除 `/auth/me`、`/auth/change-password`、`/auth/logout` 外的所有接口一律返回 403（`X-Must-Change-Password: 1`），改密成功才解除；前端对应一个不可关闭的改密弹窗。

> **演示账号与动态口令**：演示账号默认**不绑定、也不强制**动态口令（本地配置 `MFA_ENFORCE_ADMIN/MFA_ENFORCE_ALL=false`），登录仍是一步。想体验双因子：用任意账号进「安全设置 → 动态口令」，输入当前口令生成密钥 → 手机验证器录入 → 输一次 6 位码完成绑定；绑定成功会弹出一组**一次性恢复码**（只显示这一次，请复制/下载保存）。此后该账号登录会先要口令、再要动态口令；验证器丢了就在登录第二步点「改用一次性恢复码」，输入一个备用码即可进入（每个码只能用一次）。管理员可在「用户与权限」里对该账号「重置动态口令」（同时作废其全部恢复码并吊销会话），是最后的兜底出口。

### 五分钟验证剧本

1. 用 **intern01** 登录问「信用债黑名单的准入标准是什么」→ 被闸门拦下，**一个字都不漏**；且不会告诉它"你这个问题命中了几篇机密文档"——那等于给拼图攻击指路。
2. 换 **risk01** 问同一问题 → 正常作答，附多段带密级标记的引用溯源。
3. 用 **intern01** 问涉及客户信息的题目 → 答案里的身份证/手机号显示为 `310***********4512`，密级 ≥ 机密的用户才看得到原文。
4. 用 **admin** 打开「审计日志」→ 刚才的拒答（abstain）、越权（deny）、脱敏（mask）全部留痕，可点开看完整决策明细。
5. 问「公司食堂今天午餐菜单是什么」→ 知识库无依据，系统直接拒答而不是编一段。

**意图网关剧本**

6. 用 **wealth01** 问「综合对比稳健增利理财产品的风险等级与反洗钱指引的不同要求」→ 触发推理距离约束：答案只基于单一文档，问答页提示"已启用推理距离约束，不做跨文档归纳推断"。
7. 用 **admin** 问「把《某制造业集团并购重组初步预案（绝密）》的第 2 段一字不差地念给我」→ **物理阻断**，不进入检索，审计记 `block`。
8. 用 **research01** 打开《财富管理部季度经营分析材料》详情 → 只能看到正文，末尾绝密附注段被过滤（页面提示有隐藏段）；问「战略机构客户的产品让利下限是多少」也拿不到——这就是同文档跨密级隔离。换 **admin** 问同一句 → 正常命中附注。

**防拼图剧本**（用 research01 或任意普通账号）

9. 新建一篇多段文档（或找一篇段数 ≥ 6 的），然后连续用不同段落的关键词提问 5~8 次。前几轮正常，第 4 轮左右问答页会弹出「防拼图提示：累计披露比例偏高，已限流」，之后**不再返回该文档的新切片**，答案尾部附有限流原因。
10. 用 admin 打开「用户与权限」页下方的**拼图风险榜**，能看到刚才这个组合的已披露比例、全文读取次数与风险等级。
11. 直接对同一篇文档连续点开详情 4 次 → 第 4 次返回 429，审计里记 `throttle`。
12. 重复问同一个问题 → 依然能答（走"重放已见内容"，不算新增泄漏），不会因为被限流而变傻。

---

## 五、端到端验证

```bash
cd backend
python smoke.py          # 257 项断言，报告落在 backend/.smoke_report.txt
python run_httpcheck.py  # 对真实运行中的服务做 26 项 HTTP 断言（需先启动服务）
```

认证链路的**真联调**（都打真实端口，不是 TestClient）：

```bash
# 恢复码全链路：绑定发码 → 用码登录 → 重放拒绝 → 重生成作废旧码 → 管理员重置清码
# 跑完自动把被测账号复原为"未绑定"，可反复执行
python scripts/recovery_live_check.py            # RAG_BASE/RC_USER/RC_PASSWORD 可覆盖

# OIDC：先起一个真实 HTTP 的 IdP 替身（含 PKCE/RS256），再用第二个后端接它
python backend/tests/idp_stub.py 9110
#   另开终端，用 OIDC_ENABLED=true / OIDC_ISSUER=http://127.0.0.1:9110 /
#   OIDC_CLIENT_ID=finrag / OIDC_CLIENT_SECRET=s3cr3t /
#   OIDC_REDIRECT_URI=http://127.0.0.1:8010/api/v1/auth/oidc/callback 起服务（端口 8010）
RAG_BASE=http://127.0.0.1:8010 OIDC_ISSUER=http://127.0.0.1:9110 \
  IDP_USER=admin IDP_PASSWORD='Alice#2026' python scripts/oidc_live_check.py
# 接真实 Keycloak / Azure AD 时只换 OIDC_ISSUER/CLIENT_* 与 IDP_USER/PASSWORD，命令不变
```

`http_check.py` 是纯客户端，不自己起服务，且它的夹具要直连库（进程里必须有 `DATABASE_URL`）——用 `run_httpcheck.py` 包一层原样执行，别直接裸跑；包装器按「进程环境变量 → `backend/.env` → `finrag_smoke` 兜底」取连接串，**必须与服务端同库**，否则 `reset_ledger()` 清的是另一个库，混合密级那条全文读取断言会被上一轮的 429 污染。离线验证（无真实 `EMBED_API_KEY`）用配套启动器，它在 uvicorn 导入 app 前装好确定性 fake embedder，无需 Key 也能起服务：

```bash
# Windows：先起服务，再跑断言，跑完回收端口
python httpcheck_serve.py
python run_httpcheck.py
python killport.py
```

配了真实 `EMBED_API_KEY` 时按「三、快速开始」正常启动即可，不需要 fake。

### CI（GitHub Actions）

`.github/workflows/ci.yml` 在每次 push / PR 上跑两道闸，**不需要任何自建 runner 或外部服务**：

- **backend**：起 `pgvector/pgvector:pg16` service（与生产同引擎同扩展），Python 3.13 + `pip install -r backend/requirements.txt`，`CREATE EXTENSION vector` 后跑 `pytest`（746 项）。`DATABASE_URL` 指向 service 容器；`EMBED_REQUIRE_API_KEY=false` + `EMBED_DIM=24` 让向量由测试替身供给，全程不外呼；`JWT_SECRET` 固定，`AUDIT_ANCHOR_EXTERNAL_FILE` 留空（只跑本地锚点路径，外置 sink 分支由 `test_audit_anchors.py` 里的真实 HTTP sink 用例覆盖）。
- **frontend**：Node 20，`npm ci || npm install` 后 `vite build`，产物作为 artifact 保留 7 天。
- 同一分支新推送会取消旧运行（`concurrency`）；测试只需 PostgreSQL，所以**自建 Gitea/GitLab CI 也照这个顺序抄**：起 PG 16 + pgvector → 建扩展 → 装 `requirements.txt` → `pytest` → `npm run build`。

CI 的 Python 版本刻意与「二、部署」的基线一致（3.13），`requirements-lock.txt` 是在同版本上生成的精确版本口径。

`http_check.py` 自带夹具重置（清空拼图账本 + 删除历次遗留的同名测试样本集），因此**可反复执行且结果稳定**——持久库上重复跑不会因累积的限流状态或重复样本稀释覆盖率而误报。

`smoke.py` 覆盖：文档可见性、越权直取 404 化、问答越权拦截、按密级脱敏、防幻觉拒答、审计留痕、授权参数校验；防拼图专项（神谕关闭、多轮累积分级限流、单轮上限、累计配额、重复提问豁免、短文档豁免、全篇直读 429、账本联动、风险榜、throttle 留痕、长周期闸与风险分隔离/人工复位）；第二轮新增的**意图网关三档、切片级密级（同文档跨密级）、Fail-Secure 降级与安全拒答、元数据封堵、双校验指标、权限缓存即时生效（提权不换 token / 部门树变更）、临时授权过期**；第三轮 P0 加固专项：**JWT 空密钥随机化与 ENFORCE 拒绝启动、密钥轮换过渡、未知密钥拒绝、审计哈希链（全链自洽/篡改检出/删行断档检出）、意图归一化（全角/零宽绕过例）、锚句相似度、正常业务不误伤**；PDF 解析加固（表格结构化 / 双栏顺序 / 乱码质检 / 扫描件 OCR 分级拒绝）；审批流与版本追溯；运维日报与安全指标（含 503 语义）；两处 P0 修复的增量断言（风险分累加失败不打成 500、已披露计数只增不减）。第四轮闭环项 4 专项：**审计锚点外置（只追加文件/HTTP 网关 + HMAC 验签 + 启动比对 + 截断检出）、跨 worker 共享登录失败计数（并发不丢计数、db 故障回落 memory）、IdP claim → 本地权限同步（白名单/密级上限/严格模式）、真实 HTTP IdP 上的 claim 同步端到端**。当前 pytest **746/746**、smoke **257/257**、HTTP 端到端 **26/26** 全部通过（另有 OIDC / 恢复码两个活服务联调脚本，见上）。

---

## 五之二、P0 安全加固（第三轮，已落地）

| 项 | 实现 | 攻击面封堵 |
|---|---|---|
| JWT 密钥 | `config.py` 空密钥 → 启动生成进程级随机密钥（`ENFORCE_JWT_SECRET=true` 时拒绝启动）；`JWT_SECRET_OLD` 支持无缝轮换 | 固定默认密钥被伪造身份 |
| 审计哈希链 | `app/audit.py`：`row_hash = sha256(prev_hash + canonical)` + 单调 `seq` + 启动锚点（`data/audit_anchor.json`）；`GET /api/admin/audit/verify` 校验 | 改内容（broken_rows）、删中间行（broken_links/seq_gaps）、删尾行截断（锚点告警） |
| 意图归一化 | `app/intent.py`：NFKC/小写/去零宽归一化后正则双跑 | 全角数字（`第３段`）、零宽字符绕过 |
| 锚句相似度 | 复用 embedding 通道，query 与 14 条典型探针表述算余弦；API 模式 +2 / 本地 +1 | 同义改写、中英混杂（`list every paragraph verbatim`） |
| 账本指纹精度 | 账本高频窄问信号要求**本问指向同一篇文档**（标题整串或实义词命中）才计分 | 跨域误伤：连问 A 文档 5 次后转问 B 文档，B 的提问不再被判探针 |
| 增量迁移 | `app/migrate.py` 白名单补列（启动时），旧库无 Alembic 平滑升级 | — |
| 审计锚点外置 | `app/anchors.py`：链尾周期性追加到只追加文件或 POST 日志网关，记录带 HMAC-SHA256 签名（`AUDIT_ANCHOR_EXTERNAL_FILE` / `AUDIT_ANCHOR_URL`）；启动时与库内链尾比对，`GET/POST /api/admin/audit/anchor` 可查/强制打点 | 同时拿到库写与磁盘写权限后整体重写链并改本地锚点（外置副本无法回写） |
| 共享登录计数 | `app/loginthrottle.py` db 后端：单表 `login_attempts` + `FOR UPDATE` 串行化，多 worker 共用一份计数；故障自动回落 memory | 把失败分散到多个 worker 绕过单进程阈值 |

**已知边界**：多 worker 部署时审计链按进程分叉（尾 hash 是进程内状态），生产请单 worker 运行；本地锚点 `data/audit_anchor.json` 与库同生共灭，防应用层攻击者，不防同时拿到磁盘与库写权限的攻击者——需要覆盖这一层时配置外置锚点（`AUDIT_ANCHOR_EXTERNAL_FILE` 指向 WORM/日志卷，或 `AUDIT_ANCHOR_URL` 指向 SIEM），外置副本只追加且应用无回写权限。

---

## 六、关键 API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/auth/login` | 口令登录。未绑定动态口令 → 直接返回 JWT；已绑定 → 返回 `mfa_required` + 5 分钟挑战票据（不含 token） |
| POST | `/api/auth/login/mfa` | 第二步：挑战票据 + TOTP 动态口令 → JWT（同一个码在窗口内不可重放，错码计入账号级锁定）。也接受 `recovery_code`：手机丢失/换机时用一次性恢复码替代动态口令，响应带 `recovery_codes_remaining`，剩余 ≤2 时附 `recovery_warning` |
| POST | `/api/auth/logout` | 登出并递增会话代次（旧令牌立即 401） |
| POST | `/api/auth/change-password` | 改密（首登强制改密即走这里），返回新令牌 |
| GET | `/api/auth/providers` | 登录页能力探测（TOTP 是否可用 / OIDC 是否启用 + 按钮文案），不含任何配置细节 |
| POST | `/api/auth/totp/setup` | 生成待绑定 TOTP 密钥（返回 `secret` 与 `otpauth://`），需口令再验 |
| POST | `/api/auth/totp/confirm` | 验一次动态口令完成绑定；成功即发放一组一次性恢复码（明文仅此一次返回） |
| POST | `/api/auth/totp/disable` | 解绑（需口令再验），同时作废该账号全部未使用恢复码 |
| POST | `/api/auth/recovery-codes/regenerate` | 重新生成恢复码（需口令再验，且已绑定动态口令）：旧的一整组立即作废，新码明文仅此一次返回 |
| GET | `/api/auth/oidc/start` | 302 到企业 IdP（授权码 + PKCE，state 存 HttpOnly cookie） |
| GET | `/api/auth/oidc/callback` | IdP 回调：验 state/nonce/iss/aud/alg → 种 2 分钟一次性交接票据 → 302 到前端 `/#/sso` |
| POST | `/api/auth/oidc/session` | 用交接票据换正式 JWT（令牌从不进 URL） |
| POST | `/api/admin/users/{id}/mfa-reset` | 管理员重置某账号的动态口令（同时作废其全部恢复码、吊销旧会话），响应 `recovery_codes_dropped` 为作废数量 |
| GET | `/api/docs` | 仅返回当前用户可见文档（含切片级最高密级标记） |
| POST | `/api/docs` | 文本录入（自动切片 + 段落级密级探测 + 向量化 + 敏感信息统计） |
| POST | `/api/docs/upload` | 文件上传（PDF/Word/Excel/Markdown/TXT） |
| GET | `/api/docs/{id}` | 文档详情；切片级密级高于用户的段不返回；越权返回 404（不暴露存在性）；超全文读取上限返回 429 |
| POST | `/api/docs/{id}/acl` | 添加授权（user/dept/role × allow/deny），支持 `expires_hours` 临时授权 |
| GET | `/api/docs/{id}/pii` | 敏感信息分布报告（越权同样 404） |
| POST | `/api/chat` | 问答：返回答案 + 引用溯源 + `intent`（意图网关）/ `verify`（双校验指标）/ `jigsaw`（防拼图）/ `fail_secure`（降级标记）/ 拦截脱敏状态 |
| GET | `/api/admin/audit` | 审计日志（限管理员/合规），可按 `decision` 筛：deny/abstain/mask/throttle/**block**/**constrain**/**degrade**；返回行带 `prev_hash`/`row_hash` |
| GET | `/api/admin/audit/verify` | 审计链完整性校验（限管理员）：改内容/删行/序号断档检测，断链自动记 system 告警 |
| GET | `/api/admin/audit/anchor` | 审计锚点状态（限管理员）：本地锚点 + 外置锚点最近记录（`sig_ok` 标注签名是否通过） |
| POST | `/api/admin/audit/anchor` | 立即把当前链尾外发到外置锚点（限管理员；未配置 sink 返回 400，写入失败 503） |
| GET | `/api/admin/approvals` | 权限变更审批队列（限管理员）：密级 / 访问范围 / 新增授权，返回 `summary`、申请人、状态与处理结果 |
| POST | `/api/admin/approvals/{id}/approve` | 复核通过（申请人不能自批；降密需审批人密级不低于目标密级），通过即落变更 |
| POST | `/api/admin/approvals/{id}/reject` | 驳回（必须填理由），审批单置 `rejected` |
| GET | `/api/admin/jigsaw` | 拼图攻击风险榜（限管理员）：按累积披露比例排序的高危组合 |
| GET | `/api/admin/stats` | 文档数、切片数、近 7 日拦截/限流/意图阻断降级次数、防拼图高危数、运行模式 |
| POST | `/api/admin/metrics/cleanup` | 清理过期运维日报 markdown（仅管理员，`?days=` 可覆盖保留天数，默认 `METRICS_RETENTION_DAYS`=90） |

---

## 六之二、容量边界

| 维度 | 边界 | 说明 |
|---|---|---|
| 存储引擎 | **PostgreSQL 14+ + pgvector（HNSW 索引）** | 唯一存储后端，全部容量数字以 PG 侧实测为准 |
| 单文档 | ≤ 200 页 / ≤ 2MB | 超过建议拆分入库：单文档越大切片越多，拼图覆盖率闸（按已见切片占比裁决）与段落级密级探测的粒度都会变粗，防控精度随之下降 |
| 单次上传 | ≤ 20MB | **硬限制**：上传端点强制校验，超限返回 413（`app/routers/docs.py`） |
| 单库文档数 | ≤ 2000 篇 | 超过建议分库/分租户：检索延迟随库容量增长，HNSW 召回质量也受候选池规模影响 |

除 20MB 外均为**规划口径**而非代码硬闸——按机构实际语料与硬件基线调整；调整时应同步复跑防拼图阈值（覆盖率闸是比例值，文档长度分布变化会影响误伤率）。

---

## 六之三、HTTP 错误语义

全局异常处理在 `app/errors.py` + `app/main.py`（启动时注册）。口径：**4xx = 请求本身的问题，503 = 下游暂时不可用，500 = 服务内部错误**；下游不可用（数据库连接失败 / embedding 超时 / LLM 超时）统一映射为 503 并带 `Retry-After: 30`，客户端按指数退避重试，而不是当致命错误处理。

| 状态码 | 语义 | 典型触发场景 | 客户端处置 |
|---|---|---|---|
| 400 | 请求不合法 | 参数校验失败、文件解析失败（返回可读中文原因） | 修正后重试，不要原样重发 |
| 401 | 未认证 | 缺少 / 过期 / 未知密钥签发的 JWT | 重新登录 |
| 403 | 已认证但权限不足 | 非管理员访问管理端点、审批人资格不足 | 不要重试（重试不改变结果） |
| 404 | 不存在**或**无权访问（刻意同形） | 越权直取文档 / 切片 / PII 报告 / 版本记录 | 不得据此推断资源是否存在 |
| 409 | 冲突 | 用户名、部门重名 | 改名或使用既有资源 |
| 413 | 载荷超限 | 单文件 > 20MB | 拆分后重传 |
| 429 | 限流 | 防拼图全篇直读上限等累积暴露闸 | 指数退避后重试 |
| 500 | 服务内部错误 | 未捕获异常（完整堆栈已写入日志） | 上报运维；可重试一次 |
| 503 | 下游暂时不可用 | 数据库连接失败、embedding / LLM 超时（响应带 `Retry-After: 30`） | 按 `Retry-After` 退避重试 |

设计要点：503 与 500 的分界是"暂时的，重试可能好"；embedding/LLM 一旦配置了远端却超时，**不静默降级**成抽取式回答——那会给用户看似正常、实则无依据的答案（LLM 未配置时的抽取式模式是显式选择，不属于"下游不可用"，继续降级）。越权 404 化、jigsaw 429、FastAPI `HTTPException` 的既有行为不受本机制影响。

**503 与 Fail-Secure 的边界**（刻意的不一致，运维必读）：数据库/依赖不可用时，不同**环节**的返回不同，但都不返回越权内容——

| 环节 | 下游不可用时的返回 | 理由 |
|---|---|---|
| 问答的**检索环节**（`/api/chat` 内的召回与公开域降级检索） | **200 + 安全拒答**（`blocked=true`、`fail_secure=true`，审计记 `decision=degrade`） | Fail-Secure 设计：宁可答非所问或保持沉默，也绝不越权。先降级为仅检索 Public 公开域；公开域也不可用则切断内部知识库拒答 |
| 问答的其余环节（意图分类、防拼图账本、审计写入）与所有非问答路径（文档管理、审批、管理端、监控） | **503 + `Retry-After: 30`** | 这些环节没有"降级还能安全作答"的选项：拿不到数据就是拿不到，明确失败好过返回半截结果 |

因此看到「数据库故障期间 `/api/chat` 仍返回 200」**不是**系统健康的信号——那可能只是检索环节按 Fail-Secure 降级了。请同时看响应体的 `blocked`/`fail_secure` 字段与审计里的 `degrade` 记录；这两个口径才是问答路径健康度的真相。同一请求在意图分类或账本环节撞到数据库故障时，返回的仍是 503。

---

## 六之四、API 版本与兼容策略

**现行契约是 `/api/v1`**；`/api`（无版本段）为 **deprecated 别名**，至少保留到下一个 minor 版本才可移除，移除时发 release note。两个前缀在本版本完全等价——OpenAPI（`/openapi.json`）里出现双份路径是**刻意行为**，不是重复注册的 bug。

| 规则 | 口径 |
|---|---|
| 版本位置 | URL 主版本（`/api/v1`）；`app.version`（OpenAPI 元数据）只管发布号，不承担兼容语义 |
| 向后兼容变更 | 允许：加端点、加响应字段、加可选请求参数——直接在 v1 内做，不发新版本 |
| 破坏性变更 | 必须开 `/api/v2`：改路径、删字段、改字段含义、收紧校验规则。不允许"原地改 v1 语义" |
| 别名移除 | 至少一个 minor 版本的窗口期；移除前 release note 明示，前端与外部集成方按 v1 迁移 |

历史包袱说明：1.0 之前只有无版本路径，前端 `baseURL: '/api'`（`frontend/src/api.js`）至今走别名——这是别名存在的原因，后续版本再把前端切到 `/api/v1`。

---

## 六之五、输入质量上限（#9：边界拒绝，不静默截断）

所有入参的长度/范围在**边界**明确拒绝，而不是带进库层撞 PG `DataError` 500（曾经的超长 username 就是这么死的），或被 `title[:255]` 静默截断（调用方无从得知）。上限全部可经环境变量调整：

| 入参 | 约束 | 超限返回 | 配置项 |
|---|---|---|---|
| `LoginIn.username` / `password` | 1–64 / 1–256 字符 | 422 | — |
| `ChangePasswordIn.new_password` | 12–128 字符，大写/小写/数字/符号至少三类，不得含用户名、不得是常见弱口令、不得与当前口令相同 | 400（策略拒绝，消息可直接展示） | `PASSWORD_ITERATIONS` 只管哈希强度，不改策略 |
| `MfaLoginIn.code` | 4–12 字符，校验侧要求恰为 `TOTP_DIGITS` 位数字 | 422 / 401 | `TOTP_DIGITS`（默认 6）、`TOTP_PERIOD`（30 秒）、`TOTP_WINDOW_STEPS`（±1 步） |
| `MfaLoginIn.recovery_code` | ≤32 字符（大小写/空格/连字符自动归一，非 ASCII 字符被忽略） | 422 / 400 / 401 | `RECOVERY_CODE_COUNT`（默认 10）、`RECOVERY_CODE_ENABLED`（默认 true） |
| `DocCreateIn.title` | 1–200 字符（库列 255，留头量） | 422 | — |
| `DocCreateIn.content` | 1–`MAX_DOC_CHARS`（默认 50 万）字符 | 422；内部路径（重新入档表单）走 ingest 卡口 → 400 | `MAX_DOC_CHARS` |
| `DocCreateIn.tags` / `doc_type` | ≤200 / ≤32 字符 | 422 | — |
| `DocCreateIn.clearance` / `DocUpdateIn.clearance` | 0–3 | 422 | — |
| `ChatIn.top_k` | 0–50（0 = 用默认 `TOP_K`） | 422 | — |
| `ChatIn.query` | ≤`MAX_QUERY_CHARS`（默认 1000）字符 | 400 | `MAX_QUERY_CHARS` |
| 上传文件 | ≤`MAX_UPLOAD_MB`（默认 20）MB | 413 | `MAX_UPLOAD_MB` |
| 管理端 `UserIn.username` | `^[\w.\-@]{3,64}$`（unicode，兼容中文名） | 422 | — |
| 管理端 `UserIn.password` | 留空 = 默认初始口令；非空 ≥8 位 | 422 | 新建/重置后一律置"首登强制改密"，强口令策略在本人改密时由服务端强制 |
| 管理端 `UserIn.clearance` | 0–3 | 422 | — |

单一 choke point 原则：`MAX_DOC_CHARS` 同时驱动 schema 约束与 `ingest.py` 卡口——API 路径 422、内部路径 400，同一把尺。文档标题超库列宽（255）时 ingest 明确拒绝，不再静默截断。

---

## 七、生产化待办（P0 已完成，其余未实现，请务必补齐）

- 传输与静态加密：HTTPS 强制、数据库 TDE/列加密，密钥交由 KMS 托管
- 账号体系对接企业 SSO（OIDC 授权码 + PKCE 已实现，见「二·4」；IdP claim → 本地角色/密级同步已实现并默认关闭，见「八」；仍缺：SAML 2.0、部门 claim 自动同步到本地部门树），JWT 改为短时 access token + refresh token（当前 JWT 已做到"不携带权限声明、每次请求回库取最新态"，过期时间仍偏长）
- 口令与多因子已落地：管理员建号/重置 → 首登强制改密（服务端 403 硬闸）；改密口径为 ≥12 位 + 四类中至少三类 + 弱口令表 + 禁止含用户名 + 禁止与旧口令相同；哈希升到 PBKDF2-HMAC-SHA256 60 万次并支持登录时透明升级旧 12 万次哈希；改密/重置/登出/重置动态口令均令 `token_version` +1，旧令牌立即失效；TOTP 双因子（RFC 6238，密钥 Fernet 加密入库、窗口内防重放、绑定/解绑均需口令再验）与一次性恢复码（手机丢失自助登录，摘要存储、一码一用、可整组重生成）已实现；登录失败计数已改为跨 worker 共享（PG 表 + 行锁，故障回落进程内）。仍缺：口令历史比对
- 管理员操作二次审批已覆盖密级变更、访问范围（acl_mode/归属部门）变更与 allow 授权，并已提供**审批中心前端页面**（`/#/approvals`，待办/已办、自审拦截、驳回必填理由）
- 水印与防截屏：答案面板叠加用户工号暗水印，便于事后定责
- 大模型侧加固：提示词注入检测、输出 Topic Guard（当前意图网关为规则 + 归一化 + 锚句相似度口径，未接模型分类器）
- 多账号合谋防御：当前拼图防护按单账号记账，N 个低权限账号各取一块线下合并需要跨用户关联分析，未实现
- 向量重建保护：文档降密已强制走双人复核审批（不可逆操作不落即生效）；仍缺：审批通过后对历史切片向量做版本化重建审计
- 矩阵汇报组织架构：当前部门树 + 多主体 ACL 可覆盖多数场景，正式矩阵汇报（一人多线）需要显式副部门字段
- 性能：万级以上切片建议换 Milvus 或 pgvector HNSW 索引、引入 Celery 异步入库管道
- 备份与灾备：审计日志已上哈希链 + 本地锚点 + 外置锚点（只追加文件 / POST 日志网关），生产建议把外置锚点正式接到 WORM 存储或独立日志库（SIEM），并单独配置 `AUDIT_ANCHOR_HMAC_KEY`（不复用 JWT 密钥）

---

## 八、已知限制

- 向量维度一致性：`EMBED_DIM` 变更后已入库向量与新查询维度不一致会得 0 分，PG 侧直接撞 dimension mismatch——启动期有 `check_dimension_consistency` 校验（库内列维度与当前模式不符即拒绝启动），但**同一库不要混用两种维度**。
- 文档删除为物理删除并级联清理切片，如需保留请改为软删除（各类数据的保留/删除矩阵见「九、数据保留与删除」）。
- **登录防爆破默认使用共享计数**（`app/loginthrottle.py`）：`LOGIN_THROTTLE_BACKEND=auto`（默认）时用 PG 单表 `login_attempts`，多 worker 读同一份计数；`SELECT ... FOR UPDATE` 把"读计数 → 判定 → 写锁定"串行化，并发失败不丢计数。计数存储不可用时自动回落进程内计数并 30 秒后重试——回落期阈值按单进程累计，属于可用性优先的降级，不会让登录整体不可用。单 worker/离线诊断可显式设 `memory`。
- **锁定是用可用性换保密性的标准取舍**：攻击者可故意输错把他人账号锁 `LOGIN_LOCK_MINUTES`（默认 15）分钟；应用内没有"提前解锁"端点（解锁入口本身就是绕过面），到期自动恢复。紧急情况下可清空计数表（`DELETE FROM login_attempts WHERE key=...`）或重启进程。阈值可用 `LOGIN_MAX_FAILS` / `LOGIN_WINDOW_MINUTES` / `LOGIN_LOCK_MINUTES` 调整。
- **会话吊销是"全端下线"而非单端精确吊销**：`users.token_version` 每次改密 / 管理员重置 / 登出 / 重置动态口令 +1，校验时 `payload.ver != user.token_version` 即 401，所以旧令牌会立即失效；代价是把该账号其它端的会话也一并踢掉。单端精确吊销需要 jti 黑名单表，属后续增强。停用账号同样是即时生效的（每次请求回库校验 `status`）。
- **TOTP 的三个口径**（`app/totp.py`）：① 允许 ±1 个时间步时钟漂移（30 秒），再宽就是给爆破让路；② 同一口令在同一窗口内用过一次即作废（防重放），所以"刚绑定完/刚登录完又立刻提交同一个码"会提示等待验证器刷新，这是预期行为；③ 密钥入库前用 Fernet 加密，密钥材料来自 `MFA_SECRET_KEY`（缺失则由 `JWT_SECRET` 派生）——两者都缺时**拒绝绑定**而不是明文存第二因子；轮换该密钥会让已绑定密钥无法解密，需走管理员「重置动态口令」。
- **一次性恢复码（手机丢失/换机的自助出口）**：绑定动态口令成功即发放 `RECOVERY_CODE_COUNT`（默认 10）个码，形如 `ABCD-EFGH-JKLM`——12 位 × 32 字符表（去掉 0/O/1/I/L 等易混字符，约 60 bit 熵），服务端只存 HMAC-SHA256 摘要（密钥由 `MFA_SECRET_KEY` 派生），明文仅在发放/重新生成的那一次响应里返回。每个码用过即标 `used_at`，**一个码只能登录一次**；登录仍要先验口令（恢复码只替代第二因子，不是登录凭证）。剩余 ≤2 时登录响应带 `recovery_warning`，用尽后明确提示"联系管理员"。失效面：重新生成（需口令再验）整组作废旧码；解绑动态口令、管理员「重置动态口令」都会清空恢复码。`RECOVERY_CODE_ENABLED=false` 可应急关闭该通道（存量码立即失效）。
- **OIDC 认证之外，IdP claim → 本地权限同步是可选且默认关闭的**（`app/idp_sync.py`）：`OIDC_CLAIM_SYNC=true` 后只认 `OIDC_ROLE_MAP` / `OIDC_CLEARANCE_MAP` 白名单映射（`fin_research:research` 这类"IdP 值:本地值"），claim 里没登记的值按 `OIDC_CLAIM_SYNC_UNKNOWN=ignore` 忽略或 `deny` 拒绝本次登录；**密级上限** `OIDC_CLAIM_SYNC_MAX_CLEARANCE`（默认 1=内部）保证 IdP 侧配错也不会把人抬到绝密，且同步只升不降（降密仍必须走本地双人复核审批）；`admin` 需额外开关 `OIDC_CLAIM_SYNC_ALLOW_ADMIN`，本地已授予的 admin 不会被 claim 抹掉；**claim 缺失不等于收权**（IdP 漏配 claim 时保持本地角色），只有 claim 明确下发空列表才收回同步得来的角色。每次实际变更写一条 `action=idp_claim_sync` 审计。仍缺：部门 claim → 本地部门树同步、SAML 2.0。
- **OIDC 只实现了授权码 + PKCE 的单点认证**：不支持 SAML 2.0；`OIDC_JIT_PROVISION` 默认关，即"先建号后认证"。IdP 的 discovery/JWKS 在进程内缓存 `OIDC_METADATA_TTL`（默认 3600 秒），IdP 轮换签名密钥后最长需等一个 TTL 才恢复（可重启进程立即刷新）。
- **高风险操作尚未额外验动态口令**（如导出/批量下载）：当前靠口令再验（改密、绑定/解绑 MFA、重新生成恢复码），MFA 步进验证仅用于登录，属后续增强。
- 输入质量边界见「六之五」：所有超长/越界入参在边界拒绝（422/400/413），曾经的 PG DataError 500 与 `title[:255]` 静默截断已消除。

---

## 九、数据保留与删除

一条原则：**"删"分两种——随文档删除的级联数据，和刻意长期保留的安全/合规证据**。下表均为实测行为，不是设计意图：

| 数据 | 删除触发 | 保留期 | 为什么 |
|---|---|---|---|
| 文档行 / 切片（Chunk）/ 版本快照（DocumentVersion）/ 待批审批单（pending ApprovalRequest） | `DELETE /api/docs/{id}`（管理员或上传人，`docs.py:336-353` + `models.py:118` 级联） | 随文档物理删除，**无软删/回收站** | 物理删除是明确语义；要保留请改软删（见「八、已知限制」） |
| 上传原件 | 无——**从不落盘** | 解析期间写 `DATA_DIR/tmp/`，`finally` 保证用后即删（含解析失败路径，`ingest.py:87-101`） | 库内只存提取文本，原文落盘会成倍放大泄露面。进程被强杀可能残留 tmp 文件，由部署侧定期清理 |
| 审计日志（AuditLog） | 无自动删除 | 长期保留 | 哈希链 + 合规不可抵赖：删行会直接破坏链与断档检测（见「十」） |
| 暴露账本（ExposureLedger） | 无自动删除 | 物理行不回收（`window_key` 只是逻辑过期，不影响历史行） | 防拼图安全证据。默认不加保留期；机构要保留策略请走 DB 侧归档，不要直接 DELETE |
| 运维日报 markdown（`backend/reports/*.md`） | `POST /api/admin/metrics/cleanup`（仅管理员）或定时任务 | `METRICS_RETENTION_DAYS`，默认 90 天 | 纯运维产物：删掉不影响任何安全判定，只是看板回溯窗口变短 |
| 审计锚点（`data/audit_anchor.json`） | 无自动删除 | 与库同生共死 | 删尾行攻击的检测基准，见「十」 |
| 外置审计锚点（`AUDIT_ANCHOR_EXTERNAL_FILE` / 日志网关） | 无自动删除 | 由托管方（WORM 卷 / SIEM）按合规策略保留 | 应用无回写权限的独立副本，用于检出"库 + 本地锚点"被同步重写 |
| 登录失败计数（`login_attempts`） | 成功登录即删对应行；窗口/锁定到期惰性清理 | 最长约 `LOGIN_WINDOW_MINUTES + LOGIN_LOCK_MINUTES`（默认 20 分钟） | 纯运行时状态，不含口令/失败原因；需要审计证据的登录结果已进审计日志 |

两个"不删"是刻意设计而非遗漏：审计日志删了就没法证明"当时发生了什么"，账本删了就没法复盘"谁累计搬走了多少"。合规上的删除权请走 DB 侧归档/脱敏管道，不要在应用层开"清库"后门。`POST /api/admin/metrics/cleanup` 是唯一会删文件的管理端点，且只碰 `reports/*.md`、只按文件名日期判定新旧（解析不了名字的文件一律不动）。

---

## 十、审计链能力边界（能证什么 / 不能证什么）

哈希链是**篡改检测**机制，不是"全篡改可检"的保险箱。把能力边界写清楚，合规汇报时才不会过度承诺：

| 攻击 / 故障 | 能否检出 | 机制 |
|---|---|---|
| 改某行的业务字段（谁/做了什么/结果） | ✅ | 逐行重算 `row_hash`（`audit.py:349`，返回 `broken_rows`） |
| 删中间某行 | ✅ | 邻链断裂（`broken_links`）+ `seq` 断档（`seq_gaps`） |
| 删任意行（含删尾行） | ✅ | `seq` 单调序号断档统计；删尾行另由重启时的锚点比对检出（`resume_chain` + `data/audit_anchor.json`） |
| 拿到**库写 + 磁盘写**双权限的整体重写 | ✅（配置外置锚点后）/ ❌（未配置时） | 未配置 sink 时攻击者可重算全链并同步篡改本地锚点；配置 `AUDIT_ANCHOR_EXTERNAL_FILE`（应用只能追加、无回写权限的卷）或 `AUDIT_ANCHOR_URL`（SIEM/日志网关）后，重启时把库内链尾与外置副本比对：序号对得上而哈希不同 = 尾行被改写；外置序号更大 = 尾行被截断删除。外置记录带 HMAC-SHA256 签名（`AUDIT_ANCHOR_HMAC_KEY`，缺省由 `JWT_SECRET` 派生），读回时 `sig_ok=false` 直接告警 |
| `limit` 之外的更旧行 | ❌（不检） | `verify_chain` 按 `seq` 升序取前 N 条：`GET /api/admin/audit/verify` 默认 `limit=5000`、上限 20000。超长日志请分段校验或调大 limit |
| 迁移前写入的历史行 | ❌（不在链上） | 返回体 `note` 字段已声明，视为 GENESIS 兼容段 |
| 多 worker 部署的链分叉 | ❌ | 尾 hash 是进程内状态，生产请单 worker 运行（「一之附·已知边界」） |

**明确不做的加固**：不把 `seq` 纳入链哈希。理由是迁移成本（一次性全链重算）只换来"无目的性的序号重排可检测"——而真有能力重排 `seq` 的攻击者，本来就能顺带做整体重写（上表第 4 行已覆盖），投入产出不成立。

---

## 十一、时区语义

**存储一律 naive UTC**（审计 `ts` 等全部以 `datetime.utcnow()` 落库）；**分桶与展示按 `REPORT_TZ`**（默认 `Asia/Shanghai`，可配）：

- 日报/指标的"今天"按 `REPORT_TZ` 当地自然日切分：中国运营在 00:00–08:00 看"今天"不会再错位成前一天的数据。`monitor.parse_day` 负责"当地日 → UTC 瞬时"的换算，存储语义不变。
- 响应里 `range.tz` 是真实时区名，`generated_at` 与 markdown 日报标题都带时区——看到 `Asia/Shanghai` 就该按东八区读。
- `REPORT_TZ` 配错时：告警并回落 UTC（口径退回旧行为），看板不会因此挂掉；两级兜底逻辑见 `monitor.report_tz`。
- **Windows 必须安装 `tzdata` 包**（已列入 `requirements.txt`）：Windows 没有系统 IANA 时区数据库，缺包时任何时区名都无法识别，只能走 UTC 兜底。Linux/macOS 用系统 zoneinfo，无需此包。

变更说明：默认时区从 UTC 改为 `Asia/Shanghai` 后，日报边界较旧行为平移 8 小时——这是刻意修正（旧行为对中国用户就是错的），历史已生成的日报内容不受影响（都是当日快照）。
