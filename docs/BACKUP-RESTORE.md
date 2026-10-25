# 升级、备份、恢复与留存 runbook（P0-6）

> 目标：把"上线后出事怎么办"从口头约定变成可执行、可演练、可复核的步骤。
> 适用范围：单实例 / 主备两种部署形态（多活不在本版本范围内，见 §8 遗留项）。

## 1. 指标口径

| 指标 | 目标值 | 靠什么达成 |
| --- | --- | --- |
| RPO（可容忍数据丢失窗口） | ≤ 24 小时 | 每日逻辑备份（`scripts/pg_backup.py backup`）+ 审计外置副本（近实时） |
| RTO（恢复耗时目标） | ≤ 2 小时 | 备份文件已在本地可读 + 恢复命令一条化 + 季度演练 |
| 审计在线留存 | ≥ 6 个月 | 不删除在线审计行（见 §6）；容量按行数预估 |
| 审计离线留存 | ≥ 6 个月（建议 12 个月） | 归档包（`scripts/audit_archive.py`）+ 外置 sink 副本 |

结论口径：**没有做过一次恢复演练的备份，不算备份**。§5 的演练必须留记录。

## 2. 备份

前置：目标机需有 `pg_dump` / `pg_restore`（PostgreSQL 客户端工具），
连接串走 `DATABASE_URL`（与 `app.config` 同口径，可来自密钥托管）。

> Windows 便携版常见坑：`<PostgreSQL>/bin` 没进 `PATH` 时脚本找不到客户端工具。
> 设置 `PG_BIN=D:\pgsql\pg16\bin` 即可，脚本会先查 `PATH`、再查 `PG_BIN`。
> 注意 `pg_dump` 大版本必须 ≥ 服务端版本（16 的客户端能 dump 16 的库）。

```bash
# 每日（建议 cron / 计划任务，凌晨低峰）
python scripts/pg_backup.py backup --out /backup/finrag --keep-days 30
```

产物三件套：

- `finrag-<UTC 时间戳>.dump`：`pg_dump --format=custom` 全库逻辑备份；
- `finrag-<UTC 时间戳>.dump.manifest.json`：sha256、字节数、
  **审计链尾 `(seq, row_hash)`**、`alembic_version`、各表行数；
- 轮转：超过 `--keep-days` 的 `finrag-*.dump` 与其清单自动清理。

异地副本：把 `--out` 指到跨主机挂载 / 对象存储同步目录即可（脚本不假设
存储介质）。**至少保留一份应用进程不可回写的副本**（与审计外置锚点同一
思路：本地可写的备份挡不住"本机被控"）。

## 3. 升级发布（结构变更）

```bash
# 0) 先备份（不可跳过；这是唯一可回退的凭据）
python scripts/pg_backup.py backup --out /backup/finrag

# 1) 结构迁移（幂等；已是最新版本时是空操作）
cd backend && alembic upgrade head && alembic current

# 2) 前端构建产物（若本次含前端改动）
cd ../frontend && npm run build

# 3) 启动服务（启动期仍会跑 create_all + ensure_schema 作为兜底）
cd ../backend && python run.py --port 8000
```

发布后验收（顺序固定，任一失败即回退）：

1. `GET /api/health` → `ok=true` 且 `jwt_secret=configured`；
2. `GET /api/admin/audit/verify`（admin 令牌）→ `ok=true`，
   `broken_rows=broken_links=seq_gaps=0`；
3. `GET /api/admin/audit/anchor` → `external.enabled=true`（若已配置 sink），
   `records` 在增长、`bad_signature=0`；
4. 冒烟：`python smoke.py`（端到端）、`python run_httpcheck.py`（HTTP 契约）。

约定：**结构变更一律新增 alembic revision**，禁止改 `0001_baseline`；
新 revision 的 `upgrade()` 必须幂等（老库可能已被 `ensure_schema` 改过）。

## 4. 回滚

分两种，不要混：

| 情形 | 做法 | 说明 |
| --- | --- | --- |
| 只有代码回退（结构未变 / 新代码向后兼容） | 回退代码版本，重启 | 推荐路径；DB 保持新版本结构 |
| 结构必须回退 | **不要** `alembic downgrade` 到 baseline | `0001_baseline.downgrade()` 会删表，审计证据一并消失 |
| 结构必须回退（真实需要） | 用升级前备份恢复到**新实例** → 校验 → 切流量 | 旧实例保留只读用于取证，确认后再下线 |

为什么默认不 downgrade：删表/删列的"回滚"会连同审计日志、审批记录一起
销毁，合规上等价于销毁证据。`0001_baseline` 因此显式 `raise`。

## 5. 恢复演练（每季度一次，留记录）

### 5.0 恢复目标库的前置条件（必须先做，否则恢复必失败）

`chunks.embedding` 是 pgvector 类型，目标库必须先装扩展；而 pgvector **没有
标记 `trusted`**，属主是创建它的超级用户（通常是 `postgres`），应用账号既不能
`CREATE` 也不能 `DROP`。因此：

```sql
-- 以超级用户在目标库执行一次（演练库/新实例都一样）
CREATE EXTENSION IF NOT EXISTS vector;
```

脚本的处理方式：备份照常包含扩展条目（`pg_dump` 没有 `--exclude-extension`，
只有正向的 `--extension`），**恢复侧按 TOC 过滤掉 `EXTENSION` / `COMMENT` 条目**
（输出里会打印 `toc_filtered_out`），避免 `--clean` 执行
`DROP EXTENSION vector` → `must be owner of extension` → `--single-transaction`
整次回滚。`restore` 还会先查 `pg_extension`，缺扩展时直接给出上面的 SQL 并中止。

> 这个坑的真实症状极具误导性：退出码非 0、恢复后行数全 0，看起来像"备份坏了"。
> 实际是权限问题，备份是好的。

### 5.1 步骤

```bash
# 1) 校验备份完整性（哈希 + 清单 + 目录可解析）
python scripts/pg_backup.py verify --file /backup/finrag/finrag-XXXX.dump

# 2) 准备演练库（扩展见 5.0）+ 恢复（--yes 才允许破坏性 --clean）
createdb -h 127.0.0.1 -U finrag finrag_drill
psql -h 127.0.0.1 -U postgres -d finrag_drill -c "CREATE EXTENSION IF NOT EXISTS vector;"
python scripts/pg_backup.py restore \
    --file /backup/finrag/finrag-XXXX.dump \
    --target postgresql://finrag:***@127.0.0.1:5432/finrag_drill --yes
```

`restore` 会自动比对三项，全部一致才返回 0：

- 恢复后审计链尾 `seq` 与清单一致；
- 恢复后审计链尾 `row_hash` 与清单一致（证明备份里的链完整）；
- `alembic_version` 与清单一致（证明结构与代码版本匹配）。

3) 用演练库起一个临时服务实例（改 `DATABASE_URL` 指向 `finrag_drill`），
   跑 `smoke.py`；4) 记录：备份文件、耗时、三项校验结果、经办人。
   演练记录归档到变更管理台账（季度审计会查）。

> 演练实例要用**独立的** `AUDIT_ANCHOR_EXTERNAL_FILE`（或留空关闭）：外置 sink
> 与部署一一对应，若沿用生产 sink，启动比对会看到"外置 seq=440 > 演练库 seq"，
> `resume_chain` 会如实写一条"疑似尾行被截断"的告警——这是正确行为，不是 bug，
> 但会让演练的审计报告看起来像出事。同理，pytest 侧已在 `conftest.py` 强制清空
> 这两个变量，避免开发者本地 `.env` 打开 sink 后把链相关用例的序号带偏。

### 5.2 已完成的演练记录

**第一次（2026-10-24，本机 16.15）**

| 项 | 结果 |
| --- | --- |
| 备份 | 131,898 字节；清单含审计链尾 `seq=440 / row_hash=da947f…`、`alembic_version=0001_baseline`、各表行数（users 6 / documents 7 / chunks 20 / audit_logs 439 / auth_sessions 16 / exposure_ledger 20） |
| 校验 | `sha256_ok=true`，`table_data_entries=12` |
| 恢复 | `finrag_drill`：`exit_code=0`，`audit_tail_seq_match / audit_tail_hash_match / alembic_version_match` 全 `true`，行数与清单逐表一致 |
| 结构复核 | 恢复后 `alembic_version=0001_baseline`，`trg_audit_append_only` / `trg_audit_no_truncate` 两个触发器均在，`vector 0.8.6` 在位 |
| 归档 | 6 个月下限生效（`--months 3` 被拒）；链校验不过的库被拒（`--months 6` 返回 2）；干净链库导出 171 行，`sha256` 与清单一致、`--redact-query` 后不含 `query/detail`、包内 `prev_hash → row_hash` 自洽 |

**第二次（2026-10-25，上线前复查；脚本改动后重跑）**

| 项 | 结果 |
| --- | --- |
| 备份 | `203,706` 字节；`seq=819`、`alembic_version=0001_baseline`、行数 users 6 / documents 7 / chunks 20 / audit_logs 819 / approval_requests 0 / auth_sessions 124 / exposure_ledger 19 |
| 校验 | `sha256_ok=true`，清单行数与 dump 内数据条目一致 |
| 恢复 | 同一 `finrag_drill` 库：`exit_code=0`，三项 match 全 `true`，逐表行数与清单一致；`toc_filtered_out` = 2 条（`EXTENSION vector` 与其 `COMMENT`），即"扩展由 DBA 预建、不随 dump 覆盖"的预期行为 |
| 说明 | 本次重跑用于验证 `pg_backup.py` 的两处改动：连接串自动补 `+psycopg`（runbook 给的 libpq 形态也能用）、子进程输出统一 UTF-8 解码（Windows locale 下不再因 `UnicodeDecodeError` 掩盖真实报错） |

> 演练中发现的两个真实缺陷已修：① `pg_dump` 的扩展条目导致恢复整体回滚（见 5.0）；
> ② 演示库存在迁移前写入的历史行造成的 1 处序号断档（`seq=57`），
> `verify_chain` 如实报 `seq_gaps=1` —— 脚本据此拒绝归档，这正是设计意图
> （先排查再归档），不是脚本缺陷。

## 6. 审计留存与归档

- **在线不删**：审计表是"哈希链 + 单调序号"的证据链，删掉最旧的一段会永久
  留下 `seq_gaps`（`verify_chain` 从此常报警）。在线留存靠容量规划：审计行
  是结构化元数据（`query`/`detail` 有长度上限），量级远小于文档正文。
- **归档只导不删**：

  ```bash
  # 归档 6 个月前的审计（链校验不通过时拒绝执行；--force 仅用于取证）
  python scripts/audit_archive.py --months 6 --out /archive/finrag
  ```

  产物：`*.ndjson.gz`（逐行审计）+ `*.manifest.json`（条数、首尾序号、链尾、
  导出时点锚点、sha256）。归档包与同时点锚点一起构成可独立取证的证据。
  归档目录同样需要"应用不可回写"的存储与访问审计。
- **在线外送副本**（P0-3）：`AUDIT_ANCHOR_EXTERNAL_FILE` / `AUDIT_ANCHOR_URL`
  同时承载 `kind=audit_rows`（每批行副本）与 `kind=audit_anchor`（周期链尾），
  供实时对账与离线重建时间线。
- **需要下沉旧数据时**（超出表容量规划）：走"按 `ts` 月分区 + detach 分区"
  方案，detach 后整分区导出归档，链与序号连续；不要在在线表上 DELETE
  （触发器会直接拒绝，见下）。

## 7. 密钥与破窗

- **JWT 轮换**：先配 `JWT_SECRET_OLD=<旧值>` + `JWT_SECRET=<新值>` → 重启
  （旧令牌仍可验证）→ 观察一个 `JWT_EXPIRE_HOURS` 周期 → 移除 `JWT_SECRET_OLD`。
- **密钥托管**：`SECRETS_PROVIDER=file|http` 一经启用**不再回落 .env**；
  `REQUIRE_SECRETS_PROVIDER=true` 时缺密钥即拒绝启动。轮换后用
  `/api/health` 的 `jwt_secret=configured` 与启动日志确认来源。
- **MFA_SECRET_KEY 轮换**：TOTP 密钥是 Fernet 加密存储，换 key 会导致旧
  绑定无法解密（用户需重新绑定 TOTP）。先公告，再轮换。
- **审计只追加破窗**（演练/取证需要改行时）：只能在同一事务内开：

  ```sql
  SET LOCAL finrag.audit_append_only = 'off';
  -- 仅限演练库；生产库改审计行必须走变更审批，并同步说明外置副本对账结果
  ```

  应用代码永不下发这个开关（`migrate.py` 只负责安装触发器）。
- **审批紧急旁路**：`APPROVAL_EMERGENCY_BYPASS=true` 会免审批执行权限放宽，
  属高危开关；开启/关闭都必须留审计说明，事故后立即关闭。

## 8. 遗留与边界（诚实说明）

- 尚未做：多活/跨机房切换、PITR（WAL 归档 + `recovery_target_time`）、
  SCA/渗透测试、SAML 2.0、部门 claim → 部门树同步、口令历史与定期改密。
- PITR 若要做：开 `archive_mode=on` + `archive_command`/`archive_library`
  到独立存储，并把 RPO 目标从 24 小时改为分钟级；脚本与 runbook 需同步更新。
- 本 runbook 的自动化只覆盖"备份/校验/恢复"与"归档导出"，**不覆盖**容量
  预估、存储 HA、密钥托管服务（Vault/KMS）自身的高可用——这些属基础设施边界。
