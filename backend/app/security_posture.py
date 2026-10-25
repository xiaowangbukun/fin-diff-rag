# SPDX-License-Identifier: AGPL-3.0-only
"""启动安全姿态自检（production readiness self-check）。

为什么需要它：本项目的安全能力几乎全是环境变量开关，而默认值为了演示/联调
可用往往偏宽松（指标不跑、MFA 不强制、Bearer 令牌、无 Host 白名单……）。
代码评审看到的是"有一堆防线"，线上实际生效的可能是"一条都没开"——这是最
典型的"审过代码就以为安全"事故。

这里把**当前进程实际生效的姿态**翻译成人能读的清单：

  OK    已符合生产口径
  WARN  需按部署形态确认（内网纯 HTTP、单机演示都可能合理）
  FAIL  明确危险的取值（等于关掉某条防线）

`STRICT_SECURITY_POSTURE=true` 时任何 WARN/FAIL 都拒绝启动，把上线检查从
"记得看一眼日志"变成"没配好就起不来"。默认关闭：演示与自动化测试仍照常启动。

设计约束：
  · 只读配置，不建连、不改状态——所以能在 `init_db()` 之前跑（配置类问题
    不该先留下半个库）；
  · 每条 finding 自带 remediation（改哪个环境变量、改成什么），否则运维看到
    WARN 也无从下手；
  · 通过 `app.config` 模块属性取值（不是 `from .config import X`），这样
    测试可以 monkeypatch 单条开关，不必重载进程。
"""
import sys
from dataclasses import asdict, dataclass

from . import config as cfg

OK = "OK"
INFO = "INFO"
WARN = "WARN"
FAIL = "FAIL"

_LEVEL_ORDER = {FAIL: 0, WARN: 1, INFO: 2, OK: 3}


@dataclass(frozen=True)
class Finding:
    """一条姿态结论。`fix` 为空表示无需动作（OK/INFO）。"""
    level: str
    key: str
    detail: str
    fix: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _v(name: str, default=None):
    """按名字读 config 常量（模块属性查找，monkeypatch 友好）。"""
    return getattr(cfg, name, default)


def _db_host() -> str:
    """从 DATABASE_URL 里抠出主机名（不解析口令，避免把凭证带进日志）。"""
    url = str(_v("DATABASE_URL", "") or "")
    tail = url.split("://", 1)[-1]
    host = tail.split("@")[-1].split("/", 1)[0]          # [user:pass@]host:port
    return host.split(":", 1)[0].strip("[]").lower()


def _external_anchor_enabled() -> bool:
    return bool(_v("AUDIT_ANCHOR_EXTERNAL_FILE", "") or _v("AUDIT_ANCHOR_URL", ""))


def _secrets_provider_effective() -> str:
    """密钥托管实际生效的来源（与 secrets_provider 的 auto 判定保持一致）。"""
    mode = str(_v("SECRETS_PROVIDER", "auto") or "auto").lower()
    if mode in ("file", "http"):
        return mode
    if mode == "auto":
        if _v("SECRETS_DIR", ""):
            return "file"
        if _v("SECRETS_URL", ""):
            return "http"
        return "none"
    return "none"


def assess() -> list[Finding]:
    """计算当前进程的安全姿态。纯函数（只读配置），可在任意时刻重复调用。"""
    f: list[Finding] = []

    def ok(key: str, detail: str) -> None:
        f.append(Finding(OK, key, detail))

    def info(key: str, detail: str) -> None:
        f.append(Finding(INFO, key, detail))

    def warn(key: str, detail: str, fix: str) -> None:
        f.append(Finding(WARN, key, detail, fix))

    def fail(key: str, detail: str, fix: str) -> None:
        f.append(Finding(FAIL, key, detail, fix))

    # ---------- 防泄密核心链条：关掉任何一条，等于把对应防线从产品里删掉 ----------
    if _v("SECURITY_HEADERS", True):
        ok("SECURITY_HEADERS", "安全头已启用（nosniff / DENY / no-store / CSP）")
    else:
        fail("SECURITY_HEADERS", "安全头被关闭：点击劫持、MIME 嗅探、缓存泄露全部打开",
             "置 SECURITY_HEADERS=true")

    if _v("JIGSAW_ENABLED", True):
        ok("JIGSAW_ENABLED", "防拼图账本已启用（跨会话累积暴露裁决）")
    else:
        fail("JIGSAW_ENABLED", "防拼图被关闭：多轮窄问即可拼出全貌，单次判定无法防御",
             "置 JIGSAW_ENABLED=true（仅联调可关）")

    if _v("INTENT_ENABLED", True):
        ok("INTENT_ENABLED", "意图网关已启用（探针阻断 / 推理距离约束）")
    else:
        fail("INTENT_ENABLED", "意图网关被关闭：明文片段索取与跨域归纳将直达模型",
             "置 INTENT_ENABLED=true")

    if _v("FAIL_SECURE_ENABLED", True):
        ok("FAIL_SECURE_ENABLED", "Fail-Secure 降级通道已启用（权限/检索故障断内部库）")
    else:
        fail("FAIL_SECURE_ENABLED", "Fail-Secure 被关闭：权限引擎故障时会继续用内部知识库作答",
             "置 FAIL_SECURE_ENABLED=true")

    # 单账号账本挡不住"N 个低权限账号各取一块、线下合并"——这条防线是检出而非拦截，
    # 关掉不等于数据会立刻外流，但等于没人会被告知发生了合谋，故按 WARN 处理。
    if _v("JIGSAW_ENABLED", True) and not _v("JIGSAW_COALITION_ENABLED", True):
        warn("JIGSAW_COALITION",
             "跨账号合谋检出被关闭：多账号各取一块线下合并，单账号账本不会报警",
             "置 JIGSAW_COALITION_ENABLED=true（管理端 /api/admin/jigsaw/coalition 可查）")
    elif _v("JIGSAW_ENABLED", True):
        ok("JIGSAW_COALITION",
           "跨账号合谋检出已启用（长窗口多账号并集覆盖率，管理端可查）")

    # ---------- 审计：只追加 + 外置锚点 ----------
    if _v("AUDIT_APPEND_ONLY", True):
        ok("AUDIT_APPEND_ONLY", "审计只追加触发器已启用（UPDATE/DELETE 被数据库拒绝）")
    else:
        fail("AUDIT_APPEND_ONLY", "审计只追加被关闭：任何有 UPDATE 权限的人都能改写历史",
             "置 AUDIT_APPEND_ONLY=true")

    if _external_anchor_enabled():
        ok("AUDIT_ANCHOR_EXTERNAL", "外置锚点已配置（链尾见证离开本机，删库删盘也无法同步篡改）")
    else:
        warn("AUDIT_ANCHOR_EXTERNAL",
             "未配置外置锚点：链尾只在本机（DB + 本地文件），同时拿到两处写权限就能"
             "截断审计而不被检出",
             "置 AUDIT_ANCHOR_EXTERNAL_FILE=/secure/audit.ndjson（或 AUDIT_ANCHOR_URL 指向只追加网关）")

    # ---------- 身份与会话 ----------
    if _v("JWT_SECRET", ""):
        ok("JWT_SECRET", "JWT 密钥为固定注入值（重启不掉线、多 worker 一致）")
    else:
        fail("JWT_SECRET", "JWT_SECRET 未配置：进程级随机密钥，重启即全员失效、"
                           "多 worker 间歇 401",
             "生成 48 位随机串置 JWT_SECRET（写入 .env 或密钥托管源）")

    if _v("AUTH_COOKIE_MODE", False):
        ok("AUTH_COOKIE_MODE", "Cookie 会话模式（HttpOnly + 双重提交 CSRF，令牌不进 JS）")
    else:
        warn("AUTH_COOKIE_MODE", "Bearer 模式：令牌存于浏览器 localStorage，任一 XSS 即可窃取",
             "生产置 AUTH_COOKIE_MODE=true（前端已适配）")

    if _v("MFA_ENABLED", True):
        if _v("MFA_ENFORCE_ADMIN", False) or _v("MFA_ENFORCE_ALL", False):
            ok("MFA_ENFORCE", "管理员/全体已强制第二因子")
        else:
            warn("MFA_ENFORCE_ADMIN", "MFA 可用但未强制：管理员账号仍可单因子登录",
                 "置 MFA_ENFORCE_ADMIN=true（金融场景建议连同 MFA_ENFORCE_ALL 一起评估）")
    else:
        warn("MFA_ENABLED", "MFA 整体关闭：高密级账号只有口令一道门",
             "置 MFA_ENABLED=true")

    if _v("OIDC_CLAIM_SYNC", False) and str(_v("OIDC_CLAIM_SYNC_UNKNOWN", "ignore")).lower() == "ignore":
        warn("OIDC_CLAIM_SYNC_UNKNOWN",
             "IdP 同步已开启，但未登记的 role/clearance 取值被静默忽略：IdP 侧新增角色"
             "不会报错，只会悄悄没权限（排查极耗时）",
             "置 OIDC_CLAIM_SYNC_UNKNOWN=reject 让不认识的取值直接拒绝登录")

    # ---------- 传输与入口 ----------
    if _v("TRUST_PROXY_HEADERS", True):
        warn("TRUST_PROXY_HEADERS",
             "信任 X-Forwarded-*（反代终止 TLS 必需）：若源站可被绕过直连，客户端可伪造"
             "协议/来源 IP，进而影响 HTTPS 跳转、Cookie Secure、审计 IP",
             "确认网络层只允许反代访问源站，并配 uvicorn FORWARDED_ALLOW_IPS=<反代 IP>；"
             "直连暴露的部署必须置 TRUST_PROXY_HEADERS=false")
    else:
        info("TRUST_PROXY_HEADERS",
             "不信任反代头：源站直连口径最安全，但反代终止 TLS 的部署需改回 true，"
             "否则 Cookie 会漏发 Secure")

    if _v("FORCE_HTTPS", False) and int(_v("HSTS_SECONDS", 0) or 0) > 0:
        ok("HTTPS", "强制跳转 HTTPS 且已下发 HSTS")
    else:
        warn("HTTPS",
             f"未同时启用 FORCE_HTTPS 与 HSTS（当前 force={bool(_v('FORCE_HTTPS', False))}, "
             f"hsts={_v('HSTS_SECONDS', 0)}s）：内网纯 HTTP 可接受，公网部署则是最容易"
             "被降级的环节",
             "公网部署置 FORCE_HTTPS=true 且 HSTS_SECONDS>=31536000")

    if str(_v("TRUSTED_HOSTS", "") or "").strip():
        ok("TRUSTED_HOSTS", "Host 头白名单已配置（防 DNS rebinding / 反代误暴露）")
    else:
        warn("TRUSTED_HOSTS", "未配置 Host 白名单：任意 Host 头都会被接受",
             "置 TRUSTED_HOSTS=rag.example.com,127.0.0.1")

    if _v("DISABLE_DOCS", False):
        ok("DISABLE_DOCS", "接口文档面已关闭（/docs、/openapi.json 不再暴露）")
    else:
        warn("DISABLE_DOCS", "接口文档面仍开放：OpenAPI 是侦察面，能列出全部端点与参数",
             "生产置 DISABLE_DOCS=true（内网联调可留）")

    if str(_v("CORS_ALLOW_ORIGINS", "") or "").strip():
        ok("CORS_ALLOW_ORIGINS", "跨域白名单已显式配置")
    else:
        info("CORS_ALLOW_ORIGINS", "未配置跨域来源（同源部署的正常形态）")

    # ---------- 数据与密钥 ----------
    provider = _secrets_provider_effective()
    if provider != "none":
        ok("SECRETS_PROVIDER", f"高危密钥来自托管源（{provider}），不落应用主机配置文件")
    elif _v("REQUIRE_SECRETS_PROVIDER", False):
        # 走到这里说明 require_provider 会更早拒绝启动，这行只是给出可读结论。
        fact = Finding(FAIL, "SECRETS_PROVIDER", "要求托管但未配置来源", "见启动日志")
        f.append(fact)
    else:
        warn("SECRETS_PROVIDER",
             "高危密钥（DB 口令 / JWT / MFA / 锚点 HMAC / API Key）来自 .env 明文",
             "置 SECRETS_PROVIDER=file 并配 SECRETS_DIR（或 http + SECRETS_URL），"
             "再置 REQUIRE_SECRETS_PROVIDER=true")

    db_host = _db_host()
    tls_on = str(_v("DATABASE_URL", "") or "").lower().find("sslmode=") >= 0 or _v("REQUIRE_DB_TLS", False)
    local_db = db_host in ("127.0.0.1", "localhost", "::1", "")
    if tls_on:
        ok("DB_TLS", "数据库链路已加密（sslmode / REQUIRE_DB_TLS）")
    elif local_db:
        info("DB_TLS", "数据库在本机（127.0.0.1/localhost），明文链路风险可接受")
    else:
        warn("DB_TLS", f"数据库在远端（{db_host}）但未启用链路加密：口令与查询在网内明文传输",
             "DSN 加 ?sslmode=require（校验证书用 verify-full），并置 REQUIRE_DB_TLS=true")

    # ---------- 可观测与审批策略（形态选择，非缺陷） ----------
    if _v("METRICS_ENABLED", False):
        ok("METRICS_ENABLED", "安全指标与告警已启用")
    else:
        warn("METRICS_ENABLED", "安全指标/告警未启用：拦截率、拼图风险、口令爆破都没人喊",
             "生产置 METRICS_ENABLED=true 并配 ALERT_WEBHOOK_URL")

    if not _v("ENFORCE_PASSWORD_CHANGE", False):
        info("ENFORCE_PASSWORD_CHANGE",
             "出厂口令仅告警不阻断启动（启动日志仍会列出未改密账号）")

    if not _v("APPROVAL_UPGRADE_REQUIRED", False):
        info("APPROVAL_UPGRADE_REQUIRED",
             "仅降密/放宽类变更新增双人复核；升密不强制（已知策略选择）")

    f.sort(key=lambda x: (_LEVEL_ORDER.get(x.level, 9), x.key))
    return f


def summarize(findings: list[Finding]) -> dict:
    counts = {OK: 0, INFO: 0, WARN: 0, FAIL: 0}
    for item in findings:
        counts[item.level] = counts.get(item.level, 0) + 1
    return {
        "counts": counts,
        # 生产口径是否就绪：没有 FAIL 且没有 WARN
        "production_ready": counts[FAIL] == 0 and counts[WARN] == 0,
        "strict": bool(_v("STRICT_SECURITY_POSTURE", False)),
    }


def report(findings: list[Finding]) -> str:
    s = summarize(findings)
    lines = [
        "[SECURITY-POSTURE] 启动安全姿态自检"
        f"（OK {s['counts'][OK]} / INFO {s['counts'][INFO]}"
        f" / WARN {s['counts'][WARN]} / FAIL {s['counts'][FAIL]}）"
    ]
    for item in findings:
        lines.append(f"  {item.level:<4} {item.key} — {item.detail}")
        if item.fix:
            lines.append(f"       → {item.fix}")
    if s["counts"][WARN] or s["counts"][FAIL]:
        lines.append(
            "  说明：WARN/FAIL 是**当前进程实际生效**的姿态，不是理论值。生产上线前应清零；"
            "置 STRICT_SECURITY_POSTURE=true 可让未清零的进程直接拒绝启动。")
    return "\n".join(lines)


def evaluate_and_report() -> list[Finding]:
    """启动时调用：打印清单；`STRICT_SECURITY_POSTURE=true` 且有 WARN/FAIL 则拒绝启动。"""
    findings = assess()
    print(report(findings), file=sys.stderr)   # stderr：不走 stdout 缓冲，容器日志里更可靠
    strict = bool(_v("STRICT_SECURITY_POSTURE", False))
    blocking = [x for x in findings if x.level in (WARN, FAIL)]
    if strict and blocking:
        keys = ", ".join(f"{x.key}({x.level})" for x in blocking)
        raise RuntimeError(
            f"拒绝启动：STRICT_SECURITY_POSTURE=true，仍有 {len(blocking)} 项未达生产口径："
            f"{keys}。逐条按上面的 → 建议修正后重启，或（仅演示环境）关闭该开关。")
    return findings
