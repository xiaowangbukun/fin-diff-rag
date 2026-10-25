# SPDX-License-Identifier: Apache-2.0
"""全局配置：全部可通过环境变量覆盖，便于金融内网部署时注入。"""
import os
from pathlib import Path

from . import secrets_provider

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))


def _load_env_file() -> None:
    """轻量 .env 支持：系统环境变量优先，配置文件只做兜底。"""
    for p in (BASE_DIR / ".env", BASE_DIR.parent / ".env"):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k:
                os.environ.setdefault(k, v)


_load_env_file()

DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _env(k: str, default: str = "") -> str:
    return os.getenv(k, default).strip()


def _secret(name: str, default: str = "") -> str:
    """高危密钥取值：托管源（密封文件 / KMS 网关）优先，未配置时才用环境变量。

    P0-5：密钥不落应用主机配置文件的落地方式。托管源一旦启用就不再回落
    .env——"以为在托管、实际在用明文"是比不托管更危险的状态（合规检查会
    认为已托管，事故却出在明文上）。见 app/secrets_provider.py。
    """
    return secrets_provider.resolve(name, default)



# ---------- 数据库 ----------
# #21：SQLite 降级链路已移除，PostgreSQL + pgvector 是唯一存储后端。
# DATABASE_URL 必填；缺失或非 postgres 开头由 require_database_url() 在
# 启动期拒绝。刻意不做导入期校验：import app.main 不该因缺配置而失败
# （CI 的 import 冒烟步骤依赖这一点）。
DATABASE_URL = _secret("DATABASE_URL", _env("DATABASE_URL", ""))


def require_database_url() -> None:
    """启动期校验：DATABASE_URL 必填且必须是 PostgreSQL 连接串。

    与 require_embedding_key() 同一口径——导入期不校验、启动期拒绝，
    且排在 init_db() 之前：配置类失败不该先留下半个库（建表/种子都是
    副作用）。刻意不在报错里回显连接串内容（可能含账号信息）。
    """
    if not DATABASE_URL:
        raise RuntimeError(
            "拒绝启动：未配置 DATABASE_URL。自 #21 起本项目只支持 "
            "PostgreSQL + pgvector（SQLite 降级链路已移除）。请注入形如 "
            "postgresql+psycopg://user:pass@host:5432/dbname 的连接串。"
        )
    if not DATABASE_URL.startswith("postgres"):
        raise RuntimeError(
            "拒绝启动：DATABASE_URL 不是 PostgreSQL 连接串。SQLite 降级"
            "链路已移除（#21），只支持 postgresql:// 或 "
            "postgresql+psycopg:// 开头的连接串。"
        )


def require_db_tls() -> None:
    """启动期校验：REQUIRE_DB_TLS=true 时连接串必须显式启用 TLS。

    为什么要显式：数据库链路承载的是全库密级内容 + 审计证据，明文在内网
    横向移动场景下等于把"谁看了什么绝密"整包送人。sslmode=prefer（libpq
    默认）会**静默降级**成明文——必须 require / verify-ca / verify-full 才算数。
    verify-ca/verify-full 还要求根证书在位（`sslrootcert=`），因此这里只校验
    模式，不校验证书文件是否存在（证书路径属部署环境）。
    """
    if not REQUIRE_DB_TLS:
        return
    from urllib.parse import parse_qs, urlsplit

    query = parse_qs(urlsplit(DATABASE_URL).query)
    mode = (query.get("sslmode") or [""])[0].strip().lower()
    if mode not in ("require", "verify-ca", "verify-full"):
        raise RuntimeError(
            "拒绝启动：REQUIRE_DB_TLS=true 但 DATABASE_URL 未启用强制 TLS。"
            "请在连接串追加 ?sslmode=verify-full（或 require / verify-ca），"
            f"当前为 {mode or '未设置'}。sslmode=prefer 会静默降级为明文，不算数。"
        )

# ---------- 大模型 / Embedding（OpenAI 兼容协议）----------
LLM_BASE_URL = _env("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_API_KEY = _secret("LLM_API_KEY", _env("LLM_API_KEY", ""))
LLM_MODEL = _env("LLM_MODEL", "deepseek-chat")

EMBED_BASE_URL = _env("EMBED_BASE_URL", LLM_BASE_URL)
EMBED_API_KEY = _secret("EMBED_API_KEY", _env("EMBED_API_KEY", LLM_API_KEY))
EMBED_MODEL = _env("EMBED_MODEL", "text-embedding-3-small")
EMBED_DIM = int(_env("EMBED_DIM", "1024"))          # pgvector 列维度，改值需重建表
# true = 未配置 EMBED_API_KEY 时拒绝启动（方案 B，现为唯一路径：#21 已移除
# 本地哈希向量，无 Key 即无可用向量通道）。仅离线测试/回归基线可显式置
# false 放行——放行后由测试侧注入替身 embedder（见 tests/conftest.py），
# 不代表生产可无 Key 运行。
EMBED_REQUIRE_API_KEY = _env("EMBED_REQUIRE_API_KEY", "true").lower() in (
    "1", "true", "yes", "on")

HTTP_TIMEOUT = int(_env("HTTP_TIMEOUT", "60"))

# ---------- 安全 ----------
# JWT_SECRET 为空时启动生成进程级随机密钥（重启失效，开发无感；忘配固定密钥
# 的最坏结果是重启后需重新登录，而不是被固定默认密钥伪造身份）。
# 生产必须显式注入固定密钥，多 worker 部署尤其如此。
JWT_SECRET = _secret("JWT_SECRET", _env("JWT_SECRET", ""))
# 轮换过渡密钥：只参与验证、不用于签发。换密钥时先配 OLD 再换新，实现无缝轮换。
JWT_SECRET_OLD = _secret("JWT_SECRET_OLD", _env("JWT_SECRET_OLD", ""))
# true = 未配置 JWT_SECRET 时拒绝启动（生产建议开启）
ENFORCE_JWT_SECRET = _env("ENFORCE_JWT_SECRET", "false").lower() in ("1", "true", "yes", "on")
# 出厂口令闸门：seed 注入的 admin/业务角色口令（Admin@123 / User@123）若未改，
# 等于把全库对内网开放（admin 密级 3 可见绝密）。默认只告警（演示/测试仍可跑），
# true = 启动期检出即拒绝启动——生产部署请置 true。
ENFORCE_PASSWORD_CHANGE = _env("ENFORCE_PASSWORD_CHANGE", "false").lower() in (
    "1", "true", "yes", "on")
JWT_EXPIRE_HOURS = int(_env("JWT_EXPIRE_HOURS", "12"))

# ---------- 口令哈希强度（闭环项 3）----------
# 600k 为 OWASP 当前对 PBKDF2-HMAC-SHA256 的建议下限（2023 口径）。
# LEGACY_ITERATIONS 只用于验证**存量旧格式**哈希：登录成功时透明重算为新格式，
# 因此升级迭代次数不需要任何人重置口令。
PASSWORD_ITERATIONS = int(_env("PASSWORD_ITERATIONS", "600000"))
LEGACY_ITERATIONS = 120_000

# ---------- 多因子认证：TOTP（闭环项 3 · S3，双适配之一）----------
# 为什么用 TOTP 而不是短信/邮件：内网可离线、无运营商依赖、无按条计费，
# 密钥不出企业边界。TOTP 是"第二因子"，不替代口令：登录先验口令，再验
# 动态口令，两步都过才签发会话。
#
# MFA_ENABLED 是总开关：关掉后即便用户已绑定 TOTP 也只用口令登录
# （应急降级用，需审计说明）。
MFA_ENABLED = _env("MFA_ENABLED", "true").lower() in ("1", "true", "yes", "on")
# 强制绑定策略（服务端硬闸，不是前端提示）：未绑定者除身份自查/绑定/登出
# 外一律 403。默认关：演示账号与冒烟基线要保持"登录即可用"；生产内网应
# 置 MFA_ENFORCE_ADMIN=true（admin 可见绝密），高敏机构可再开 ENFORCE_ALL。
MFA_ENFORCE_ADMIN = _env("MFA_ENFORCE_ADMIN", "false").lower() in (
    "1", "true", "yes", "on")
MFA_ENFORCE_ALL = _env("MFA_ENFORCE_ALL", "false").lower() in (
    "1", "true", "yes", "on")
# 第一步口令校验通过后签发的"待验动态口令"票据（独立 purpose，不可当访问令牌）
MFA_CHALLENGE_MINUTES = int(_env("MFA_CHALLENGE_MINUTES", "5"))
# 动态口令参数：RFC 6238 默认 SHA1/6 位/30 秒。允许前后各 1 步时钟漂移
# （±30 秒），再宽就等于给爆破让路。
TOTP_ISSUER = _env("TOTP_ISSUER", "FinRAG")
TOTP_DIGITS = int(_env("TOTP_DIGITS", "6"))
TOTP_PERIOD = int(_env("TOTP_PERIOD", "30"))
TOTP_WINDOW_STEPS = int(_env("TOTP_WINDOW_STEPS", "1"))
# TOTP 密钥静态加密用的 Fernet key（64 字符 urlsafe base64）。留空则从
# JWT_SECRET 派生（同一密钥库，轮换 JWT 密钥需先确认已无人依赖派生密钥）。
# 两者都没配时拒绝绑定（宁可 503 也不明文存第二因子）。
MFA_SECRET_KEY = _secret("MFA_SECRET_KEY", _env("MFA_SECRET_KEY", ""))

# 恢复码（一次性备用码）：手机丢失/换机且来不及找管理员时的自助出口。
# 为什么不用 6 位数字：恢复码等价于第二因子本身，必须是高熵随机串
# （12 个字符取自 32 字母表 = 60 bit），否则可以离线爆破。
RECOVERY_CODE_COUNT = int(_env("RECOVERY_CODE_COUNT", "10"))
RECOVERY_CODE_ENABLED = _env("RECOVERY_CODE_ENABLED", "true").lower() in (
    "1", "true", "yes", "on")

# ---------- 单点登录：OIDC（闭环项 3 · S3，双适配之二）----------
# 授权码 + PKCE 流程，对接企业 IdP（Keycloak/Azure AD/Okta/飞书等）。
# 与 TOTP 可同时开启：本地账号走口令+TOTP，企业账号走 SSO，互不冲突。
OIDC_ENABLED = _env("OIDC_ENABLED", "false").lower() in ("1", "true", "yes", "on")
OIDC_ISSUER = _env("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = _env("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = _secret("OIDC_CLIENT_SECRET", _env("OIDC_CLIENT_SECRET", ""))
# 回调地址必须与 IdP 侧登记一致；留空则按请求的 base_url 推导
# （/api/auth/oidc/callback），仅适合单域名部署。
OIDC_REDIRECT_URI = _env("OIDC_REDIRECT_URI", "")
OIDC_SCOPES = _env("OIDC_SCOPES", "openid profile email")
# 用哪个 claim 匹配本地 username（常见 preferred_username / email / upn）
OIDC_USERNAME_CLAIM = _env("OIDC_USERNAME_CLAIM", "preferred_username")
# 即时建号：默认关——金融机构的账号应由 HR/管理员先建，SSO 只做认证。
# 开启后首次 SSO 登录按默认密级/角色建号（无本地口令，只能走 SSO）。
OIDC_JIT_PROVISION = _env("OIDC_JIT_PROVISION", "false").lower() in (
    "1", "true", "yes", "on")
OIDC_DEFAULT_CLEARANCE = int(_env("OIDC_DEFAULT_CLEARANCE", "0"))
OIDC_DEFAULT_ROLES = _env("OIDC_DEFAULT_ROLES", "")
# IdP 已完成 MFA（如 Azure AD 强制 MFA）时，本地不再叠加 TOTP。
# 置 false = SSO 登录仍要求本地动态口令（双因子叠加，仅高敏场景需要）。
OIDC_TRUST_IDP_MFA = _env("OIDC_TRUST_IDP_MFA", "true").lower() in (
    "1", "true", "yes", "on")
OIDC_METADATA_TTL = int(_env("OIDC_METADATA_TTL", "3600"))   # 发现文档/JWKS 缓存秒数
OIDC_HTTP_TIMEOUT = int(_env("OIDC_HTTP_TIMEOUT", "10"))
OIDC_BUTTON_LABEL = _env("OIDC_BUTTON_LABEL", "企业单点登录")

# ---------- IdP claim → 本地权限同步（默认关）----------
# 默认关是有意的：IdP 侧一次误配置就能放大数据可见面，权限应以本地为准。
# 开启后只认**白名单映射**，claim 里没登记的值一律忽略（而不是"照着写"）。
OIDC_CLAIM_SYNC = _env("OIDC_CLAIM_SYNC", "false").lower() in ("1", "true", "yes", "on")
OIDC_ROLE_CLAIM = _env("OIDC_ROLE_CLAIM", "roles")
# 形如 "fin_research:research,fin_risk:risk"（IdP 角色名:本地角色名）
OIDC_ROLE_MAP = _env("OIDC_ROLE_MAP", "")
# 密级 claim（留空 = 不同步密级）。取值经映射表翻译成 0-3 的整数。
OIDC_CLEARANCE_CLAIM = _env("OIDC_CLEARANCE_CLAIM", "")
# 形如 "public:0,internal:1,confidential:2,secret:3"
OIDC_CLEARANCE_MAP = _env("OIDC_CLEARANCE_MAP", "")
# claim 同步能授予的密级上限（默认 1=内部）：即使 IdP 配了 secret，
# 也不会自动把人抬到绝密——那一步必须由本地管理员做。
OIDC_CLAIM_SYNC_MAX_CLEARANCE = int(_env("OIDC_CLAIM_SYNC_MAX_CLEARANCE", "1"))
# 是否允许 claim 同步授予 admin（默认否：管理员必须是本地显式操作）
OIDC_CLAIM_SYNC_ALLOW_ADMIN = _env("OIDC_CLAIM_SYNC_ALLOW_ADMIN", "false").lower() in (
    "1", "true", "yes", "on")
# claim 里出现白名单外的角色/密级值时的口径：ignore（忽略，保持本地现状）
# / deny（拒绝本次登录）。严格模式适合 IdP 与本地映射表强一致的环境。
OIDC_CLAIM_SYNC_UNKNOWN = _env("OIDC_CLAIM_SYNC_UNKNOWN", "ignore").lower()

# ---------- 登录防爆破（#11）----------
# pbkdf2 600k 迭代只能压慢爆破，不能阻止——按 key（用户名 / 用户名#mfa）失败
# 计数 + 锁定，把"无限试"变成"试 5 次等 15 分钟"。
# 后端：auto（默认，有 DATABASE_URL 走共享 PG 表）/ memory（进程内，单 worker
# 部署或离线诊断）/ db（强制共享）。db 后端不可用时自动回落 memory 并降频重试，
# 保证登录入口不因计数存储故障整体不可用。
LOGIN_THROTTLE_BACKEND = _env("LOGIN_THROTTLE_BACKEND", "auto").lower()
LOGIN_MAX_FAILS = int(_env("LOGIN_MAX_FAILS", "5"))              # 窗口内失败次数上限
LOGIN_WINDOW_MINUTES = int(_env("LOGIN_WINDOW_MINUTES", "5"))    # 计数滚动窗口
LOGIN_LOCK_MINUTES = int(_env("LOGIN_LOCK_MINUTES", "15"))       # 触发后的锁定时长

# ---------- 部署边界：TLS / 浏览器安全头 / CORS（P0-2）----------
# 金融机构的部署形态通常是"TLS 终止在反代（Nginx/F5/网关），应用只监听内网
# 明文口"。因此这里既要能信任反代传来的协议头，也要能在灰度/直连时强制跳
# HTTPS——两种形态都能收口，而不是把安全责任全推给运维"记得配"。
TRUST_PROXY_HEADERS = _env("TRUST_PROXY_HEADERS", "true").lower() in (
    "1", "true", "yes", "on")
FORCE_HTTPS = _env("FORCE_HTTPS", "false").lower() in ("1", "true", "yes", "on")
HSTS_SECONDS = int(_env("HSTS_SECONDS", "31536000"))   # 0 = 不发 HSTS（内网纯 HTTP 时）
SECURITY_HEADERS = _env("SECURITY_HEADERS", "true").lower() in ("1", "true", "yes", "on")
# CSP 按"前端由本服务同源托管"来写：脚本/样式/接口全部 self，禁 object/框架嵌套。
# Element Plus 有运行时内联样式，style-src 必须留 'unsafe-inline'（不影响脚本执行）。
CSP_POLICY = _env("CSP_POLICY", (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
))
# 跨域白名单：默认空 = 不装 CORS 中间件（只允许同源）。确需前后端分离部署时
# 显式列出来源（逗号分隔），不要用 *——带 Cookie 的跨域在规范上也不允许 * 配凭证。
CORS_ALLOW_ORIGINS = _env("CORS_ALLOW_ORIGINS", "")
# Host 头白名单（防 DNS rebinding / 反代配错暴露到公网）。留空 = 不校验。
TRUSTED_HOSTS = _env("TRUSTED_HOSTS", "")
# true = 关闭 /docs、/redoc、/openapi.json（生产建议开：接口文档面本身是侦察面）
DISABLE_DOCS = _env("DISABLE_DOCS", "false").lower() in ("1", "true", "yes", "on")

# ---------- 会话：空闲超时 + 单端吊销（P0-4）----------
# 12 小时固定过期对办公场景太宽：离开工位一下午再回来仍可读绝密。这里加
# 服务端会话表，按"最后一次使用"计空闲超时；0 = 关闭（仅测试/离线诊断）。
SESSION_IDLE_MINUTES = int(_env("SESSION_IDLE_MINUTES", "30"))
# 每次请求都写一次 last_seen 会把审计库打热，因此节流：最多每 N 秒回写一次。
SESSION_TOUCH_SECONDS = int(_env("SESSION_TOUCH_SECONDS", "60"))
# Cookie 会话模式：令牌不进 localStorage（XSS 也拿不到），改由 HttpOnly
# Cookie 承载 + 双提交 CSRF 校验。默认关，保持"Bearer 令牌"的兼容路径；
# 生产建议开（前端已适配）。开启后登录响应不再回传 token。
AUTH_COOKIE_MODE = _env("AUTH_COOKIE_MODE", "false").lower() in (
    "1", "true", "yes", "on")
AUTH_COOKIE_NAME = _env("AUTH_COOKIE_NAME", "finrag_session")
CSRF_COOKIE_NAME = _env("CSRF_COOKIE_NAME", "finrag_csrf")
# Cookie 的 Secure 属性：auto = 按请求实际协议（HTTPS 才设），true/false 强制。
AUTH_COOKIE_SECURE = _env("AUTH_COOKIE_SECURE", "auto").lower()

# ---------- 密钥托管（P0-5）----------
# 高危密钥（DATABASE_URL / JWT_SECRET / MFA_SECRET_KEY / AUDIT_ANCHOR_HMAC_KEY /
# OIDC_CLIENT_SECRET / LLM_API_KEY / EMBED_API_KEY）从密封文件或 KMS 网关读取，
# 不落应用主机配置文件。托管源一旦启用就不再回落 .env（避免"以为在托管、
# 实际在用明文"）。见 app/secrets_provider.py。
SECRETS_PROVIDER = _env("SECRETS_PROVIDER", "auto").lower()
SECRETS_DIR = _env("SECRETS_DIR", "")
SECRETS_URL = _env("SECRETS_URL", "")
SECRETS_TOKEN = _secret("SECRETS_TOKEN", _env("SECRETS_TOKEN", ""))
SECRETS_TTL = int(_env("SECRETS_TTL", "300"))
# true = 启动期强制要求密钥确实来自托管源（生产建议开）
REQUIRE_SECRETS_PROVIDER = _env("REQUIRE_SECRETS_PROVIDER", "false").lower() in (
    "1", "true", "yes", "on")
# true = DATABASE_URL 必须显式带 TLS（sslmode=require/verify-ca/verify-full）
REQUIRE_DB_TLS = _env("REQUIRE_DB_TLS", "false").lower() in (
    "1", "true", "yes", "on")

# ---------- 审计：只追加 + 全量外送（P0-3）----------
# 只追加：数据库触发器拒绝 UPDATE/DELETE（需要改审计行做攻击演练时，会话内
# 显式 SET LOCAL finrag.audit_append_only='off' 破窗，应用代码永不这样设）。
AUDIT_APPEND_ONLY = _env("AUDIT_APPEND_ONLY", "true").lower() in (
    "1", "true", "yes", "on")
# 全量外送：把每批新增审计行（序号+行哈希+摘要）随锚点一起发到外置 sink，
# 而不是只发链尾。这样离线副本可独立重建审计时间线，而不只是"校验尾哈希"。
AUDIT_SHIP_ROWS = _env("AUDIT_SHIP_ROWS", "true").lower() in (
    "1", "true", "yes", "on")

# ---------- 检索 ----------
TOP_K = int(_env("TOP_K", "8"))
CANDIDATE_POOL = int(_env("CANDIDATE_POOL", "60"))   # 融合前的候选池
MAX_CONTEXT_CHARS = int(_env("MAX_CONTEXT_CHARS", "6000"))

# ---------- 输入质量上限（#9：边界拒绝，替代库层 500 与静默截断）----------
# 超限请求在 pydantic schema / ingest 卡口处被明确拒绝（422/400），而不是
# 带进库层撞 PG DataError 500，或被 title[:255] 静默截断（调用方无从得知）。
MAX_UPLOAD_MB = int(_env("MAX_UPLOAD_MB", "20"))        # 单上传文件字节上限（MB）
MAX_DOC_CHARS = int(_env("MAX_DOC_CHARS", "500000"))    # 单文档正文字符上限
MAX_QUERY_CHARS = int(_env("MAX_QUERY_CHARS", "1000"))  # 单轮问答 query 字符上限

# ---------- 切片 ----------
CHUNK_SIZE = int(_env("CHUNK_SIZE", "520"))
CHUNK_OVERLAP = int(_env("CHUNK_OVERLAP", "80"))

# ---------- 密级定义 ----------
CLEARANCE_LEVELS = {"公开": 0, "内部": 1, "机密": 2, "绝密": 3}
LEVEL_NAMES = {v: k for k, v in CLEARANCE_LEVELS.items()}

# 面向用户的统一"无依据"拒答文案。刻意中性：不出现"授权""相关性未达阈值"
# 等可被反推的措辞——同一问题对高密级用户可能有答案，文案差异等于告诉低密级
# 用户"库里有但你无权看"。检索为空与命中被权限过滤走同一句话，无法区分。
# 真实原因只落审计（decision=abstain/throttle），不对外暴露。
NO_EVIDENCE_TEXT = "抱歉，当前没有可支撑该结论的资料，按防幻觉策略暂不作答。"
NO_EVIDENCE_REASON = "暂无可支撑结论的依据，已拒答"

# ---------- 防拼图攻击（累积暴露管控）----------
# 拼图攻击特征：单轮请求全部合法，靠多轮累积拼出全貌 → 必须按累积量裁决，而非单次。
JIGSAW_ENABLED = _env("JIGSAW_ENABLED", "true").lower() in ("1", "true", "yes", "on")
JIGSAW_WINDOW_HOURS = int(_env("JIGSAW_WINDOW_HOURS", "24"))     # 记账滚动窗口
JIGSAW_DOC_COVER_WARN = float(_env("JIGSAW_DOC_COVER_WARN", "0.45"))  # 单文档覆盖率软阈值 → 限流
JIGSAW_DOC_COVER_STOP = float(_env("JIGSAW_DOC_COVER_STOP", "0.70"))  # 单文档覆盖率硬阈值 → 停机
JIGSAW_MIN_DOC_CHUNKS = int(_env("JIGSAW_MIN_DOC_CHUNKS", "6"))     # 低于此段数的文档不启用覆盖率闸
JIGSAW_MAX_CHUNKS_PER_DOC = int(_env("JIGSAW_MAX_CHUNKS_PER_DOC", "12"))  # 单用户单文档窗口内切片配额
JIGSAW_MAX_PER_TURN = int(_env("JIGSAW_MAX_PER_TURN", "2"))          # 单轮单文档新切片交付上限
JIGSAW_RECALL_FACTOR = int(_env("JIGSAW_RECALL_FACTOR", "3"))        # 召回放大倍数，抵消限流占用的名额
JIGSAW_USER_DOC_LIMIT = int(_env("JIGSAW_USER_DOC_LIMIT", "25"))     # 窗口内可触及文档数
JIGSAW_USER_CHAR_LIMIT = int(_env("JIGSAW_USER_CHAR_LIMIT", "120000"))   # 窗口内累计披露字符
JIGSAW_FULLREAD_LIMIT = int(_env("JIGSAW_FULLREAD_LIMIT", "3"))     # 窗口内全篇直读次数
JIGSAW_ADMIN_EXEMPT = _env("JIGSAW_ADMIN_EXEMPT", "false").lower() in ("1", "true", "yes", "on")

# ---------- 慢速拼图：长周期累计闸（P1-7）----------
# 短窗口（JIGSAW_WINDOW_HOURS）滚过去就重置，攻击者每天卡在阈值 90% 慢拉，
# 长期照样能搬空语料。长周期闸按近 N 天的累计字符量裁决，堵住慢速消耗。
JIGSAW_LONG_WINDOW_DAYS = int(_env("JIGSAW_LONG_WINDOW_DAYS", "7"))
JIGSAW_LONG_USER_CHAR = int(_env("JIGSAW_LONG_USER_CHAR", "60000"))   # 近 N 日用户累计字符上限
JIGSAW_LONG_DOC_CHAR = int(_env("JIGSAW_LONG_DOC_CHAR", "25000"))     # 近 N 日单文档累计字符上限
JIGSAW_RISK_READONLY = int(_env("JIGSAW_RISK_READONLY", "3"))        # 有效风险分达到该值 → 转人工

# ---------- 密级变更审批流（P2-9）----------
# 降密 = 把受限内容开放出去，不可逆，必须走双人复核。
# 升级（变严格）默认直接生效：变严不产生外流，卡审批只会逼人绕过流程。
APPROVAL_UPGRADE_REQUIRED = _env("APPROVAL_UPGRADE_REQUIRED", "false").lower() in (
    "1", "true", "yes", "on")
# 紧急旁路（break-glass）：默认关，开启后降密免审批，仅在事故处置时临时开。
APPROVAL_EMERGENCY_BYPASS = _env("APPROVAL_EMERGENCY_BYPASS", "false").lower() in (
    "1", "true", "yes", "on")

# ---------- 向量索引（P1-6，仅 PostgreSQL/pgvector 生效）----------
# 无索引时 pgvector 走全表精确扫描；HNSW 是近似检索，召回与延迟的取舍点。
HNSW_AUTO_BUILD_MAX = int(_env("HNSW_AUTO_BUILD_MAX", "50000"))  # 行数超过则不在启动时自动建
HNSW_EF_SEARCH = int(_env("HNSW_EF_SEARCH", "100"))              # 查询期 ef_search，越大越准越慢

# ---------- 意图识别网关（前置意图分类：放行 / 推理距离约束 / 物理阻断）----------
# 对应「针对诱导套取：意图识别网关与推理约束」：在检索之前先给提问定性，
# 拼图式诱导探针直接阻断，跨域组合联想只允许单一文档作答（切断因果串联）。
INTENT_ENABLED = _env("INTENT_ENABLED", "true").lower() in ("1", "true", "yes", "on")
INTENT_LEDGER_TRIGGER = int(_env("INTENT_LEDGER_TRIGGER", "4"))  # 窗口内同文档窄问次数达到该值 → 探针指纹

# 探针锚句相似度（P0-3）：query 与一组典型诱导探针表述算余弦相似度，
# 复用 embedding 通道（无新依赖），弥补纯正则对同义改写/中英混杂的盲区。
# 本地哈希向量区分度有限：分数调低（只升级到 Risky 约束，不误杀正常业务问句）。
INTENT_ANCHOR_ENABLED = _env("INTENT_ANCHOR_ENABLED", "true").lower() in ("1", "true", "yes", "on")
INTENT_ANCHOR_THRESHOLD_API = float(_env("INTENT_ANCHOR_THRESHOLD_API", "0.80"))
INTENT_ANCHOR_THRESHOLD_LOCAL = float(_env("INTENT_ANCHOR_THRESHOLD_LOCAL", "0.62"))
INTENT_ANCHOR_SCORE_API = int(_env("INTENT_ANCHOR_SCORE_API", "2"))    # API 模式：等同强特征 → Danger
INTENT_ANCHOR_SCORE_LOCAL = int(_env("INTENT_ANCHOR_SCORE_LOCAL", "1"))  # 本地模式：只到 Risky
# JSON 数组覆盖默认锚句集（内网按实际攻击样本热更新，无需改代码）
INTENT_ANCHORS = _env("INTENT_ANCHORS", "")

# ---------- Fail-Secure 容灾降级 ----------
# 对应「容灾降级规范：Fail-Secure」：权限/检索组件异常时宁可答非所问或保持沉默，
# 也绝不能多吐出一个越权字。异常 → 切断内部知识库，降级为仅检索 Public 公开域。
FAIL_SECURE_ENABLED = _env("FAIL_SECURE_ENABLED", "true").lower() in ("1", "true", "yes", "on")

# ---------- 部门树缓存 ----------
# 对应「消除缓存时间窗」：权限决策不做长时缓存。部门树缓存仅作性能优化，
# TTL 秒级过期，任何结构变更都会立即 invalidate，避免"人员异动后的安全空窗期"。
DEPT_CACHE_TTL = float(_env("DEPT_CACHE_TTL", "5"))

# ---------- 提示注入防护（P1-4）----------
# 检索资料视为数据而非指令：入库与问答出口双向扫描"忽略规则/输出提示词"类话术。
# 命中只标记留痕（上传审计 decision=flag / 问答响应 inject_flag=true），默认不拦截，
# 避免正则误伤正常业务文本；true = 问答出口检出注入时直接用安全拒答替换回答。
INJECT_BLOCK_OUTPUT = _env("INJECT_BLOCK_OUTPUT", "false").lower() in ("1", "true", "yes", "on")

# ---------- 敏感信息识别扩展（P1-5）----------
# 自定义 PII 正则（JSON 数组），启动时追加到 pii.PATTERNS 尾部：
#   ["工号\\d{6}", {"kind": "合同编号", "pattern": "HT-\\d{10}"}]
# JSON 里反斜杠必须双写；解析失败只告警不阻断启动；自定义规则不走银行卡上下文逻辑。
PII_EXTRA_PATTERNS = _env("PII_EXTRA_PATTERNS", "")
# 可选 NER 兜底（OpenAI 兼容 chat 协议）：正则未命中时才调用，3s 超时、失败静默，
# 任何异常都不影响主链路——NER 只是正则的补充。留空 = 关闭。
PII_NER_URL = _env("PII_NER_URL", "")

# ---------- 审计异步写入（P1-8）----------
# 请求线程只入队，后台守护线程批量落库（AUDIT_BATCH_MAX 行 / AUDIT_BATCH_TIMEOUT 一批，
# 独立 Session 单事务提交）；队列满自动回落同步直写，审计不丢；关停时 flush 收尾。
AUDIT_QUEUE_MAXSIZE = int(_env("AUDIT_QUEUE_MAXSIZE", "10000"))
AUDIT_BATCH_MAX = int(_env("AUDIT_BATCH_MAX", "50"))
AUDIT_BATCH_TIMEOUT = float(_env("AUDIT_BATCH_TIMEOUT", "0.2"))

# ---------- 审计锚点外置（P0-2 增强：防"库+应用磁盘"双权限重写）----------
# 本地锚点（data/audit_anchor.json）与库同生共灭：同时拿到库写与应用磁盘写的
# 攻击者可重算全链并改写锚点。把链尾周期**追加**到应用不可回写的位置即可破局：
#   · AUDIT_ANCHOR_EXTERNAL_FILE：只追加挂载（WORM 卷 / 另一台主机的共享目录）
#   · AUDIT_ANCHOR_URL：POST 到独立日志网关/对象存储（一次写定）
# 两者可同时配置；都留空 = 不启用（本地锚点仍按原逻辑工作）。
# 每条记录带 HMAC-SHA256 签名，密钥留空则由 JWT_SECRET 派生。
AUDIT_ANCHOR_EXTERNAL_FILE = _env("AUDIT_ANCHOR_EXTERNAL_FILE", "")
AUDIT_ANCHOR_URL = _env("AUDIT_ANCHOR_URL", "")
AUDIT_ANCHOR_HMAC_KEY = _secret("AUDIT_ANCHOR_HMAC_KEY", _env("AUDIT_ANCHOR_HMAC_KEY", ""))
AUDIT_ANCHOR_INTERVAL_SECONDS = float(_env("AUDIT_ANCHOR_INTERVAL_SECONDS", "60"))
AUDIT_ANCHOR_TIMEOUT = float(_env("AUDIT_ANCHOR_TIMEOUT", "5"))

# ---------- 运维监控日报（P2-12）----------
# GET /api/admin/report/daily 按自然日只读聚合审计日志与库内状态。
# 纯 SELECT：日报自身不写审计，否则"今天的拦截数"里会混进看板自己的记录。
REPORT_TOP_N = int(_env("REPORT_TOP_N", "5"))          # Top 榜单长度（用户/文档/动作）
REPORT_INCLUDE_TEXT = _env("REPORT_INCLUDE_TEXT", "true").lower() in (
    "1", "true", "yes", "on")                          # false = 接口只回结构化 dict，不带文本
# 日报/指标按哪个时区切"自然日"。存储一律 naive UTC（audit ts 等），只改分桶与
# 展示：默认 Asia/Shanghai——中国运营在 00:00–08:00 看"今天"不会再错位成昨天。
# 非法值告警并回落 UTC（见 monitor.report_tz）。
REPORT_TZ = _env("REPORT_TZ", "Asia/Shanghai")

# ---------- 安全指标监控（P2-12 设计文档口径）----------
# GET /api/admin/metrics?days=14：多日时序 + 拦截率异常判定 + markdown 落盘 + webhook 告警。
# 默认关闭：关着时接口返回 503、不落盘、不推送——监控不该在无人同意时往磁盘堆文件。
METRICS_ENABLED = _env("METRICS_ENABLED", "false").lower() in ("1", "true", "yes", "on")
# 当日拦截率（blocked / 当日审计总量）超过该阈值即判定为异常日，进 alerts 并推送告警
ALERT_BLOCK_RATE = float(_env("ALERT_BLOCK_RATE", "0.30"))
# 参与异常判定的最小样本量：当日审计总量不足该值时不参与判定（不是"不告警"，
# 而是样本太小不做判定——否则某天只有 1 条审计且被拦，拦截率 1.0 就会误报）
ALERT_MIN_ACTIONS = int(_env("ALERT_MIN_ACTIONS", "20"))
# 异常日摘要推送地址（POST JSON）。留空 = 不推送；推送失败只告警，不影响接口返回
ALERT_WEBHOOK_URL = _env("ALERT_WEBHOOK_URL", "")
# 运维日报 markdown（backend/reports/*.md）的保留天数：更早的文件由
# POST /api/admin/metrics/cleanup 清理。只管落盘文件，不碰任何库表——
# 审计日志与暴露账本按设计不自动清理（见 README「九、数据保留与删除」）。
METRICS_RETENTION_DAYS = int(_env("METRICS_RETENTION_DAYS", "90"))

# 内置角色
ROLES = ["admin", "compliance", "risk", "research", "trader", "guest"]
