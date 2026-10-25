# SPDX-License-Identifier: AGPL-3.0-only
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import InterfaceError, OperationalError

from .audit import resume_chain, shutdown_audit
from .config import (
    CORS_ALLOW_ORIGINS, DISABLE_DOCS, ENFORCE_PASSWORD_CHANGE, TRUSTED_HOSTS,
    require_database_url,
)
from .db import SessionLocal, init_db
from .embed import check_dimension_consistency, require_embedding_key
from .errors import (
    ServiceUnavailable, internal_error_handler, service_unavailable_handler,
)
from .httpguard import (
    CORSGuardMiddleware, HTTPSRedirectMiddleware, SecurityHeadersMiddleware,
)
from .migrate import ensure_schema
from .routers import admin, auth, chat, docs
from .seed import default_password_users, ensure_seed
from .vindex import ensure_vector_index

DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


def _cors_origins() -> list[str]:
    """CORS 白名单（逗号分隔）。空 = 不启用跨域，只允许同源。"""
    return [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # #21：DATABASE_URL 必填校验与方案 B（无 EMBED_API_KEY 拒绝启动）同为
    # 配置类失败，放在 init_db 之前——配置类失败不该先留下半个库
    # （建表/种子都是副作用）。
    require_database_url()
    require_embedding_key()
    # P0-5/P0-6：密钥来源与数据库链路加密同为"配置类失败"，必须在建表之前拒绝。
    from .config import require_db_tls
    from .secrets_provider import require_provider as require_secret_provider
    require_secret_provider(("DATABASE_URL", "JWT_SECRET"))
    require_db_tls()
    # S3 配置类失败同样前置拒绝：开了 OIDC 却没 issuer/client_id 时，
    # 登录页会挂一个永远 503 的按钮——宁可起不来，也别带病对外。
    from .oidc import require_config as require_oidc_config
    require_oidc_config()
    init_db()
    ensure_schema()  # 增量补列（哈希链字段等），旧库升级无 Alembic 也能平滑落地
    resume_chain(SessionLocal())  # 审计链尾 hash 从库恢复，重启后链继续
    ensure_seed()
    # 出厂口令风险：seed 注入的 admin（密级 3，可见绝密）/ 业务角色口令若未改，
    # 等于把全库对内网开放。默认只告警（演示与冒烟链仍可跑），
    # ENFORCE_PASSWORD_CHANGE=true 时检出即拒绝启动。
    _seed_db = SessionLocal()
    try:
        _stale = default_password_users(_seed_db)
    finally:
        _seed_db.close()
    if _stale:
        print(
            f"[SECURITY] 以下账号仍在使用出厂口令，请立即修改：{', '.join(_stale)}"
            "（生产环境任何人可用 admin 登录查看全部密级内容）",
            file=sys.stderr,
        )
        if ENFORCE_PASSWORD_CHANGE:
            raise RuntimeError(
                f"拒绝启动：{', '.join(_stale)} 仍在使用出厂口令，且 "
                "ENFORCE_PASSWORD_CHANGE=true。请先在管理端改密后再启动。"
            )
    # P0-3：外置 sink 的签名密钥若没显式配置，会在 JWT 轮换/随机化后让历史
    # 记录全部验签失败。不阻断启动（否则演示环境起不来），但必须说出来——
    # 沉默的密钥耦合最终会被运维误读成"有人伪造锚点"。
    from .anchors import startup_warning as _anchor_warning
    _warn = _anchor_warning()
    if _warn:
        print(_warn, file=sys.stderr)
    # P1-6：保障 PG 侧向量索引存在
    _db = SessionLocal()
    try:
        ensure_vector_index(_db)
        # 维度一致性要对照"库内已建的列"，必须等建表之后：全新库此时列维度
        # 就是当前配置维度，天然一致；老库维度不符则在这里明确拒绝启动。
        check_dimension_consistency(_db)
    finally:
        _db.close()
    yield
    shutdown_audit()  # P1-8：收尾把异步审计队列剩余行全部落库后再退出


app = FastAPI(
    title="金融企业级 RAG 知识库",
    description="全链路权限防泄密的检索增强问答系统",
    version="1.0.0",
    lifespan=lifespan,
    # 关掉默认 /docs 与 /redoc 之外的隐式交互文档面？保持开启便于内网联调，
    # 但生产可用 DISABLE_DOCS=true 关掉（见 config）。
    docs_url=None if DISABLE_DOCS else "/docs",
    redoc_url=None if DISABLE_DOCS else "/redoc",
    openapi_url=None if DISABLE_DOCS else "/openapi.json",
)

# ---------- 部署边界（P0-2）----------
# 中间件顺序（后加者在外层）：SecurityHeaders 最外 → 任何错误响应也带安全头；
# CORS 在其次（预检拒绝也要带安全头）；HTTPSRedirect 最内（跳转响应同样带头）。
# Host 白名单必须最先加：它若排在 SecurityHeaders 之后就是最外层，被拒的
# 400 响应会绕过安全头与 CORS 处理——恰恰是最需要最小信息量的错误分支。
if TRUSTED_HOSTS:
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=[h.strip() for h in TRUSTED_HOSTS.split(",") if h.strip()])
app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(CORSGuardMiddleware, origins=_cors_origins())
app.add_middleware(SecurityHeadersMiddleware)


# ---------- 全局异常语义（A4：HTTP 错误语义） ----------
# 503：下游不可用（数据库连接失败 / embedding 超时 / LLM 超时）统一映射，
#   带 Retry-After: 30，客户端据此退避重试。
#   · ServiceUnavailable：代码显式抛出（embed/llm 超时，见各模块）
#   · OperationalError / InterfaceError：SQLAlchemy 连接类异常直达 ASGI 层
#     （如 get_db 取会话即失败、写审计时掉线）。注意粒度：只登记连接类，
#     IntegrityError（唯一约束冲突）等仍是 500——那是请求撞车，不是服务不可用。
# 500：未捕获异常保持 FastAPI 默认状态码，响应体统一 JSON 并落完整堆栈。
# 不接管 4xx：jigsaw 429、权限 404（越权与不存在同形）、FastAPI HTTPException
# 的既有行为一律不动（见 errors.py 模块 docstring）。
app.add_exception_handler(ServiceUnavailable, service_unavailable_handler)
app.add_exception_handler(OperationalError, service_unavailable_handler)
app.add_exception_handler(InterfaceError, service_unavailable_handler)
app.add_exception_handler(Exception, internal_error_handler)

# ---------- 路由挂载（API 版本化，见 README「六之四、API 版本与兼容策略」）----------
# /api/v1 为现行契约；/api 为 deprecated 别名（至少下一个小版本后才可移除），
# 双份路径在 OpenAPI 里重复出现是刻意行为。破坏性变更必须开 v2，
# 不允许原地改 v1 语义。
for r in (auth.router, docs.router, chat.router, admin.router):
    app.include_router(r, prefix="/api/v1")
    app.include_router(r, prefix="/api")


@app.get("/api/health")
@app.get("/api/v1/health")
def health():
    from .config import JWT_SECRET, LLM_API_KEY
    from .embed import embedder
    return {
        "ok": True,
        # #21：SQLite 降级链路移除后存储只有一种，字段保留是前端与运维
        # 脚本的既有契约（test_api_versioning 断言其存在），值固定不再分支。
        "storage": "postgresql+pgvector",
        "embed_mode": embedder.mode,
        "llm_ready": bool(LLM_API_KEY),
        # JWT 密钥运维信号（#10）：configured = 注入了固定密钥；ephemeral =
        # 进程级随机密钥（每次重启失效，多 worker 下间歇 401 的根因）。
        # 判据只看 JWT_SECRET：JWT_SECRET_OLD 只参与验证不签发，单独存在
        # 不算 configured。只暴露状态枚举，绝不泄露密钥值本身。
        "jwt_secret": "configured" if JWT_SECRET else "ephemeral",
    }


if DIST.exists():
    # 静态资源走独立挂载；SPA 回退用 404 异常处理器而非 catch-all 路由，
    # 避免 /{path} 通配路由抢占 /api/** 的匹配（新版 FastAPI 路由优先级问题）。
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.exception_handler(StarletteHTTPException)
    async def spa_fallback(request, exc):  # noqa: ANN001
        if exc.status_code == 404 and not request.url.path.startswith("/api"):
            target = DIST / request.url.path.lstrip("/")
            if target.is_file():
                return FileResponse(target)
            return FileResponse(DIST / "index.html")
        # headers=exc.headers 不能省：HTTPException 可以带响应头（429 的
        # Retry-After、503 的退避提示等），重建响应时丢掉头，客户端就拿不到
        # 退避依据——这个 bug 在 dist 存在（生产形态）时才注册本处理器，
        # 本地无 dist 的测试环境反而看不见，极易漏网。无头的异常传 None，
        # 行为与原来完全一致。
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                            headers=exc.headers)