# SPDX-License-Identifier: AGPL-3.0-only
"""部署边界中间件（P0-2）：TLS 跳转 / 浏览器安全头 / Host 校验 / CORS 白名单。

为什么这些必须写在应用里，而不是只写在 Nginx 配置里：
  · 反代配置是"环境"，随部署漂移；应用内的默认值才是可评审、可测试、
    随代码走的东西。CI 里能断言头存在，评审能看到默认拒绝的姿势。
  · 内网直连（灰度、临时排障、Windows 单机演示）往往绕过反代，此时
    反代上的安全头全部不存在——应用自己发一份，最坏情况也不裸奔。

顺序很关键（Starlette 中间件后加者在外层）：
  SecurityHeaders 最外层 → 即便内层抛 4xx/5xx，错误响应也带上安全头；
  HTTPSRedirect 在它内侧 → 跳转响应同样带 HSTS。

CSP 按"前端由本服务同源托管"写：`script-src 'self'` 是硬约束（禁止内联脚本，
这也是本项目坚持不用 eval/内联事件的原因）；Element Plus 有运行时注入的
内联样式，`style-src` 必须留 `'unsafe-inline'`——样式注入不构成脚本执行。
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse, Response

from . import config as cfg


def apply_security_headers(request, response) -> None:  # noqa: ANN001
    """把安全头写进响应（中间件与未捕获异常处理器共用）。

    为什么必须共用而不是只在中间件里写：`Exception` 处理器由 Starlette 的
    ServerErrorMiddleware 调用，它在**所有 user middleware 之外**——未捕获
    异常产生的 500 响应不经过 SecurityHeadersMiddleware。如果只写中间件，
    恰恰是最不该裸奔的 500 响应没有安全头。这里导出同一个函数，让
    errors.internal_error_handler 自己补一份。
    """
    if not cfg.SECURITY_HEADERS:
        return
    h = response.headers
    # 防 MIME 嗅探：上传的 .txt/.pdf 被当作 HTML/JS 执行是经典 RAG 上传面攻击
    h.setdefault("X-Content-Type-Options", "nosniff")
    # 防点击劫持：本系统不做第三方嵌入，一律禁止被 iframe
    h.setdefault("X-Frame-Options", "DENY")
    # 不把完整 URL（含既有查询参数）带给外部站点
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Permissions-Policy",
                 "geolocation=(), microphone=(), camera=()")
    if cfg.CSP_POLICY:
        h.setdefault("Content-Security-Policy", cfg.CSP_POLICY)
    # HSTS 只在 HTTPS 上发：明文站点发 HSTS 是无效头，且会误导运维
    # 以为已启用（浏览器只在安全上下文里认这个头）。
    if cfg.HSTS_SECONDS > 0 and is_https(request):
        h.setdefault("Strict-Transport-Security",
                     f"max-age={cfg.HSTS_SECONDS}; includeSubDomains")
    # 令牌不进缓存：Cookie 会话模式下尤其重要（共享终端按后退键不能复活）
    if request.url.path.startswith("/api"):
        h.setdefault("Cache-Control", "no-store")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """给所有响应补安全头（含 4xx/5xx 与静态资源）。"""

    async def dispatch(self, request, call_next):  # noqa: ANN001
        response = await call_next(request)
        apply_security_headers(request, response)
        return response


def is_https(request) -> bool:
    """判断"浏览器侧是否 HTTPS"（HSTS / 跳转 / Cookie Secure 共用同一口径）。

    反代终止 TLS 时应用看到的是 http；X-Forwarded-Proto 是判定依据。必须在
    一处判定：HSTS 认反代头、而 Cookie Secure 只看 request.url.scheme 的话，
    反代部署下会话 Cookie 会漏发 Secure（明文回传风险，浏览器也不拦）。
    """
    if request.url.scheme == "https":
        return True
    if cfg.TRUST_PROXY_HEADERS:
        fwd = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
        return fwd.lower() == "https"
    return False


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """FORCE_HTTPS=true 时把明文请求 308 到 https（保留方法/路径）。

    只读方法用 301 会被缓存并改变方法语义，一律 308。健康检查路径放行，
    否则负载均衡器的明文探针会拿到 308 而误判实例不健康。
    """

    EXEMPT = ("/api/health", "/api/v1/health")

    async def dispatch(self, request, call_next):  # noqa: ANN001
        if not cfg.FORCE_HTTPS or is_https(request) or request.url.path in self.EXEMPT:
            return await call_next(request)
        url = request.url.replace(scheme="https")
        return RedirectResponse(str(url), status_code=308)


class CORSGuardMiddleware(BaseHTTPMiddleware):
    """跨域守卫：默认**不开** CORS；显式白名单时按白名单放行。

    不用 FastAPI 的 CORSMiddleware 是因为它需要 allow_origins 常量，而这里
    要处理"未命中白名单"的情况：直接不给 CORS 头（浏览器自行拦截），
    并且不回应预检的 `*`——不要用"拒绝但带通配"的半吊子配置。
    """

    def __init__(self, app, origins: list[str]):
        super().__init__(app)
        self.origins = {o.rstrip("/") for o in origins if o}

    async def dispatch(self, request, call_next):  # noqa: ANN001
        origin = (request.headers.get("origin") or "").rstrip("/")
        is_preflight = (request.method == "OPTIONS"
                        and bool(request.headers.get("access-control-request-method")))
        if not self.origins or not origin or origin not in self.origins:
            # 未命中白名单：不追加任何 CORS 头。预检请求直接 403，
            # 避免浏览器把"没有响应头"误解为可继续（部分旧实现会）。
            if is_preflight:
                return JSONResponse({"detail": "跨域来源不在白名单"}, status_code=403)
            return await call_next(request)
        # 命中白名单的预检必须由中间件直接回 204：FastAPI 没有 OPTIONS 路由，
        # 交给 call_next 会得到 405，浏览器会判定预检失败（跨域前端全挂）。
        if is_preflight:
            return Response(status_code=204, headers=self._cors_headers(origin, True))
        response = await call_next(request)
        for k, v in self._cors_headers(origin, False).items():
            response.headers[k] = v
        return response

    def _cors_headers(self, origin: str, preflight: bool) -> dict:
        headers = {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
            "Access-Control-Allow-Credentials": "true",
            # Cookie 会话模式下前端要读 CSRF 头 / 强制改密 / 强制绑定 MFA 标记
            "Access-Control-Expose-Headers": (
                "X-CSRF-Token, X-Must-Change-Password, X-MFA-Setup-Required"),
        }
        if preflight:
            headers.update({
                "Access-Control-Allow-Methods":
                    "GET, POST, PATCH, PUT, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Authorization, Content-Type, X-CSRF-Token, X-Requested-With"),
                "Access-Control-Max-Age": "600",
            })
        return headers
