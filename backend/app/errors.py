# SPDX-License-Identifier: Apache-2.0
"""HTTP 错误语义：下游不可用统一 503，未捕获异常仍 500。

设计口径（与 README「HTTP 错误语义」一节一一对应）：
  · 4xx = 请求本身的问题（参数、权限、限流），由各端点按既有语义抛出，
    本模块不接管——尤其不动 jigsaw 的 429 与权限侧 404
    （越权与不存在同形，都是 404，见 routers/docs.py `_mask_not_found`）；
  · 503 = 下游依赖不可用（数据库连接失败 / embedding 超时 / LLM 超时），
    带 `Retry-After` 头，语义是"暂时不可用，退避重试有可能好"，
    客户端（前端轮询、上游网关）据此做指数退避，而不是当致命错误处理；
  · 500 = 未捕获异常。状态码保持 FastAPI 默认的 500，响应体统一为 JSON，
    并把完整堆栈显式落入日志——不依赖 ASGI server 的日志配置，
    "未捕获异常必有完整堆栈可查"由应用自己保证。

为什么下游超时要显式 503 而不是静默降级：embedding/LLM 一旦配了远端，
就等于运维声明过"有这条链路"。此时超时若静默降级（本地哈希向量 /
抽取式回答），用户拿到的是看似正常、实则无依据的答案——比明确失败
更危险。未配置 Key 的零配置演示模式本就走在本地通道，不属于"下游不可用"，
继续降级、不受影响。
"""
import logging
import traceback

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import InterfaceError, OperationalError

# 退避重试间隔（秒）：503 响应经 Retry-After 头告知客户端多久后再来。
RETRY_AFTER_SECONDS = 30

logger = logging.getLogger("finrag.errors")


class ServiceUnavailable(Exception):
    """下游依赖不可用（数据库连接失败 / embedding 超时 / LLM 超时等）。

    统一映射为 HTTP 503 + `Retry-After: 30`。503 与 500 的分界：
    503 是"暂时的，重试可能好"；500 是"服务内部错误，重试大概率还错"。
    """

    def __init__(
        self,
        detail: str = "服务暂时不可用，请稍后重试",
        *,
        dependency: str = "",
        retry_after: int = RETRY_AFTER_SECONDS,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        # dependency：机器可读的归因标签（database / embedding / llm），
        # 供响应体与监控聚合使用；文案本身仍是中文可读的 detail。
        self.dependency = dependency
        self.retry_after = max(1, int(retry_after))


def dependency_timeout(dependency: str, label: str,
                       timeout: int) -> ServiceUnavailable:
    """下游超时 → ServiceUnavailable（embedding / LLM 共用）。

    dependency 用机器可读英文标签，label 用中文名（进 detail 文案）。
    """
    return ServiceUnavailable(
        f"{label}服务响应超时（超过 {timeout}s 未返回），请稍后重试",
        dependency=dependency,
    )


def downstream_detail(exc: BaseException) -> str:
    """原始下游异常 → 对客户端可见的归因描述（刻意不含内部细节）。

    SQLAlchemy 连接类异常（OperationalError/InterfaceError）可能是
    "连不上"也可能是"锁超时/无此表"，对客户端是同一种处置：退避重试。
    原始错误文本只进日志——连接串、SQL、账号名都可能敏感，
    响应体里只给归因，排查靠服务端日志。
    """
    if isinstance(exc, (OperationalError, InterfaceError)):
        return "数据库暂时不可用（连接失败或锁超时），请稍后重试"
    return "依赖服务暂时不可用，请稍后重试"


def service_unavailable_handler(request: Request, exc: Exception) -> JSONResponse:
    """ServiceUnavailable 与 SQLAlchemy 连接类异常 → 503 + Retry-After。

    同时接管两种来源：
      1) 代码显式 raise 的 ServiceUnavailable（embedding/LLM 超时）；
      2) 未经转换直接冒到 ASGI 层的 OperationalError/InterfaceError
         （数据库连接失败，注册见 main.py）。
    """
    if isinstance(exc, ServiceUnavailable):
        detail, dependency = exc.detail, exc.dependency
        retry_after = exc.retry_after
    else:
        detail = downstream_detail(exc)
        dependency = "database"
        retry_after = RETRY_AFTER_SECONDS
    logger.warning(
        "下游不可用：%s %s → 503（%s: %s）",
        request.method, request.url.path, type(exc).__name__, exc,
    )
    return JSONResponse(
        {"detail": detail, "dependency": dependency},
        status_code=503,
        headers={"Retry-After": str(retry_after)},
    )


def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """未捕获异常 → 500（保持 FastAPI 默认状态码）+ 完整堆栈入日志。

    响应体统一成 JSON，与 4xx/503 的错误形状一致，前端可按同一套逻辑解析。
    堆栈在本处理器里显式记录一份：ASGI server（uvicorn）也会记一份，
    双保险——日志配置变化时"未捕获异常有完整堆栈"这件事依然成立。
    """
    logger.error(
        "未捕获异常：%s %s\n%s",
        request.method, request.url.path,
        "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    )
    return JSONResponse(
        {"detail": "服务器内部错误，请联系管理员"}, status_code=500
    )
