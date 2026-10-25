# SPDX-License-Identifier: Apache-2.0
import hmac
import json
import logging
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config as cfg
from .. import idp_sync, oidc, recovery, totp
from ..audit import write_log
from ..db import get_db
from ..httpguard import is_https
from ..loginthrottle import is_locked, record_failure, record_success
from ..models import AuthSession, User
from ..password_policy import PasswordPolicyError, validate_password
from ..schemas import (
    ChangePasswordIn, LoginIn, MfaLoginIn, RecoveryRegenerateIn, TotpConfirmIn,
    TotpDisableIn, TotpSetupIn,
)
from ..security import (
    active_sessions, check_session, clear_session_cookies, create_mfa_challenge,
    create_token, current_user, decode_purpose, hash_password, needs_rehash,
    open_session, revoke_session, revoke_user_sessions, set_session_cookies,
    verify_password,
)
from ..serializers import user_out

router = APIRouter(prefix="/auth", tags=["认证"])

logger = logging.getLogger("finrag.auth")

# OIDC 会话绑定 cookie：state 与 handoff 都不进 URL 的可见部分，
# HttpOnly + SameSite=Lax 防登录 CSRF 与 XSS 窃取。
OIDC_STATE_COOKIE = "finrag_oidc_state"
OIDC_HANDOFF_COOKIE = "finrag_sso_handoff"


def client_ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for")
    return (xf.split(",")[0].strip() if xf else (request.client.host if request.client else ""))


def _secure_cookie(request: Request) -> bool:
    """OIDC state/handoff Cookie 的 Secure 判定——与 HSTS/会话 Cookie 同口径。"""
    return is_https(request)


def _mfa_locked_response(username: str, remaining: int) -> JSONResponse:
    # 同登录锁定：直接返回 JSONResponse，避开 SPA 回退处理器丢 header 的问题
    return JSONResponse(
        {"detail": f"动态口令错误次数过多，账号已锁定，请 {remaining} 秒后重试"},
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(remaining)},
    )


def _issue_session(db: Session, user: User, reason: str, ip: str,
                   request: Request | None = None) -> tuple[dict, str]:
    """口令（+动态口令）都通过后的统一收口：签发会话并留痕。

    P0-4：令牌绑定服务端会话（空闲超时 / 单端吊销）。
    P0-2：AUTH_COOKIE_MODE=true 时不回传令牌，改种 HttpOnly Cookie + CSRF Cookie。
    """
    write_log(db, user=user, action="login", decision="allow", reason=reason, ip=ip)
    sess = open_session(db, user, ip=ip,
                        ua=(request.headers.get("user-agent", "") if request else ""))
    token = create_token(user, sess.sid)
    body = {"user": user_out(db, user),
            "must_change_password": bool(user.must_change_password),
            "session_id": sess.sid}
    if cfg.AUTH_COOKIE_MODE:
        body["token"] = None
        body["csrf_required"] = True
    else:
        body["token"] = token
    return body, token


def _session_json(payload: dict, token: str, request: Request) -> JSONResponse:
    """把会话载荷包成响应；Cookie 模式下种 HttpOnly + CSRF Cookie。"""
    resp = JSONResponse(payload)
    if cfg.AUTH_COOKIE_MODE:
        csrf = set_session_cookies(resp, request, token)
        resp.headers["X-CSRF-Token"] = csrf
    return resp


def _session_response(db: Session, user: User, reason: str, ip: str,
                      request: Request) -> JSONResponse:
    """同 `_issue_session`，但直接产出响应以便种 Cookie（含 CSRF）。"""
    payload, token = _issue_session(db, user, reason, ip, request)
    return _session_json(payload, token, request)


@router.get("/providers")
def providers():
    """登录页能力探测：前端据此决定显示哪些登录方式（无需鉴权）。

    只回"开没开 + 展示文案"，不回 issuer / client_id 等任何配置细节。
    """
    return {
        "password": True,
        "mfa": {
            "enabled": bool(cfg.MFA_ENABLED),
            "issuer": cfg.TOTP_ISSUER,
            "digits": cfg.TOTP_DIGITS,
            "period": cfg.TOTP_PERIOD,
            "enforce_admin": bool(cfg.MFA_ENFORCE_ADMIN),
            "enforce_all": bool(cfg.MFA_ENFORCE_ALL),
        },
        "oidc": {
            "enabled": oidc.enabled(),
            "label": cfg.OIDC_BUTTON_LABEL,
            "start": "/api/auth/oidc/start",
        },
    }


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    # 防爆破（#11）：查库之前先看锁定——被锁账号连"试口令"都不做，
    # 失败分支只记 attempt 不放行查询。429 + Retry-After 给客户端明确退避。
    remaining = is_locked(body.username)
    if remaining > 0:
        write_log(db, action="login", target_label=body.username, decision="deny",
                  reason=f"登录锁定中，剩余 {remaining} 秒", ip=ip)
        # 直接返回 JSONResponse 而非 raise HTTPException：main.py 的 SPA 回退
        # 处理器（frontend/dist 存在时注册）会用 JSONResponse({"detail": ...})
        # 重建所有 StarletteHTTPException 响应，丢弃 exc.headers——429 的
        # Retry-After 必须活着送到客户端。直接返回的响应不经异常处理器。
        return JSONResponse(
            {"detail": f"失败次数过多，账号已锁定，请 {remaining} 秒后重试"},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(remaining)},
        )
    user = db.execute(
        select(User).where(User.username == body.username.strip())
    ).scalar_one_or_none()
    if user is None or not user.status or not verify_password(body.password, user.pwd_hash, user.salt):
        record_failure(body.username)
        write_log(db, action="login", target_label=body.username, decision="deny",
                  reason="用户名或密码错误", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
    record_success(body.username)
    # 存量旧格式哈希（120k）在登录成功时透明升级到当前强度：
    # 只有拿到明文口令的这一刻才能重算，且不改变用户体验。
    if needs_rehash(user.pwd_hash):
        user.pwd_hash, user.salt = hash_password(body.password)
        db.commit()
    # 第二因子：口令正确只是第一步，动态口令未过之前绝不签发会话。
    # 挑战票据是独立用途的短时 JWT，不能当访问令牌用（security 侧校验 typ）。
    if cfg.MFA_ENABLED and totp.is_enrolled(user):
        write_log(db, user=user, action="login", decision="allow",
                  reason=f"口令校验通过（密级 {user.clearance}），等待动态口令",
                  ip=ip)
        return {"mfa_required": True, "challenge": create_mfa_challenge(user),
                "expires_in": cfg.MFA_CHALLENGE_MINUTES * 60}
    return _session_response(
        db, user,
        f"密级 {user.clearance}"
        + ("；首次登录须修改初始口令" if user.must_change_password else ""),
        ip, request)


@router.post("/login/mfa")
def login_mfa(body: MfaLoginIn, request: Request, db: Session = Depends(get_db)):
    """第二步：挑战票据 + TOTP 动态口令（或一次性恢复码）→ 正式会话。"""
    ip = client_ip(request)
    payload = decode_purpose(body.challenge, "mfa")
    user = db.get(User, payload.get("sub"))
    if user is None or not user.status:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户不存在或已停用")
    if int(payload.get("ver", 0)) != int(user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话已失效，请重新登录")
    if not (cfg.MFA_ENABLED and totp.is_enrolled(user)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "该账号未开启动态口令")
    if not body.code.strip() and not body.recovery_code.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "请提供动态口令或恢复码")

    throttle_key = f"{user.username}#mfa"
    remaining = is_locked(throttle_key)
    if remaining > 0:
        write_log(db, user=user, action="login", decision="deny",
                  reason=f"动态口令锁定中，剩余 {remaining} 秒", ip=ip)
        return _mfa_locked_response(user.username, remaining)

    if body.recovery_code.strip():
        # 恢复码通道：手机丢失/换机时的一次性自助入口。
        # 与 TOTP 共用同一账号级锁定，避免"恢复码当成绕过限速的口子"。
        if not (cfg.RECOVERY_CODE_ENABLED and recovery.available()):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "本系统未启用恢复码，请联系管理员重置动态口令")
        ok, new_blob, left = recovery.consume(user.recovery_codes,
                                              body.recovery_code)
        if not ok:
            record_failure(throttle_key)
            write_log(db, user=user, action="login", decision="deny",
                      reason="恢复码无效或已被使用", ip=ip)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "恢复码无效或已被使用；每个恢复码只能用一次，"
                "用尽后请联系管理员重置动态口令")
        user.recovery_codes = new_blob
        db.commit()
        write_log(db, user=user, action="login", decision="allow",
                  reason=f"口令+恢复码登录（剩余恢复码 {left} 个）"
                         + ("；首次登录须修改初始口令" if user.must_change_password else ""),
                  ip=ip)
        body_out, token = _issue_session(
            db, user, f"口令+恢复码通过（剩余恢复码 {left} 个）", ip, request)
        body_out["recovery_codes_remaining"] = left
        if left == 0:
            # 最后一个码也用掉了：必须明确告知"下次只能找管理员"，否则用户
            # 会以为还能继续用恢复码登录，直到被 401 卡在门外。
            body_out["recovery_warning"] = (
                "恢复码已全部用尽，请尽快在安全设置中重新生成，"
                "否则只能联系管理员重置动态口令")
        elif left <= 2:
            body_out["recovery_warning"] = (
                f"仅剩 {left} 个恢复码，请尽快在安全设置中重新生成")
        return _session_json(body_out, token, request)

    try:
        secret = totp.unseal(user.totp_secret)
    except RuntimeError as exc:
        logger.error("TOTP 密钥不可用（user=%s）：%s", user.username, exc)
        write_log(db, user=user, action="login", decision="deny",
                  reason="动态口令密钥不可用，请管理员重置", ip=ip)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "动态口令密钥不可用，请联系管理员重置")
    step = totp.verify(secret, body.code, last_step=int(user.totp_last_step or 0))
    if step is None:
        record_failure(throttle_key)
        write_log(db, user=user, action="login", decision="deny",
                  reason="动态口令校验失败（错误或窗口内重放）", ip=ip)
        # 同一口令在有效窗口内用过一次就不可再用（防重放），因此这里也覆盖
        # "刚绑定完/刚登录完又立刻提交同一个口令"的情形：提示刷新后重试，
        # 否则用户会以为是口令错了。
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "动态口令不正确或本次口令已被使用，请等待验证器刷新（约 30 秒）后重试")
    record_success(throttle_key)
    # 记录已用步长：同一口令在有效窗口内不能重放（RFC 6238 §5.2）
    user.totp_last_step = int(step)
    db.commit()
    return _session_response(
        db, user,
        f"口令+动态口令双因子通过（密级 {user.clearance}）"
        + ("；首次登录须修改初始口令" if user.must_change_password else ""),
        ip, request)


@router.post("/totp/setup")
def totp_setup(body: TotpSetupIn, request: Request,
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    """生成（或重新生成）待绑定的 TOTP 密钥。

    必须重新输入口令：只有会话没有口令的攻击者不能替受害者绑定第二因子。
    """
    ip = client_ip(request)
    if not cfg.MFA_ENABLED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "动态口令功能未启用")
    if not verify_password(body.password, user.pwd_hash, user.salt):
        write_log(db, user=user, action="mfa_setup", decision="deny",
                  reason="口令校验失败", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "口令不正确")
    if totp.is_enrolled(user):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "已绑定动态口令，如需更换请先解绑")
    if not totp.encryption_ready():
        logger.error("未配置 MFA_SECRET_KEY/JWT_SECRET，拒绝绑定 TOTP")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "服务端未配置动态口令加密密钥（MFA_SECRET_KEY），无法绑定")
    secret = totp.generate_secret()
    try:
        user.totp_secret = totp.seal(secret)
    except RuntimeError as exc:
        logger.error("TOTP 密钥加密失败：%s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "动态口令密钥存储失败，请检查 MFA_SECRET_KEY")
    user.totp_confirmed_at = None
    user.totp_last_step = 0
    db.commit()
    write_log(db, user=user, action="mfa_setup", decision="allow",
              reason="生成待绑定的动态口令密钥", ip=ip)
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, user.username),
        "issuer": cfg.TOTP_ISSUER,
        "digits": cfg.TOTP_DIGITS,
        "period": cfg.TOTP_PERIOD,
    }


@router.post("/totp/confirm")
def totp_confirm(body: TotpConfirmIn, request: Request,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    """验一次动态口令才把账号标为"已绑定"。"""
    ip = client_ip(request)
    if not cfg.MFA_ENABLED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "动态口令功能未启用")
    if totp.is_enrolled(user):
        raise HTTPException(status.HTTP_409_CONFLICT, "已绑定动态口令")
    if not user.totp_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "请先生成动态口令密钥")
    try:
        secret = totp.unseal(user.totp_secret)
    except RuntimeError as exc:
        logger.error("TOTP 密钥不可用（user=%s）：%s", user.username, exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "动态口令密钥不可用，请重新生成")
    step = totp.verify(secret, body.code, last_step=int(user.totp_last_step or 0))
    if step is None:
        write_log(db, user=user, action="mfa_setup", decision="deny",
                  reason="绑定校验失败：动态口令不正确", ip=ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "动态口令不正确，请确认手机时间自动同步后重试")
    user.totp_confirmed_at = datetime.utcnow()
    user.totp_last_step = int(step)
    # 绑定成功即自动发一组恢复码，并在本次响应里一次性返回明文。
    # 为什么绑定时就发：用户此刻正好在"设置第二因子"的心智里，最容易
    # 把码存好；否则事后很少有人回来点"生成恢复码"。
    codes: list[str] = []
    if cfg.RECOVERY_CODE_ENABLED and recovery.available():
        codes, user.recovery_codes = recovery.generate()
    db.commit()
    write_log(db, user=user, action="mfa_setup", decision="allow",
              reason="动态口令绑定成功" +
                     (f"，已发放 {len(codes)} 个一次性恢复码" if codes else ""),
              ip=ip)
    return {"ok": True, "mfa_enabled": True, "user": user_out(db, user),
            "recovery_codes": codes}


@router.post("/recovery-codes/regenerate")
def regenerate_recovery_codes(body: RecoveryRegenerateIn, request: Request,
                              user: User = Depends(current_user),
                              db: Session = Depends(get_db)):
    """重新生成一组恢复码（旧码库整组作废，明文只返回这一次）。"""
    ip = client_ip(request)
    if not cfg.RECOVERY_CODE_ENABLED:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "本系统未启用恢复码")
    if not verify_password(body.password, user.pwd_hash, user.salt):
        write_log(db, user=user, action="recovery_regenerate", decision="deny",
                  reason="口令校验失败", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "口令不正确")
    if not totp.is_enrolled(user):
        # 未绑定第二因子时恢复码毫无意义（只有一道口令），发了反而是安全负债
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "请先绑定动态口令，再生成恢复码")
    if not recovery.available():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "服务端未配置恢复码密钥（MFA_SECRET_KEY），无法生成")
    old_left = recovery.remaining(user.recovery_codes)
    codes, user.recovery_codes = recovery.generate()
    db.commit()
    write_log(db, user=user, action="recovery_regenerate", decision="allow",
              reason=f"重新生成 {len(codes)} 个恢复码（旧码作废，"
                     f"作废前剩余 {old_left} 个）", ip=ip)
    return {"recovery_codes": codes, "remaining": len(codes),
            "user": user_out(db, user)}


@router.post("/totp/disable")
def totp_disable(body: TotpDisableIn, request: Request,
                 user: User = Depends(current_user), db: Session = Depends(get_db)):
    """解绑第二因子（同样要求口令再验，防"拿到会话就能关掉 MFA"）。"""
    ip = client_ip(request)
    if not verify_password(body.password, user.pwd_hash, user.salt):
        write_log(db, user=user, action="mfa_disable", decision="deny",
                  reason="口令校验失败", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "口令不正确")
    user.totp_secret = ""
    user.totp_confirmed_at = None
    user.totp_last_step = 0
    # 恢复码是第二因子的替代凭证：第二因子都不存在了，留着就是绕过新
    # 验证器的后门，必须一并清除。
    dropped = recovery.remaining(user.recovery_codes)
    user.recovery_codes = ""
    db.commit()
    write_log(db, user=user, action="mfa_disable", decision="allow",
              reason="账号主动解绑动态口令" +
                     (f"，同时作废 {dropped} 个未使用恢复码" if dropped else ""),
              ip=ip)
    return {"ok": True, "mfa_enabled": False, "user": user_out(db, user)}


# ---------------- OIDC 单点登录 ----------------

def _sso_error_redirect(code: str) -> RedirectResponse:
    # 错误码走 URL fragment，不把 IdP 原始报文（可能含内部地址）带进浏览器
    resp = RedirectResponse("/#/login?sso_error=" + quote(code, safe=""),
                            status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(OIDC_STATE_COOKIE, path="/")
    return resp


@router.get("/oidc/start")
def oidc_start(request: Request):
    """302 到 IdP 授权端点（state 同时写 HttpOnly cookie 做浏览器绑定）。"""
    if not oidc.enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "单点登录未启用")
    try:
        state, url = oidc.begin(request)
    except oidc.OidcError as exc:
        logger.error("OIDC 授权初始化失败：%s", exc.detail)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "单点登录暂不可用，请稍后重试或使用账号口令登录")
    resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        OIDC_STATE_COOKIE, state,
        max_age=oidc.STATE_TTL_MINUTES * 60, httponly=True,
        samesite="lax", path="/", secure=_secure_cookie(request),
    )
    return resp


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str = "", state: str = "",
                  error: str = "", db: Session = Depends(get_db)):
    """IdP 回调：校验 state/cookie → 换令牌 → 验 id_token → 映射用户。

    成功后不直接把访问令牌放进 URL，而是种一个 2 分钟的一次性交接
    票据，SPA 再用 POST /auth/oidc/session 换取（令牌不进日志与历史记录）。
    """
    if not oidc.enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "单点登录未启用")
    ip = client_ip(request)
    try:
        if error:
            raise oidc.OidcError("idp_error", f"IdP 返回错误：{error}")
        cookie_state = request.cookies.get(OIDC_STATE_COOKIE) or ""
        if not code or not state:
            raise oidc.OidcError("callback_invalid", "缺少 code 或 state")
        if not cookie_state or not hmac.compare_digest(cookie_state, state):
            raise oidc.OidcError("state_mismatch", "state 与浏览器 cookie 不一致")
        try:
            payload = decode_purpose(state, "oidc_state")
        except HTTPException as exc:
            raise oidc.OidcError("state_invalid", str(exc.detail)) from exc
        token_body = oidc.exchange_code(code, payload.get("verifier", ""),
                                        payload.get("redirect_uri", ""))
        claims = oidc.verify_id_token(token_body["id_token"],
                                      payload.get("nonce", ""))
        user = oidc.map_user(db, claims)
        # IdP claim → 本地角色/密级同步（默认关；白名单 + 密级上限，见 idp_sync）。
        # 放在"登录成功"审计之前：严格模式下 claim 越界会抛 OidcError，
        # 此时不该留下一条 allow 记录。
        sync = idp_sync.apply(db, user, claims)
        write_log(db, user=user, action="login_sso", decision="allow",
                  reason=f"OIDC 单点登录（sub={claims.get('sub')}）", ip=ip)
        if sync.get("changed"):
            bits = []
            if sync["roles_added"]:
                bits.append("授权角色 " + "/".join(sync["roles_added"]))
            if sync["roles_removed"]:
                bits.append("收回角色 " + "/".join(sync["roles_removed"]))
            if sync["clearance_from"] != sync["clearance_to"]:
                bits.append(f"密级 {sync['clearance_from']}→{sync['clearance_to']}")
            write_log(db, user=user, action="idp_claim_sync", decision="allow",
                      target_id=user.id, target_label=user.username,
                      reason="IdP claim 同步：" + "；".join(bits),
                      detail=json.dumps({"claim_roles": sync.get("claim_roles", [])},
                                        ensure_ascii=False),
                      ip=ip)
    except oidc.OidcError as exc:
        logger.warning("OIDC 回调失败 code=%s detail=%s", exc.code, exc.detail)
        write_log(db, action="login_sso", decision="deny",
                  reason=f"单点登录失败：{exc.code}", ip=ip)
        return _sso_error_redirect(exc.code)
    resp = RedirectResponse("/#/sso", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        OIDC_HANDOFF_COOKIE, oidc.create_handoff(user),
        max_age=oidc.HANDOFF_TTL_MINUTES * 60, httponly=True,
        samesite="lax", path="/", secure=_secure_cookie(request),
    )
    resp.delete_cookie(OIDC_STATE_COOKIE, path="/")
    return resp


@router.post("/oidc/session")
def oidc_session(request: Request, db: Session = Depends(get_db)):
    """用回调种下的一次性交接票据换取正式会话（前端 /#/sso 调用）。"""
    if not oidc.enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "单点登录未启用")
    raw = request.cookies.get(OIDC_HANDOFF_COOKIE)
    if not raw:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "没有可用的单点登录凭据")
    payload = decode_purpose(raw, "sso_handoff")
    user = db.get(User, payload.get("sub"))
    if user is None or not user.status:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "账号不存在或已停用")
    if int(payload.get("ver", 0)) != int(user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话已失效，请重新登录")
    write_log(db, user=user, action="login_sso", decision="allow",
              reason="单点登录交接票据换取会话", ip=client_ip(request))
    sess = open_session(db, user, ip=client_ip(request),
                        ua=request.headers.get("user-agent", ""))
    token = create_token(user, sess.sid)
    payload = {
        "user": user_out(db, user),
        "must_change_password": bool(user.must_change_password),
        "session_id": sess.sid,
        "token": None if cfg.AUTH_COOKIE_MODE else token,
    }
    if cfg.AUTH_COOKIE_MODE:
        payload["csrf_required"] = True
    resp = _session_json(payload, token, request)
    resp.delete_cookie(OIDC_HANDOFF_COOKIE, path="/")
    return resp


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request,
                    user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """改密入口（首登强制 / 主动更换共用）。

    成功后 token_version +1：改密前签发的令牌全部立即失效，只把新令牌
    返回给当前会话——否则"口令泄露后改密"对已登录的攻击者毫无作用。
    """
    ip = client_ip(request)
    if not verify_password(body.old_password, user.pwd_hash, user.salt):
        write_log(db, user=user, action="change_password", decision="deny",
                  reason="原口令校验失败", ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "原口令不正确")
    try:
        validate_password(body.new_password, user.username, body.old_password)
    except PasswordPolicyError as e:
        write_log(db, user=user, action="change_password", decision="deny",
                  reason=f"策略拒绝：{e}", ip=ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    was_forced = bool(user.must_change_password)
    user.pwd_hash, user.salt = hash_password(body.new_password)
    user.must_change_password = False
    user.token_version = int(user.token_version or 0) + 1
    db.commit()
    # 改密后**所有**旧会话一律吊销（含当前这条：它对应的令牌已随代次失效），
    # 随后为当前设备重开一条新会话——这样"我的设备"列表里不会残留已死会话。
    revoked = revoke_user_sessions(db, user.id, reason="password_changed")
    write_log(db, user=user, action="change_password", decision="allow",
              reason=("首次登录完成强制改密" if was_forced else "主动修改口令")
              + "，旧会话已全部失效", ip=ip)
    sess = open_session(db, user, ip=ip, ua=request.headers.get("user-agent", ""))
    token = create_token(user, sess.sid)
    payload = {"user": user_out(db, user), "must_change_password": False,
               "session_id": sess.sid,
               "revoked_sessions": revoked,
               "token": None if cfg.AUTH_COOKIE_MODE else token}
    return _session_json(payload, token, request)


@router.get("/me")
def me(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return user_out(db, user)


def _session_out(row) -> dict:
    return {
        "id": row.sid,
        "created_at": row.created_at.strftime("%Y-%m-%d %H:%M:%S") if row.created_at else "",
        "last_seen_at": row.last_seen_at.strftime("%Y-%m-%d %H:%M:%S") if row.last_seen_at else "",
        "ip": row.ip or "",
        "user_agent": row.user_agent or "",
        "current": False,
    }


@router.get("/sessions")
def my_sessions(request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    """当前账号的有效登录设备（供"发现陌生设备→踢掉"）。"""
    cur = getattr(request.state, "sid", None)
    rows = [_session_out(r) for r in active_sessions(db, user)]
    for r in rows:
        r["current"] = bool(cur and r["id"] == cur)
    return rows


@router.post("/sessions/{sid}/revoke")
def revoke_my_session(sid: str, request: Request,
                      user: User = Depends(current_user),
                      db: Session = Depends(get_db)):
    """踢掉自己的某一台设备（单端吊销）。他人的会话只能由管理员踢。"""
    row = db.get(AuthSession, sid)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "会话不存在")
    revoke_session(db, sid, reason="user_revoked")
    write_log(db, user=user, action="session_revoke", decision="allow",
              target_label=sid, reason="用户主动吊销该设备会话",
              ip=client_ip(request))
    return {"ok": True}


@router.post("/logout")
def logout(request: Request, user: User = Depends(current_user),
           db: Session = Depends(get_db)):
    """登出：只吊销当前这台设备的会话，其余设备不受影响（P0-4 单端语义）。

    需要"全部设备下线"时调用 /auth/logout/all（会换代次 token_version）。
    """
    sid = getattr(request.state, "sid", None)
    revoke_session(db, sid, reason="logout") if sid else None
    write_log(db, user=user, action="logout", decision="allow",
              ip=client_ip(request))
    resp = JSONResponse({"ok": True})
    clear_session_cookies(resp)
    return resp


@router.post("/logout/all")
def logout_all(request: Request, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    """全部设备下线（令牌换代次 + 会话表批量吊销）。"""
    n = revoke_user_sessions(db, user.id, reason="logout_all")
    user.token_version = int(user.token_version or 0) + 1
    db.commit()
    write_log(db, user=user, action="logout", decision="allow",
              reason=f"全部设备下线（吊销 {n} 个会话）", ip=client_ip(request))
    resp = JSONResponse({"ok": True, "revoked": n})
    clear_session_cookies(resp)
    return resp
