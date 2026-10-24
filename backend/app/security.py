# SPDX-License-Identifier: Apache-2.0
"""认证与鉴权基础：密码哈希、JWT、当前用户注入。"""
import hashlib
import hmac
import logging
import os
import warnings
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    ENFORCE_JWT_SECRET, JWT_EXPIRE_HOURS, JWT_SECRET, JWT_SECRET_OLD,
    LEGACY_ITERATIONS, MFA_CHALLENGE_MINUTES, PASSWORD_ITERATIONS,
)
from . import config as _cfg
from .db import get_db
from .models import User

# 改密前允许访问的端点（只够"看自己是谁 + 改密 + 登出"）。
# 用后缀匹配，避免被 /api、/api/v1 版本前缀写死。
MUST_CHANGE_ALLOWED_SUFFIXES = (
    "/auth/me", "/auth/change-password", "/auth/logout",
)

# 未绑定 TOTP 但被强制要求绑定时放行的端点：身份自查 + 绑定三件套 + 登出。
# 改密也放行——"先改初始口令、再绑动态口令"是自然顺序，别让两个闸互相卡死。
MFA_ALLOWED_SUFFIXES = (
    "/auth/me", "/auth/logout", "/auth/change-password",
    "/auth/totp/setup", "/auth/totp/confirm", "/auth/totp/disable",
)

bearer = HTTPBearer(auto_error=False)

logger = logging.getLogger("finrag.security")


def _resolve_secrets() -> list[str]:
    """解析签发/验证密钥列表（新的在前，旧的仅参与验证）。

    空密钥时的决策（P0-1）：拒绝启动 or 进程级随机密钥。
    默认生成随机密钥——"运维忘了改固定密钥"从安全事故降级为可用性问题
    （重启后重新登录），而不是留一个全网皆知的默认密钥等人来伪造。
    """
    secrets = [s for s in (JWT_SECRET, JWT_SECRET_OLD) if s]
    if secrets:
        return secrets
    if ENFORCE_JWT_SECRET:
        raise RuntimeError(
            "JWT_SECRET 未配置且 ENFORCE_JWT_SECRET=true，拒绝启动。"
            "请通过环境变量注入固定密钥（生产多 worker 部署必须）。"
        )
    warnings.warn(
        "JWT_SECRET 未配置，已生成进程级随机密钥（重启后失效，需重新登录）。"
        "生产部署请注入固定密钥。", RuntimeWarning, stacklevel=2,
    )
    # warnings.warn 面向开发者（测试可断言）；logger 面向运维日志管道——
    # 生产部署的告警要能被日志采集看到，pytest 的 warnings 捕获管不到那里。
    logger.warning(
        "JWT_SECRET 未配置，已生成进程级随机密钥（重启后失效，需重新登录）。"
        "生产部署请注入固定密钥；多 worker 部署必须固定密钥，否则各进程密钥不同"
        "会导致间歇性 401 且无法诊断。"
    )
    return [os.urandom(32).hex()]


_SECRETS = _resolve_secrets()


def _iterations_from(stored: str) -> tuple[int, str]:
    """解析 pwd_hash：新格式 `pbkdf2_sha256$<iter>$<hex>`；旧库存纯 hex。

    旧格式一律按 120k 验证（历史值就是 120k），并在下次登录成功时
    透明重算成新格式——不需要用户重置口令，也不会出现"升级后全员登不进"。
    """
    if stored and stored.startswith("pbkdf2_sha256$"):
        parts = stored.split("$")
        if len(parts) == 3 and parts[1].isdigit():
            return int(parts[1]), parts[2]
    return LEGACY_ITERATIONS, stored


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${dk.hex()}", salt


def verify_password(password: str, pwd_hash: str, salt: str) -> bool:
    iterations, expected = _iterations_from(pwd_hash or "")
    if not expected:
        return False
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), (salt or "").encode("utf-8"), iterations
    )
    return hmac.compare_digest(dk.hex(), expected)


def needs_rehash(pwd_hash: str) -> bool:
    """存量口令是否低于当前迭代强度（登录成功后透明升级）。"""
    iterations, expected = _iterations_from(pwd_hash or "")
    return bool(expected) and iterations < PASSWORD_ITERATIONS


def create_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "username": user.username,
        "ver": int(getattr(user, "token_version", 0) or 0),
        # typ 区分令牌用途：访问令牌与"待验动态口令"票据不能互换使用。
        # 老令牌没有该字段，校验时按 access 兼容（过渡期不踢存量会话）。
        "typ": "access",
        "exp": now + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": now,
    }
    return jwt.encode(payload, _SECRETS[0], algorithm="HS256")


def sign_purpose(payload: dict, typ: str, minutes: int) -> str:
    """签发短时、单一用途的票据（typ 写进 payload，校验侧强制比对）。

    用途：MFA 挑战票据（口令已过、等动态口令）、OIDC state（带 PKCE
    verifier 与 nonce）、OIDC 登录交接票据（回调 → SPA 取会话）。
    """
    now = datetime.now(timezone.utc)
    body = dict(payload)
    body.update({"typ": typ, "iat": now, "exp": now + timedelta(minutes=minutes)})
    return jwt.encode(body, _SECRETS[0], algorithm="HS256")


def decode_purpose(token: str, typ: str) -> dict:
    """校验用途票据；typ 不符/过期/签名错一律 401。"""
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "凭据已过期，请重新登录")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "凭据无效")
    if payload.get("typ") != typ:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "凭据用途不符")
    return payload


def create_mfa_challenge(user: User) -> str:
    return sign_purpose(
        {"sub": user.id, "ver": int(user.token_version or 0), "stage": "password_ok"},
        typ="mfa", minutes=MFA_CHALLENGE_MINUTES,
    )


def mfa_setup_required(user: User) -> bool:
    """是否必须绑定 TOTP 才能使用系统（服务端判定，前端只做展示）。"""
    if not _cfg.MFA_ENABLED or getattr(user, "totp_confirmed_at", None):
        return False
    # SSO 账号且信任 IdP 已做 MFA（Azure AD 条件访问、Keycloak 认证流程等）：
    # 本地不再叠加第二因子，否则同一人要被要求两次动态口令。
    if _cfg.OIDC_ENABLED and _cfg.OIDC_TRUST_IDP_MFA and getattr(
            user, "oidc_subject", ""):
        return False
    if _cfg.MFA_ENFORCE_ALL:
        return True
    return bool(_cfg.MFA_ENFORCE_ADMIN and "admin" in user.role_list())


def decode_token(token: str) -> dict:
    """多密钥验证：先试新密钥，再试过渡期旧密钥（轮换窗口内旧 token 不失效）。"""
    last_err: Exception | None = None
    for s in _SECRETS:
        try:
            return jwt.decode(token, s, algorithms=["HS256"])
        except Exception as e:  # noqa: BLE001  逐个尝试，收集最后一个错误
            last_err = e
    raise last_err  # type: ignore[misc]


def current_user(
    request: Request,
    cred: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "未登录")
    try:
        payload = decode_token(cred.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "登录已过期")
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "令牌无效")
    user = db.get(User, payload.get("sub"))
    if user is None or not user.status:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户不存在或已停用")
    # 用途隔离：MFA 挑战票据 / OIDC 交接票据不能当访问令牌用（缺失视为老令牌）
    if payload.get("typ") not in (None, "access"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "令牌用途不符")
    # 会话代次：改密/重置/登出会让旧令牌立刻失效，而不是等 12 小时过期
    if int(payload.get("ver", 0)) != int(user.token_version or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话已失效，请重新登录")
    # 强制改密闸门：只放行"看自己/改密/登出"，其余一律 403。
    # 做成服务端硬闸而不是前端弹窗——绕过前端直接调 API 同样进不来。
    if user.must_change_password and not request.url.path.endswith(
            MUST_CHANGE_ALLOWED_SUFFIXES):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "首次登录须先修改初始口令（POST /auth/change-password）",
            headers={"X-Must-Change-Password": "1"},
        )
    # 强制绑定动态口令闸门（MFA_ENFORCE_ADMIN / MFA_ENFORCE_ALL 开启时）：
    # 同样做服务端硬闸；未绑定只放行绑定相关端点。
    if mfa_setup_required(user) and not request.url.path.endswith(
            MFA_ALLOWED_SUFFIXES):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "须先绑定动态口令（POST /auth/totp/setup → /auth/totp/confirm）",
            headers={"X-MFA-Setup-Required": "1"},
        )
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if "admin" not in user.role_list():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "需要管理员权限")
    return user
