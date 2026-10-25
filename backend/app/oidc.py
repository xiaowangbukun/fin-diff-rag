# SPDX-License-Identifier: AGPL-3.0-only
"""OIDC 单点登录（授权码 + PKCE），对接企业 IdP。

设计取舍：
  · 只用标准三件套（discovery / JWKS / token endpoint），不写任何 IdP
    专属逻辑——Keycloak、Azure AD、Okta、飞书（OIDC 模式）都按同一路径接。
  · 校验 id_token 走 PyJWT 的 JWKS 验签：iss / aud / exp / nonce 全查，
    算法白名单只允许非对称签名（禁 HS* 与 none，防算法混淆）。
  · state 用签名 JWT 承载 PKCE verifier 与 nonce，浏览器侧再用 HttpOnly
    cookie 绑一次：没有 cookie 的回调（登录 CSRF）直接拒。
  · 回调不在 URL 里吐会话令牌，而是换成一次性交接票据（HttpOnly cookie
    + 2 分钟过期），由 SPA 调 POST /auth/oidc/session 换取，令牌不进
    浏览器历史/Referer/访问日志。

本模块只做协议 + 用户映射（map_user 是唯一写库处），不碰权限判定。
"""
import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import config as cfg
from .security import sign_purpose

# id_token 允许的签名算法：只收非对称算法。HS256 会让"用 client_secret
# 当 HMAC 密钥"的算法混淆攻击成立；none 更不用说。
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512")

STATE_TTL_MINUTES = 10
HANDOFF_TTL_MINUTES = 2


class OidcError(Exception):
    """协议/映射失败。code 直接进前端提示，不携带 IdP 原始报文。"""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ---------------- 配置与元数据缓存 ----------------

def enabled() -> bool:
    return bool(cfg.OIDC_ENABLED)


def require_config() -> None:
    """启动期校验：开了 OIDC 就必须有 issuer 与 client_id。

    与 require_database_url / require_embedding_key 同口径——导入期不校验，
    启动期拒绝，避免"配置半截就对外服务、登录页挂个永远 404 的按钮"。
    """
    if not enabled():
        return
    missing = [k for k, v in (("OIDC_ISSUER", cfg.OIDC_ISSUER),
                              ("OIDC_CLIENT_ID", cfg.OIDC_CLIENT_ID)) if not v]
    if missing:
        raise RuntimeError(
            "拒绝启动：OIDC_ENABLED=true 但缺少 " + "、".join(missing)
            + "。请补齐 issuer 与 client_id（回调地址可由请求推导，"
              "但生产建议显式配置 OIDC_REDIRECT_URI）。"
        )


_cache: dict[str, tuple[float, dict]] = {}


def _cache_get(key: str):
    hit = _cache.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > cfg.OIDC_METADATA_TTL:
        _cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value: dict) -> None:
    _cache[key] = (time.time(), value)


def clear_cache() -> None:
    _cache.clear()


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=cfg.OIDC_HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OidcError("idp_unavailable", f"拉取 {url} 失败：{exc}") from exc


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.OIDC_HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # 只回状态码，不回 IdP 正文（可能含 client_secret 回显/内部地址）
        raise OidcError("token_exchange_failed", f"token endpoint HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OidcError("idp_unavailable", f"交换令牌失败：{exc}") from exc


def discovery() -> dict:
    cached = _cache_get("discovery")
    if cached:
        return cached
    doc = _fetch_json(cfg.OIDC_ISSUER + "/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not doc.get(key):
            raise OidcError("idp_metadata_invalid", f"发现文档缺少 {key}")
    if str(doc["issuer"]).rstrip("/") != cfg.OIDC_ISSUER:
        # issuer 不一致是典型的"发现文档被指向别的租户"信号，必须拒
        raise OidcError("idp_metadata_invalid", "发现文档 issuer 与配置不一致")
    _cache_put("discovery", doc)
    return doc


def jwks() -> list[dict]:
    cached = _cache_get("jwks")
    if cached:
        return cached["keys"]
    doc = _fetch_json(discovery()["jwks_uri"])
    keys = doc.get("keys") or []
    if not keys:
        raise OidcError("idp_metadata_invalid", "JWKS 为空")
    _cache_put("jwks", {"keys": keys})
    return keys


# ---------------- 授权请求 ----------------

def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).decode().rstrip("=")
    return verifier, challenge


def redirect_uri(request=None) -> str:
    if cfg.OIDC_REDIRECT_URI:
        return cfg.OIDC_REDIRECT_URI
    if request is None:
        raise OidcError("config_invalid", "未配置 OIDC_REDIRECT_URI 且无请求上下文")
    # 单域名部署推导；反向代理场景请显式配置，避免 http/https、内网域名错位
    return str(request.base_url).rstrip("/") + "/api/auth/oidc/callback"


def begin(request=None) -> tuple[str, str]:
    """返回 (state JWT, 授权端点 URL)。state 里带 PKCE verifier 与 nonce。"""
    verifier, challenge = _pkce_pair()
    nonce = secrets.token_urlsafe(24)
    uri = redirect_uri(request)
    state = sign_purpose(
        {"purpose": "oidc_login", "verifier": verifier, "nonce": nonce,
         "redirect_uri": uri},
        typ="oidc_state", minutes=STATE_TTL_MINUTES,
    )
    doc = discovery()
    params = {
        "response_type": "code",
        "client_id": cfg.OIDC_CLIENT_ID,
        "redirect_uri": uri,
        "scope": cfg.OIDC_SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = doc["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)
    return state, url


# ---------------- 回调与令牌校验 ----------------

def _jwk_for(kid: str | None, alg: str):
    keys = jwks()
    candidates = [k for k in keys if k.get("use") in (None, "sig")]
    if kid:
        candidates = [k for k in candidates if k.get("kid") == kid] or candidates
    candidates = [k for k in candidates if k.get("alg") in (None, alg)]
    if not candidates:
        raise OidcError("id_token_invalid", "JWKS 中没有匹配的签名密钥")
    last: Exception | None = None
    for jwk in candidates:
        try:
            return jwt.PyJWK(jwk).key
        except Exception as exc:  # noqa: BLE001 尝试下一个候选
            last = exc
    raise OidcError("id_token_invalid", f"无法解析 JWKS 密钥：{last}")


def verify_id_token(id_token: str, nonce: str) -> dict:
    """验签 + iss/aud/exp/nonce 校验，返回 claims。"""
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:
        raise OidcError("id_token_invalid", "id_token 结构非法") from exc
    alg = header.get("alg", "")
    if alg not in ALLOWED_ALGS:
        raise OidcError("id_token_invalid", f"不接受的签名算法：{alg}")
    key = _jwk_for(header.get("kid"), alg)
    try:
        claims = jwt.decode(
            id_token, key, algorithms=[alg],
            audience=cfg.OIDC_CLIENT_ID, issuer=cfg.OIDC_ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OidcError("id_token_invalid", f"id_token 校验失败：{exc}") from exc
    if str(claims.get("nonce") or "") != nonce:
        raise OidcError("id_token_invalid", "nonce 不匹配（疑似重放）")
    return claims


def exchange_code(code: str, verifier: str, uri: str) -> dict:
    doc = discovery()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": uri,
        "client_id": cfg.OIDC_CLIENT_ID,
        "code_verifier": verifier,
    }
    if cfg.OIDC_CLIENT_SECRET:
        data["client_secret"] = cfg.OIDC_CLIENT_SECRET
    body = _post_form(doc["token_endpoint"], data)
    if not body.get("id_token"):
        raise OidcError("token_exchange_failed", "token 响应缺少 id_token")
    return body


# ---------------- 登录交接 ----------------

def create_handoff(user) -> str:
    return sign_purpose(
        {"sub": user.id, "ver": int(user.token_version or 0), "method": "oidc"},
        typ="sso_handoff", minutes=HANDOFF_TTL_MINUTES,
    )


# ---------------- 用户映射 ----------------

def _default_roles() -> list[str]:
    return [r.strip() for r in (cfg.OIDC_DEFAULT_ROLES or "").split(",") if r.strip()]


def map_user(db, claims: dict):
    """把 id_token claims 映射成本地 User（必要时绑定 sub / 即时建号）。

    匹配顺序：oidc_subject → username claim。优先用 sub 是因为 IdP 侧
    用户改名/换登录名后 username 会漂移，sub 不会。
    失败一律抛 OidcError（code 给前端，detail 只进服务端日志）。
    """
    from .models import User

    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise OidcError("id_token_invalid", "id_token 缺少 sub")
    username = str(claims.get(cfg.OIDC_USERNAME_CLAIM) or "").strip()

    user = db.execute(
        select(User).where(User.oidc_subject == subject)).scalar_one_or_none()
    if user is None:
        if not username:
            raise OidcError(
                "account_not_provisioned",
                f"id_token 缺少 {cfg.OIDC_USERNAME_CLAIM} claim，无法匹配本地账号")
        user = db.execute(
            select(User).where(User.username == username)).scalar_one_or_none()
        if user is None:
            if not cfg.OIDC_JIT_PROVISION:
                # 默认行为：账号必须先由管理员建好，SSO 只做认证
                raise OidcError("account_not_provisioned",
                                f"本地不存在账号 {username}")
            user = User(
                username=username,
                display_name=str(claims.get("name") or username)[:64],
                roles=json.dumps(_default_roles(), ensure_ascii=False),
                clearance=cfg.OIDC_DEFAULT_CLEARANCE,
                pwd_hash="", salt="",   # 无本地口令：只能走 SSO
                status=True, must_change_password=False,
                oidc_subject=subject,
            )
            db.add(user)
            try:
                db.commit()
            except IntegrityError:
                # 并发首登撞唯一约束：回滚后按 username 重查，避免 500
                db.rollback()
                user = db.execute(
                    select(User).where(User.username == username)).scalar_one()
                if user.oidc_subject and user.oidc_subject != subject:
                    raise OidcError("subject_conflict", "账号已绑定其它 IdP 身份")
                user.oidc_subject = subject
                db.commit()
        else:
            if user.oidc_subject and user.oidc_subject != subject:
                raise OidcError("subject_conflict", "账号已绑定其它 IdP 身份")
            user.oidc_subject = subject
            db.commit()
    if not user.status:
        raise OidcError("user_disabled", "账号已停用")
    return user
