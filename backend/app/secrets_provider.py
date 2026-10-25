# SPDX-License-Identifier: Apache-2.0
"""密钥托管（P0-5）：把"口令/密钥只存在于 .env 明文"这一层拿掉。

金融机构的常见约束是：**密钥不得落在应用主机的配置文件里**，必须由 KMS /
Vault / 密封卷在启动时注入，且要有可审计的取值来源。本模块给出两个最小
可用的适配器，都不引入新依赖：

  · file：`SECRETS_DIR` 下的密封文件（KMS sidecar 挂载、Docker/K8s secret
    卷、systemd LoadCredential 都落到"一堆按名读取的文件"这个形态）。
    读取顺序：`<NAME>` → `<name>` → `<name 小写、下划线换中划线>`。
  · http：`GET {SECRETS_URL}/v1/secret/{name}`，Header 带
    `X-Vault-Token` / `Authorization: Bearer`。兼容两种响应体：
    `{"value": "..."}` 与 Vault KV v2 的 `{"data": {"value": "..."}}`。

取舍说明：
  · 解析优先级是 **托管源 > 环境变量/.env**。托管源配了却读不到某个密钥时
    *不*回落环境变量——否则"以为在托管、实际在用明文"这种半吊子状态会静默
    成立，正是要消灭的东西。只有托管源整体未配置时才用环境变量。
  · 文件内容支持 `NAME=value` 单行格式（密封文件里带 key 名，便于人工核对），
    其余按整文件内容当作值（去掉行首尾空白与结尾换行）。
  · HTTP 取值结果进程内缓存 `SECRETS_TTL` 秒；密钥轮换后最迟一个 TTL 生效
    （JWT 轮换有 JWT_SECRET_OLD 过渡，见 README）。
  · 不打印、不记日志任何取到的密钥值；启动期只报告"来源 + 命中的名字"。

应用侧只在**导入期**用它解析少数几个高危密钥（DATABASE_URL / JWT_SECRET /
MFA_SECRET_KEY / AUDIT_ANCHOR_HMAC_KEY / OIDC_CLIENT_SECRET / LLM_API_KEY /
EMBED_API_KEY），因此 provider 不可达时表现为**拒绝启动**而不是运行期间歇
失败——这是密钥托管应有的失败方式。
"""
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

_CACHE: dict[str, tuple[float, str]] = {}
# 每个密钥名最近一次解析命中的来源（env / file / http / default），
# 供启动期自检与 /api/health 展示——只报来源，不报值。
_PROVENANCE: dict[str, str] = {}

PROVIDERS = ("none", "file", "http")


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def provider_name() -> str:
    """当前托管源：auto 时按"先 file 后 http"探测配置，都没有则 none。"""
    raw = _env("SECRETS_PROVIDER", "auto").lower()
    if raw not in ("", "auto"):
        return raw if raw in PROVIDERS else "none"
    if _env("SECRETS_DIR"):
        return "file"
    if _env("SECRETS_URL"):
        return "http"
    return "none"


def reset_cache() -> None:
    _CACHE.clear()
    _PROVENANCE.clear()


def provenance() -> dict[str, str]:
    return dict(_PROVENANCE)


# ------------------------------------------------------------------ file

def _read_secret_file(name: str) -> str | None:
    root = _env("SECRETS_DIR")
    if not root:
        return None
    base = Path(root)
    candidates = [name, name.lower(), name.lower().replace("_", "-")]
    for cand in candidates:
        p = base / cand
        if not p.is_file():
            continue
        raw = p.read_text(encoding="utf-8").strip()
        if not raw:
            continue
        # 允许 `NAME=value` 单行格式：密封文件常把 key 名一起写进去，
        # 直接当值使用会把 "JWT_SECRET=xxx" 整串当成密钥（签名全错且难查）。
        if "=" in raw.splitlines()[0] and name.upper() in raw.splitlines()[0].upper():
            for line in raw.splitlines():
                if "=" in line and line.split("=", 1)[0].strip().upper() == name.upper():
                    value = line.split("=", 1)[1].strip().strip('"').strip("'")
                    return value or None
            return None
        return raw
    return None


# ------------------------------------------------------------------ http

def _http_get(url: str, timeout: float, token: str) -> str | None:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        req.add_header("X-Vault-Token", token)
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            import json
            doc = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if isinstance(doc, dict):
        if isinstance(doc.get("value"), str):
            return doc["value"]
        data = doc.get("data")
        if isinstance(data, dict) and isinstance(data.get("value"), str):
            return data["value"]
    return None


def _fetch_http(name: str) -> str | None:
    base = _env("SECRETS_URL").rstrip("/")
    if not base:
        return None
    timeout = float(_env("SECRETS_TIMEOUT", "5") or 5)
    token = _env("SECRETS_TOKEN", "")
    for suffix in (f"/v1/secret/{name}", f"/v1/secret/{name.lower()}"):
        value = _http_get(base + suffix, timeout, token)
        if value:
            return value
    return None


# ------------------------------------------------------------------ API

def fetch(name: str) -> str | None:
    """按当前托管源取值；未配置托管源或取不到时返回 None。"""
    provider = provider_name()
    if provider == "none":
        return None
    key = f"{provider}:{name}"
    ttl = float(_env("SECRETS_TTL", "300") or 300)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] <= ttl:
        return hit[1]
    value = _read_secret_file(name) if provider == "file" else _fetch_http(name)
    if not value:
        return None
    _CACHE[key] = (time.time(), value)
    return value


def resolve(name: str, default: str = "") -> str:
    """解析密钥值：托管源优先，未配置托管源时回落传入的默认值（环境变量/.env）。

    托管源已配置但**取不到**该密钥时返回空串而不是默认值：把"托管失败"
    暴露成启动期错误（见 require_provider），而不是悄悄用明文配置顶上。
    """
    provider = provider_name()
    if provider == "none":
        _PROVENANCE[name] = "env" if default else "default"
        return default
    value = fetch(name)
    if value:
        _PROVENANCE[name] = provider
        return value
    _PROVENANCE[name] = "missing"
    return ""


def require_provider(names: tuple[str, ...] = ("JWT_SECRET",)) -> None:
    """启动期自检：要求密钥确实来自托管源（REQUIRE_SECRETS_PROVIDER=true 时生效）。"""
    if _env("REQUIRE_SECRETS_PROVIDER", "false").lower() not in ("1", "true", "yes", "on"):
        return
    provider = provider_name()
    if provider == "none":
        raise RuntimeError(
            "拒绝启动：REQUIRE_SECRETS_PROVIDER=true 但未配置密钥托管源。"
            "请设置 SECRETS_DIR（密封文件目录）或 SECRETS_URL（KMS/Vault 网关）。"
        )
    missing = [n for n in names if _PROVENANCE.get(n) != provider]
    if missing:
        raise RuntimeError(
            f"拒绝启动：密钥托管源（{provider}）缺少 {', '.join(missing)}。"
            "托管源一旦启用就不再回落 .env，以免出现'以为在托管、实际在用明文'。"
        )
