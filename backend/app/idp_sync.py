# SPDX-License-Identifier: AGPL-3.0-only
"""IdP claim → 本地角色/密级同步（默认关闭，白名单映射，安全上限硬编码）。

为什么要默认关：
  权限以本地为准，IdP 侧一次误配置（把全公司塞进 `fin_admin`、或把外部
  协作方标成 `secret`）就等于放大数据可见面。SSO 只该回答"你是谁"，
  "你能看什么"仍由本地管理员决定。

开启后的硬约束（都在这里实现，不依赖调用方自觉）：
  1. **白名单**：claim 值必须命中 OIDC_ROLE_MAP / OIDC_CLEARANCE_MAP；
  2. **密级上限**：claim 只能把密级抬到 OIDC_CLAIM_SYNC_MAX_CLEARANCE
     （默认 1=内部），绝密必须由本地管理员显式授予；且只增不降；
  3. **admin 例外**：映射表里写了 admin 也要额外开关
     OIDC_CLAIM_SYNC_ALLOW_ADMIN=true 才生效；本地已授的 admin 不会被
     同步抹掉（否则一次 IdP 配置疏忽就把唯一管理员锁在门外）；
  4. **claim 缺失 ≠ 收权**：IdP 没发这个 claim（scope 未授权/字段改名）时
     完全不动本地权限；只有 claim **存在**时才按映射表对齐（此时缺省值
     就是"收回"，这是 IdP 主动表达"这个人不再有该角色"的唯一途径）。
  5. **密级撤权口径可配**（OIDC_CLAIM_SYNC_MODE）：union（默认）只升不降，
     撤权必须走本地双人复核；authoritative 允许 IdP 撤权，但只回落到
     **同步前的本地基线**（users.idp_clearance_base），本地另行授予的更高
     密级不会被抹掉。溯源见 _clearance_base()。

返回 diff 供调用方写审计：没有变化时 changed=False，不产生审计噪音。
"""
from __future__ import annotations

import json

from . import config as cfg

# 与 policy/模型一致的密级区间（0公开 1内部 2机密 3绝密）
_MIN_CLEARANCE, _MAX_CLEARANCE = 0, 3


def _parse_map(raw: str, value_cast=str) -> dict[str, object]:
    """"a:b,c:d" → {"a": b, "c": d}；空项/畸形项直接跳过（配置错误不该 500）。"""
    out: dict[str, object] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        key, val = item.split(":", 1)
        key, val = key.strip(), val.strip()
        if not key or not val:
            continue
        try:
            out[key] = value_cast(val)
        except (TypeError, ValueError):
            continue
    return out


def _claim_list(claims: dict, name: str) -> list[str]:
    """claim 可能是字符串（空格/逗号分隔）、数组；缺失返回 []。"""
    raw = claims.get(name)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [x for x in raw.replace(",", " ").split() if x]
    if isinstance(raw, (list, tuple, set)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [str(raw).strip()]


def _int_attr(user, name: str, default: int) -> int:
    """读取整数列，兼容"列尚未迁移/对象未刷新"（None 按 default 处理）。"""
    raw = getattr(user, name, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _clearance_base(user) -> int:
    """同步前的本地密级基线（authoritative 撤权的下界）。

    没有溯源时会陷入两难：只升不降 = IdP 侧离岗收权永远不生效；无条件
    覆盖 = 本地管理员按审批授予的更高密级被 IdP 一次误配抹掉。基线把
    "哪一截是 IdP 抬上去的"记下来：撤权只回落到基线。

    本地改过密级（当前值 ≠ max(基线, 上次同步值)）→ 以当前值为新基线，
    视为本地已重新定调。
    """
    current = _int_attr(user, "clearance", 0)
    base = _int_attr(user, "idp_clearance_base", -1)
    synced = _int_attr(user, "idp_clearance_synced", 0)
    if base < 0:
        return current
    if current != max(base, synced):
        return current
    return base


def plan(claims: dict, user) -> dict:
    """计算应写入的角色/密级（纯函数，不碰库，便于单测与输出 diff）。

    roles=None 表示"IdP 没发这个 claim，别动本地角色"。
    clearance=None 表示"IdP 没发这个 claim，别动本地密级"。
    clearance_base / clearance_synced 仅在 claim 存在时非空，供 apply 落库溯源。
    """
    role_map = _parse_map(cfg.OIDC_ROLE_MAP)
    clearance_map = _parse_map(cfg.OIDC_CLEARANCE_MAP, int)
    unknown: list[str] = []

    roles: list[str] | None = None
    if cfg.OIDC_ROLE_CLAIM in claims:
        roles = []
        for name in _claim_list(claims, cfg.OIDC_ROLE_CLAIM):
            if name not in role_map:
                if cfg.OIDC_CLAIM_SYNC_UNKNOWN == "deny":
                    unknown.append(f"{cfg.OIDC_ROLE_CLAIM}={name}")
                continue
            local = str(role_map[name])
            if local == "admin" and not cfg.OIDC_CLAIM_SYNC_ALLOW_ADMIN:
                # 映射表写了 admin 但开关没开：忽略（不拒绝登录，
                # 否则一次配置疏忽会把管理员锁在门外）
                continue
            if local not in roles:
                roles.append(local)

    clearance = None
    clearance_base = None
    clearance_synced = None
    if cfg.OIDC_CLEARANCE_CLAIM and cfg.OIDC_CLEARANCE_CLAIM in claims:
        level = None
        for v in _claim_list(claims, cfg.OIDC_CLEARANCE_CLAIM):
            if v in clearance_map:
                cand = int(clearance_map[v])
                level = cand if level is None else max(level, cand)
            elif cfg.OIDC_CLAIM_SYNC_UNKNOWN == "deny":
                unknown.append(f"{cfg.OIDC_CLEARANCE_CLAIM}={v}")
        if level is not None:
            level = max(_MIN_CLEARANCE,
                        min(_MAX_CLEARANCE,
                            min(level, cfg.OIDC_CLAIM_SYNC_MAX_CLEARANCE)))
            current = _int_attr(user, "clearance", 0)
            raw_base = _int_attr(user, "idp_clearance_base", -1)
            base = _clearance_base(user)
            synced_prev = _int_attr(user, "idp_clearance_synced", 0)
            authoritative = cfg.OIDC_CLAIM_SYNC_MODE == "authoritative"
            if authoritative:
                # 撤权口径：IdP 说多少就是多少，但不低于本地基线——
                # 基线以上的部分本来就不是同步给的。
                clearance = max(base, level)
            else:
                # 只增不降：claim 不能把本地已授的高密级拉下来
                clearance = max(current, level)
            # 溯源只在两种情况下落库：claim 真的抬升了密级；或已有溯源
            # 需要跟着 claim 更新（否则下次撤权会拿着过期基线判断）。
            # "claim 值本来就等于本地值"的空跑不写、不报变化，免审计噪音。
            if level > current or (raw_base >= 0 and level != synced_prev):
                clearance_base = base
                clearance_synced = level

    return {
        "roles": roles, "clearance": clearance, "unknown": unknown,
        "clearance_base": clearance_base, "clearance_synced": clearance_synced,
    }


def apply(db, user, claims: dict) -> dict:
    """按 plan 落库，返回 diff（changed=False 表示无需审计）。

    未开启同步时直接返回 {"enabled": False, "changed": False}，不读任何 claim。
    """
    if not cfg.OIDC_CLAIM_SYNC:
        return {"enabled": False, "changed": False}
    result = plan(claims, user)
    if result["unknown"] and cfg.OIDC_CLAIM_SYNC_UNKNOWN == "deny":
        from .oidc import OidcError
        raise OidcError(
            "claim_sync_rejected",
            f"claim 出现白名单外的取值：{', '.join(result['unknown'])}")

    current_roles = list(user.role_list())
    target_roles = list(current_roles)
    if result["roles"] is not None:
        mapped = set(result["roles"])
        # 本地已授的 admin 保留：撤销管理员必须由本地管理员操作
        if "admin" in current_roles:
            mapped.add("admin")
        target_roles = sorted(mapped)

    added = [r for r in target_roles if r not in current_roles]
    removed = [r for r in current_roles if r not in target_roles]
    old_clearance = int(getattr(user, "clearance", 0) or 0)
    new_clearance = result["clearance"]
    clearance_changed = new_clearance is not None and new_clearance != old_clearance
    # 溯源也需要落库：即使本次密级没变，也要记下"基线/上次同步值"，
    # 否则将来的 IdP 撤权无法判断该降到哪一档。
    prov_base = result["clearance_base"]
    prov_synced = result["clearance_synced"]
    prov_changed = (
        prov_synced is not None
        and (_int_attr(user, "idp_clearance_base", -1) != int(prov_base)
             or _int_attr(user, "idp_clearance_synced", 0) != int(prov_synced))
    )

    changed = bool(added or removed or clearance_changed or prov_changed)
    if changed:
        user.roles = json.dumps(sorted(target_roles), ensure_ascii=False)
        if clearance_changed:
            user.clearance = int(new_clearance)
        if prov_synced is not None:
            user.idp_clearance_base = int(prov_base)
            user.idp_clearance_synced = int(prov_synced)
        db.commit()
    return {
        "enabled": True,
        "changed": changed,
        "roles_added": added,
        "roles_removed": removed,
        "clearance_from": old_clearance,
        "clearance_to": int(user.clearance or 0),
        "clearance_mode": cfg.OIDC_CLAIM_SYNC_MODE,
        # 本次同步落下的溯源（未落库时给 None，避免把"旧值"说成"本次结果"）
        "clearance_base": prov_base,
        "clearance_synced": prov_synced,
        "claim_roles": _claim_list(claims, cfg.OIDC_ROLE_CLAIM),
    }
