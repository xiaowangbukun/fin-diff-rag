# SPDX-License-Identifier: Apache-2.0
"""审计锚点外置：把"链尾 (seq, hash)"写到数据库与应用磁盘之外的第三方。

为什么需要（对照 audit.py 的三层防线）：
  · 行内哈希链防改内容，seq 断档防删中间行，`data/audit_anchor.json` 防删尾行；
  · 但本地锚点与库同生共灭——拿到"库写 + 应用磁盘写"双权限的人可以
    同时重算全链并改写锚点文件，本地防线整体失效。

本模块把锚点按周期**追加**到一个应用无法回写的位置：
  · `AUDIT_ANCHOR_EXTERNAL_FILE`：只追加语义的挂载（WORM 卷 / 另一台主机
    的 NFS / 日志采集器落盘目录）。应用只 append，不重写、不删除。
  · `AUDIT_ANCHOR_URL`：POST 到独立日志网关/对象存储，网关侧一次写定。

每条锚点带 HMAC-SHA256 签名（密钥由 AUDIT_ANCHOR_HMAC_KEY 或 JWT_SECRET
派生），签名覆盖 seq/tail_hash/ts/host——网关或文件被换成别的系统的记录、
或被手工改数字，验签即暴露。签名只证明"这条锚点由本系统在某时刻发出"，
不证明发送者未作恶（那需要网关侧独立见证，属基础设施边界，README 已写明）。

故障行为：外置锚点写失败只告警、绝不影响主链路（审计写入是合规底线，
不能因外部 sink 挂掉而丢审计）；失败会在下一个周期重试。
"""
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

from . import config as cfg

logger = logging.getLogger("finrag.anchors")

INTERVAL = float(getattr(cfg, "AUDIT_ANCHOR_INTERVAL_SECONDS", 60))
_emit_lock = threading.Lock()
_last_emitted: tuple[int, float] = (0, 0.0)   # (seq, monotonic ts)


def _hmac_key() -> bytes:
    raw = (getattr(cfg, "AUDIT_ANCHOR_HMAC_KEY", "") or "").strip() \
        or (getattr(cfg, "JWT_SECRET", "") or "").strip()
    return hashlib.sha256(("finrag-audit-anchor|" + raw).encode("utf-8")).digest()


def key_id() -> str:
    """当前签名密钥的公开指纹（只用于区分"密钥轮换"与"记录被篡改"）。

    为什么需要它：轮换密钥后，历史记录必然验签失败。没有 key_id 时巡检只能
    报"bad_signature 激增"，运维无从判断是有人伪造锚点还是自己换过密钥——
    这类误报会让人逐渐忽略告警。带上 key_id 后可以分类：指纹不同 = 旧密钥
    下的记录（不可验证但可解释，仍不采信）；指纹相同却验签不过 = 真的被动过。
    key_id 是密钥摘要的前 12 位十六进制，不泄露密钥本身。
    """
    return hashlib.sha256(_hmac_key()).hexdigest()[:12]


def _sign(record: dict) -> str:
    body = json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(_hmac_key(), body, hashlib.sha256).hexdigest()


def _file_path() -> Path | None:
    raw = (getattr(cfg, "AUDIT_ANCHOR_EXTERNAL_FILE", "") or "").strip()
    return Path(raw) if raw else None


def _url() -> str:
    return (getattr(cfg, "AUDIT_ANCHOR_URL", "") or "").strip()


def enabled() -> bool:
    """是否配置了任一外置 sink（未配置时所有操作是空操作）。"""
    return bool(_file_path() or _url())


def startup_warning() -> str:
    """外置 sink 启用但没配独立 HMAC 密钥时，返回一句启动告警（否则空串）。

    为什么值得单独告警：密钥缺省时从 JWT_SECRET 派生。JWT 一旦轮换
    （`JWT_SECRET_OLD` → `JWT_SECRET`）或空密钥被随机化（进程级随机），
    历史外置记录会**全部验签失败**，而 `bad_signature` 计数会被运维当成
    "有人在伪造锚点"。实际只是密钥换了——这类误报最消耗信任。
    生产口径：sink 一处部署一份文件，且显式配置独立的
    `AUDIT_ANCHOR_HMAC_KEY`（不与 JWT 共用轮换周期）。
    """
    if not enabled():
        return ""
    if (getattr(cfg, "AUDIT_ANCHOR_HMAC_KEY", "") or "").strip():
        return ""
    return ("[SECURITY] 审计外置 sink 已启用但 AUDIT_ANCHOR_HMAC_KEY 为空："
            "签名密钥派生自 JWT_SECRET，JWT 轮换或空密钥随机化后历史记录将"
            "全部验签失败（巡检会显示 bad_signature 激增）。生产请显式配置"
            "独立密钥，并保证一个 sink 只服务一处部署。")


def snapshot(tail_hash: str, seq: int) -> dict:
    """构造一条待外发的锚点记录（含签名）。"""
    record = {
        "app": "finrag",
        "kind": "audit_anchor",
        "seq": int(seq),
        "tail_hash": tail_hash,
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "pid": os.getpid(),
        "key_id": key_id(),
    }
    record["sig"] = _sign({k: v for k, v in record.items() if k != "sig"})
    return record


def _post_json(url: str, record: dict, kind: str = "audit-anchor") -> bool:
    """POST 一条记录（锚点或审计行批次）；失败返回 False（调用方只告警）。"""
    import urllib.error
    import urllib.request

    body = json.dumps(record, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Finrag-Signature": record["sig"],
                 "X-Finrag-Kind": kind},
    )
    try:
        with urllib.request.urlopen(req, timeout=float(
                getattr(cfg, "AUDIT_ANCHOR_TIMEOUT", 5))) as r:
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("外置审计锚点推送失败（%s）：%s", url, exc)
        return False


def _append_file(path: Path, record: dict) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())   # 只追加 + 落盘：断电也不丢最后一条
        return True
    except OSError as exc:
        logger.warning("外置审计锚点写文件失败（%s）：%s", path, exc)
        return False


def emit(tail_hash: str, seq: int, force: bool = False) -> dict | None:
    """把当前链尾外发（按 INTERVAL 限频；seq 未变则跳过）。

    返回发出的 record（未发则 None）。任何异常不外抛：审计主链路不能被
    外部 sink 拖垮。
    """
    global _last_emitted
    if not enabled() or seq <= 0:
        return None
    now = time.monotonic()
    with _emit_lock:
        last_seq, last_ts = _last_emitted
        if not force and (seq <= last_seq or now - last_ts < INTERVAL):
            return None
        _last_emitted = (seq, now)
        record = snapshot(tail_hash, seq)
        ok_file = _append_file(_file_path(), record) if _file_path() else True
        ok_url = _post_json(_url(), record) if _url() else True
        if not (ok_file and ok_url):
            # 失败不推进限频水位，下个周期重试（但避免同一秒内疯狂重试）
            _last_emitted = (last_seq, now)
            logger.warning("外置审计锚点外发未完全成功（seq=%s）", seq)
            return None
        return record


def reset_state() -> None:
    """测试隔离：清掉限频水位。"""
    global _last_emitted
    with _emit_lock:
        _last_emitted = (0, 0.0)


def _tail_lines(path: Path, limit: int) -> list[str]:
    """只读文件尾部 N 行。

    外置 sink 是"只追加、按留存期累积"的文件：巡检接口每次看的是最新状态，
    把整份文件读进内存的代价会随留存期线性增长（半年审计副本可达数百 MB），
    不该由一次后台页面刷新承担。这里从文件尾反向按块读取，找到足够行即停。
    """
    if limit <= 0:
        return []
    block = 64 * 1024
    with path.open("rb") as f:
        pos = f.seek(0, os.SEEK_END)
        data = b""
        while pos > 0 and data.count(b"\n") <= limit:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-limit:]


def _parse_record(line: str, current: str) -> dict | None:
    """解析一行外置记录并验签，附 `sig_state`（ok / stale_key / bad）。"""
    line = line.strip()
    if not line:
        return None
    try:
        rec = json.loads(line)
    except ValueError:
        return {"raw": line, "sig_ok": False, "sig_state": "bad"}
    sig = str(rec.pop("sig", ""))
    ok = hmac.compare_digest(sig, _sign(rec))
    rec["sig_ok"] = ok
    if ok:
        rec["sig_state"] = "ok"
    elif rec.get("key_id") and rec["key_id"] != current:
        rec["sig_state"] = "stale_key"
    else:
        rec["sig_state"] = "bad"
    return rec


def read_external(limit: int = 200) -> list[dict]:
    """读取外置文件里的记录（新的在后），并标注验签结果。

    两类记录混在同一份只追加流里：
      · kind=audit_anchor：周期性链尾锚点（校验"尾行有没有被改写/截断"）
      · kind=audit_rows：每批新增审计行的序号+行哈希+摘要（全量时间线）
    校验类接口只取锚点记录，行记录供离线重建/取证。

    每条记录附 `sig_state`：
      · ok            验签通过（可信）
      · stale_key     签名是**另一把密钥**下的（指纹不同）→ 密钥轮换的历史记录，
                      不可验证但可解释；依旧不采信
      · bad           指纹相同（或无指纹）却验签不过 → 记录被动过/被伪造
    """
    path = _file_path()
    if not path or not path.is_file():
        return []
    out: list[dict] = []
    current = key_id()
    try:
        for line in _tail_lines(path, limit):
            rec = _parse_record(line, current)
            if rec is not None:
                out.append(rec)
    except OSError as exc:
        logger.warning("读取外置审计锚点失败（%s）：%s", path, exc)
    return out


# 启动/巡检比对时的尾部扫描上限。**不能沿用巡检展示的 200 条**：行副本按
# 批次（每 0.2s 最多一批）写入，而锚点按 INTERVAL 限频；高峰期 200 行里可能
# 一条锚点都没有，于是 check() 落到"暂无记录"分支报 ok=True——截断检测在最
# 需要它的时刻静默失效。按 5 batches/s 估算，2 万行 ≈ 覆盖 1 小时以上的锚点。
ANCHOR_SCAN_LINES = 20000


def check(tail_hash: str, seq: int) -> dict:
    """把库内链尾与外置锚点比对。

    外置序号 > 库内序号 → 尾行被截断删除（本地锚点可能已被同步篡改）；
    序号相同但哈希不同 → 尾行内容被改（或锚点被伪造，但签名会先暴露）。
    """
    if not enabled():
        return {"enabled": False, "ok": True, "reason": "未配置外置锚点"}
    all_records = read_external(limit=ANCHOR_SCAN_LINES)
    anchors = [r for r in all_records
               if r.get("kind", "audit_anchor") == "audit_anchor"]
    records = [r for r in anchors if r.get("sig_ok")]
    # 只有"指纹相同却验签不过"才算可疑；密钥轮换前的旧记录单列，避免误报
    bad_sig = [r for r in all_records if r.get("sig_state") == "bad"]
    stale = [r for r in all_records if r.get("sig_state") == "stale_key"]
    shipped = [r for r in all_records if r.get("kind") == "audit_rows"]
    if not records:
        # 字段口径必须与"有记录"分支一致：调用方（resume_chain、巡检接口）
        # 直接读 truncated/tampered 判断要不要告警，缺键会让本该"无锚点可比对"
        # 的正常场景抛 KeyError——一个空 sink 就把审计写入链路打断，代价太大。
        return {"enabled": True, "ok": True,
                "external_seq": 0, "external_hash": "",
                "db_seq": int(seq), "db_hash": tail_hash,
                "truncated": False, "tampered": False,
                "bad_signature": len(bad_sig), "shipped_batches": len(shipped),
                "stale_key_records": len(stale), "key_id": key_id(),
                "source": str(_file_path() or _url()),
                "reason": "外置锚点暂无记录（或仅有旧密钥/不可验证记录）"}
    latest = max(records, key=lambda r: int(r.get("seq") or 0))
    ext_seq = int(latest.get("seq") or 0)
    truncated = ext_seq > int(seq)
    tampered = ext_seq == int(seq) and latest.get("tail_hash") != tail_hash
    return {
        "enabled": True,
        "ok": not truncated and not tampered,
        "external_seq": ext_seq,
        "external_hash": latest.get("tail_hash", ""),
        "db_seq": int(seq),
        "db_hash": tail_hash,
        "truncated": truncated,
        "tampered": tampered,
        "bad_signature": len(bad_sig),
        "stale_key_records": len(stale),
        "key_id": key_id(),
        # 全量外送（P0-3）：已发送的批次条数，用于"离线副本是否跟得上"巡检
        "shipped_batches": len(shipped),
        "source": str(_file_path() or _url()),
    }


def ship_rows(rows: list[dict]) -> dict | None:
    """把一批新增审计行（seq + row_hash + 业务摘要）外发到同一 sink。

    为什么要发"每一行"而不只发链尾：链尾锚点只能回答"最后一行有没有被改"，
    回答不了"3 月 5 日谁审批了什么"——中间行被改后重算链、只留一个正确尾
    哈希，锚点仍然对得上。行业合规要求审计日志本身有独立副本（留存 ≥6 个月），
    因此这里按批外送，Sink 侧可独立重建时间线。

    记录里**不含 query 正文**：外送目标是日志基础设施，不是数据仓库，
    原始问句可能含敏感信息；只发 seq/row_hash/ts/action/decision/user/ip
    这类审计元数据，足以对账与取证，又不会把业务内容扩到第二个系统。
    """
    if not enabled() or not rows or not getattr(cfg, "AUDIT_SHIP_ROWS", True):
        return None
    record = {
        "app": "finrag",
        "kind": "audit_rows",
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "pid": os.getpid(),
        "key_id": key_id(),
        "rows": [
            {
                "seq": int(r.get("seq") or 0),
                "row_hash": str(r.get("row_hash") or ""),
                "prev_hash": str(r.get("prev_hash") or ""),
                "ts": str(r.get("ts") or ""),
                "action": str(r.get("action") or "")[:32],
                "decision": str(r.get("decision") or "")[:8],
                "username": str(r.get("username") or "")[:64],
                "target_label": str(r.get("target_label") or "")[:128],
                "ip": str(r.get("ip") or "")[:64],
            }
            for r in rows
        ],
    }
    record["count"] = len(record["rows"])
    record["sig"] = _sign({k: v for k, v in record.items() if k != "sig"})
    ok_file = _append_file(_file_path(), record) if _file_path() else True
    ok_url = _post_json(_url(), record, kind="audit-rows") if _url() else True
    if not (ok_file and ok_url):
        logger.warning("审计行外送未完全成功（%d 行）", len(rows))
        return None
    return record
