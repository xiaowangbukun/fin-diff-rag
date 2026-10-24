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
    }
    record["sig"] = _sign({k: v for k, v in record.items() if k != "sig"})
    return record


def _post_json(url: str, record: dict) -> bool:
    """POST 一条锚点；失败返回 False（调用方只告警）。"""
    import urllib.error
    import urllib.request

    body = json.dumps(record, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Finrag-Signature": record["sig"],
                 "X-Finrag-Kind": "audit-anchor"},
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


def read_external(limit: int = 200) -> list[dict]:
    """读取外置文件里的锚点记录（新的在后），并标注验签结果。"""
    path = _file_path()
    if not path or not path.is_file():
        return []
    out: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                out.append({"raw": line, "sig_ok": False})
                continue
            sig = str(rec.pop("sig", ""))
            rec["sig_ok"] = hmac.compare_digest(sig, _sign(rec))
            out.append(rec)
    except OSError as exc:
        logger.warning("读取外置审计锚点失败（%s）：%s", path, exc)
    return out


def check(tail_hash: str, seq: int) -> dict:
    """把库内链尾与外置锚点比对。

    外置序号 > 库内序号 → 尾行被截断删除（本地锚点可能已被同步篡改）；
    序号相同但哈希不同 → 尾行内容被改（或锚点被伪造，但签名会先暴露）。
    """
    if not enabled():
        return {"enabled": False, "ok": True, "reason": "未配置外置锚点"}
    records = [r for r in read_external() if r.get("sig_ok")]
    bad_sig = [r for r in read_external() if r.get("sig_ok") is False]
    if not records:
        return {"enabled": True, "ok": True, "external_seq": 0, "db_seq": int(seq),
                "bad_signature": len(bad_sig), "reason": "外置锚点暂无记录"}
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
        "source": str(_file_path() or _url()),
    }
