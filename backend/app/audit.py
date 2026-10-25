# SPDX-License-Identifier: AGPL-3.0-only
"""审计日志：全链路留痕，越权与脱敏行为必须可追溯。

P0-2 防篡改（三层，对应三种攻击）：
  1. 行内哈希链：row_hash = sha256(prev_hash + "|" + canonical(业务字段))。
     改内容 → 重算值与存储值不符（broken_rows）。
  2. 单调序号 seq：删中间行 → 序号断档（seq_gaps）。
  3. 启动锚点：链尾 (hash, seq) 落盘 data/audit_anchor.json，重启时比对。
     删尾行（截断攻击，纯库内链防不住）→ 库尾序号小于锚点 → 告警行。

P1-8 异步写入：请求线程只构造审计行并入队（预生成 id，调用方立即可用），
后台守护线程按批次（默认 50 行 / 0.2s）用独立 Session 单事务落库；
链字段（seq/prev_hash/row_hash）统一在消费线程内、持 _chain_lock
顺序分配，保证"链序 = 入库序"。队列满时该次写入自动回落为同步直写
（原路径），审计不丢；resume_chain 的启动告警行恒走同步路径
（启动锚点依赖"写入后立即可见"的链尾状态）。

多 worker 部署时各进程链会分叉（尾 hash 是进程内状态），单 worker 部署不受影响；
PG 部署可用 pg_advisory_lock 包裹取尾插行（见 README 部署说明）。
异步化不改变该约束：仍要求单 worker（或按 worker 分链 + 运维对账）。
"""
import hashlib
import json
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import (
    AUDIT_BATCH_MAX, AUDIT_BATCH_TIMEOUT, AUDIT_QUEUE_MAXSIZE, DATA_DIR,
)
from .db import SessionLocal
from .models import AuditLog, new_id

# 参与链计算的业务字段（增删字段必须同步 migrate.SCHEMA_PATCHES 的语义）。
# 边界：只放业务内容，不放 id / seq / prev_hash / row_hash——
#   1. 后四者是链机制自身的字段：id 在构造时预生成，seq/prev_hash/row_hash
#      在 _assign_chain 里依赖前序行的状态顺序分配，把它们算进 canonical
#      等于让"内容哈希"依赖机制分配细节，而不是依赖内容本身；
#   2. verify_chain 重算时必须能仅凭业务字段复原 canonical（链字段要从
#      存储值读，不能再参与哈希输入，否则循环依赖）。
_CHAIN_FIELDS = (
    "ts", "user_id", "username", "action", "target_id",
    "target_label", "query", "decision", "reason", "ip", "detail",
)

ANCHOR_FILE = Path(DATA_DIR) / "audit_anchor.json"


def _emit_external_anchor(tail_hash: str, seq: int) -> None:
    """外置锚点外发（未配置 sink 时是空操作）。失败绝不影响审计主链路。"""
    try:
        from .anchors import emit as _emit
        _emit(tail_hash, seq)
    except Exception as e:  # noqa: BLE001 外部 sink 的任何异常都不该丢审计行
        print(f"[audit] 外置锚点外发异常（{type(e).__name__}: {e}）", file=sys.stderr)


def _ship_rows(batch: list[AuditLog]) -> None:
    """把本批新增审计行外送到外置 sink（P0-3 全量副本）。

    与链尾锚点的分工：锚点回答"尾行有没有被改写"，行副本回答"中间发生过
    什么"。没有行副本时，攻击者改中间行 + 重算其后所有哈希 + 保留正确尾哈希，
    锚点比对依然通过；有了独立副本，缺失/不同的行立刻对不上。
    """
    if not batch:
        return
    try:
        from .anchors import ship_rows as _ship
    except Exception:  # noqa: BLE001 导入失败不该影响审计
        return
    rows = [{
        "seq": b.seq or 0, "row_hash": b.row_hash or "",
        "prev_hash": b.prev_hash or "",
        "ts": b.ts.isoformat() if b.ts else "",
        "action": b.action or "", "decision": b.decision or "",
        "username": b.username or "", "target_label": b.target_label or "",
        "ip": b.ip or "",
    } for b in batch if b.row_hash]
    if not rows:
        return
    try:
        _ship(rows)
    except Exception as e:  # noqa: BLE001 外部 sink 故障绝不影响审计落库
        print(f"[audit] 审计行外送异常（{type(e).__name__}: {e}）", file=sys.stderr)

# 链尾状态：锁内"取尾 → 定 prev → 插行 → commit"一气呵成，进程内无竞态。
_chain_lock = threading.Lock()
_last_hash = "GENESIS"
_last_seq = 0


def _canonical(log: AuditLog) -> str:
    payload = {f: getattr(log, f) for f in _CHAIN_FIELDS}
    ts = payload.get("ts")
    payload["ts"] = ts.isoformat() if isinstance(ts, datetime) else str(ts or "")
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _chain_hash(prev: str, canonical: str) -> str:
    return hashlib.sha256(f"{prev}|{canonical}".encode("utf-8")).hexdigest()


def _read_anchor() -> dict:
    try:
        data = json.loads(ANCHOR_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_anchor(tail_hash: str, seq: int) -> None:
    try:
        ANCHOR_FILE.parent.mkdir(parents=True, exist_ok=True)
        ANCHOR_FILE.write_text(json.dumps(
            {"tail_hash": tail_hash, "seq": seq, "ts": datetime.utcnow().isoformat()},
            ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass  # 锚点写失败不影响主链路，下次重启补写


# ---------- P1-8 异步写入：队列 + 守护消费线程 ----------
_audit_q: queue.Queue = queue.Queue(maxsize=AUDIT_QUEUE_MAXSIZE)
_wake = threading.Event()          # 有新品入队即唤醒消费线程（关键事件百毫秒内可见）
_SHUTDOWN = object()               # 关机哨兵
_consumer_thread: threading.Thread | None = None
_consumer_lock = threading.Lock()


def _assign_chain(log: AuditLog) -> None:
    """为一行审计分配链字段（调用方必须已持有 _chain_lock）。

    ts 在这里落值而非请求线程：保证同一批次内"时间序 = 链序"，
    verify_chain 按 (ts, id) 邻链校验时才不会因时钟/调度抖动误报断链。
    """
    global _last_hash, _last_seq
    log.ts = datetime.utcnow()
    _last_seq += 1
    log.seq = _last_seq
    log.prev_hash = _last_hash
    log.row_hash = _chain_hash(_last_hash, _canonical(log))
    _last_hash = log.row_hash


def _commit_batch(batch: list[AuditLog]) -> None:
    """消费线程：一个批次一个 Session 单事务提交（持链锁，链序=入库序）。

    expire_on_commit=False：提交后不冻结属性——调用方（如 chat 回 audit_id）
    在行落库后仍能读取返回对象上的字段；否则 close 后属性过期，
    读取 .id 会抛 DetachedInstanceError。
    """
    if not batch:
        return
    db = SessionLocal(expire_on_commit=False)
    tail: tuple[str, int] = ("", 0)
    committed = False
    try:
        with _chain_lock:
            for log in batch:
                _assign_chain(log)
                db.add(log)
            db.commit()
            # 在锁内只取链尾快照：外发涉及文件 fsync / HTTP，绝不能持链锁做 I/O，
            # 否则 sink 变慢会直接卡住所有审计写入（进而卡住请求）。
            tail = (_last_hash, _last_seq)
            committed = True
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        # 落库失败不重试（避免阻塞消费线程）：序号已占用会留下断档，
        # verify_chain 的 seq_gaps 会如实反映"有行丢失"，Ops 依告警介入。
        print(f"[audit] 异步批次落库失败（{len(batch)} 行，"
              f"{type(e).__name__}: {e}）", file=sys.stderr)
    finally:
        db.close()
    if not committed:
        return
    # P0-3 全量外送：本批"序号 + 行哈希 + 摘要"进独立副本（sink 侧可重建时间线）。
    # 再补一条链尾锚点：行副本回答"发生过什么"，锚点回答"尾行有没有被截断/改写"。
    _ship_rows(batch)
    _emit_external_anchor(*tail)


def _drain_all() -> None:
    """关机收尾：把队列剩余行全部落库后再退出消费线程。"""
    while True:
        batch: list[AuditLog] = []
        try:
            while len(batch) < AUDIT_BATCH_MAX:
                batch.append(_audit_q.get_nowait())
        except queue.Empty:
            pass
        if not batch:
            return
        real = [b for b in batch if b is not _SHUTDOWN]
        _commit_batch(real)
        for _ in batch:
            try:
                _audit_q.task_done()
            except ValueError:
                pass
        if len(real) != len(batch):
            return  # 批次里出现关机哨兵：剩余行已全部落库，可以退出


def _consumer() -> None:
    """守护线程：等新品（事件唤醒，AUDIT_BATCH_TIMEOUT 兜底）→ 批量取 → 单事务落库。"""
    while True:
        _wake.wait(timeout=AUDIT_BATCH_TIMEOUT)
        _wake.clear()
        batch: list[AuditLog] = []
        try:
            while len(batch) < AUDIT_BATCH_MAX:
                batch.append(_audit_q.get_nowait())
        except queue.Empty:
            pass
        if not batch:
            continue
        if any(b is _SHUTDOWN for b in batch):
            real = [b for b in batch if b is not _SHUTDOWN]
            _commit_batch(real)
            for _ in batch:
                try:
                    _audit_q.task_done()
                except ValueError:
                    pass
            _drain_all()
            return
        _commit_batch(batch)
        for _ in batch:
            _audit_q.task_done()


def _ensure_consumer() -> None:
    """惰性启动消费线程（首次写入时；关机后再次写入会自动重建）。"""
    global _consumer_thread
    t = _consumer_thread
    if t is not None and t.is_alive():
        return
    with _consumer_lock:
        if _consumer_thread is None or not _consumer_thread.is_alive():
            t = threading.Thread(target=_consumer, name="audit-writer", daemon=True)
            t.start()
            _consumer_thread = t


def resume_chain(db: Session) -> dict:
    """启动时从库恢复链尾 (hash, seq)，并与磁盘锚点比对。

    锚点序号 < 库尾序号：正常运行的重启（上次运行新增的行），更新锚点；
    锚点序号 > 库尾序号：尾行被截断删除，写 system 告警行；
    序号相同但哈希不同：尾行内容被篡改，写 system 告警行。
    告警行走同步路径（sync=True）：锚点紧随其后落盘，依赖写入立即可见。
    """
    global _last_hash, _last_seq
    row = db.execute(
        select(AuditLog.row_hash, AuditLog.seq)
        .where(AuditLog.row_hash != "")
        .order_by(AuditLog.ts.desc(), AuditLog.id.desc())
        .limit(1)
    ).first()
    _last_hash = (row.row_hash if row else "") or "GENESIS"
    _last_seq = int(row.seq) if row and row.seq else 0

    anchor = _read_anchor()
    a_hash = str(anchor.get("tail_hash") or "")
    a_seq = int(anchor.get("seq") or 0)
    # 先算出全部告警再写：比对必须针对"恢复出来的链尾"。若边比对边写告警行，
    # 写告警本身会把 _last_seq 顶上去，外置锚点随即变成"同序号不同哈希"，
    # 真实原因（截断）就被误报成"尾行被改写"。
    tail_hash, tail_seq = _last_hash, _last_seq
    alarms: list[str] = []
    if a_hash and tail_hash != "GENESIS":
        if a_seq > tail_seq:
            alarms.append(f"审计链锚点告警：库内尾行序号 {tail_seq} 小于锚点序号 "
                          f"{a_seq}，疑似最新审计记录被截断删除")
        elif a_seq == tail_seq and a_hash != tail_hash:
            alarms.append("审计链锚点告警：序号相同但链尾哈希不符，疑似尾行内容被篡改")

    # 外置锚点（P0-2 增强）：本地锚点可被"库写 + 磁盘写"双权限同步篡改，
    # 外置记录才是截断/重写的独立见证。
    try:
        from .anchors import check as _anchor_check
        ext = _anchor_check(tail_hash, tail_seq)
        if ext.get("enabled") and not ext.get("ok"):
            if ext.get("truncated"):
                why = (f"外置锚点序号 {ext.get('external_seq')} 大于库内尾行序号 "
                       f"{tail_seq}，疑似尾行被截断删除（本地锚点可能已被同步篡改）")
            else:
                why = (f"序号 {tail_seq} 的链尾哈希与外置锚点不符，"
                       f"疑似尾行内容被改写或链被重算")
            alarms.append(f"审计链外置锚点告警：{why}")
        elif ext.get("enabled") and ext.get("bad_signature"):
            # 只算"指纹相同却验签不过"（sig_state=bad）：密钥轮换前的历史
            # 记录单独归入 stale_key_records，不在这里报"伪造"——把轮换误报
            # 成攻击，正是运维开始忽略审计告警的第一步。
            alarms.append(
                f"审计链外置锚点告警：{ext['bad_signature']} 条记录验签失败"
                f"（签名指纹与当前密钥一致，疑似被伪造或改写"
                + (f"；另有 {ext['stale_key_records']} 条旧密钥记录不可验证）"
                   if ext.get("stale_key_records") else "）"))
    except Exception as e:  # noqa: BLE001 外置 sink 故障不阻断启动
        print(f"[audit] 外置锚点启动比对失败（{type(e).__name__}: {e}）",
              file=sys.stderr)

    for reason in alarms:
        write_log(db, action="system", decision="deny", reason=reason, sync=True)

    try:
        from .anchors import emit as _anchor_emit
        _anchor_emit(_last_hash, _last_seq, force=True)
    except Exception as e:  # noqa: BLE001 外置 sink 故障不阻断启动
        print(f"[audit] 外置锚点外发失败（{type(e).__name__}: {e}）", file=sys.stderr)
    _write_anchor(_last_hash, _last_seq)
    return {"tail_hash": _last_hash, "seq": _last_seq}


def write_log(
    db: Session,
    *,
    user=None,
    action: str,
    target_id: str = "",
    target_label: str = "",
    query: str = "",
    decision: str = "allow",
    reason: str = "",
    ip: str = "",
    detail: str = "",
    sync: bool = False,
) -> AuditLog:
    """写一行审计（默认异步入队，返回值的 .id 立即可用）。

    sync=True 时走同步直写（resume_chain 启动告警等"写入后立即可见"场景）；
    异步队列满（背压）时同样自动回落同步直写，审计不丢。
    注意：异步路径下返回行的链字段（seq/prev_hash/row_hash）要等消费线程
    落库后才赋值——测试里"写后即查"必须先调 flush_audit()。
    """
    log = AuditLog(
        id=new_id(),  # 预生成：调用方（如 chat 回 audit_id）无需等待落库
        user_id=getattr(user, "id", "") or "",
        username=getattr(user, "username", "") or "anonymous",
        action=action,
        target_id=target_id[:36],
        target_label=target_label[:255],
        query=(query or "")[:2000],
        decision=decision,
        reason=reason[:1000],
        ip=ip[:64],
        detail=detail[:4000],
    )
    if not sync:
        _ensure_consumer()
        try:
            _audit_q.put_nowait(log)
            _wake.set()  # 即时唤醒：关键事件（block 等）百毫秒内可见
            return log
        except queue.Full:
            pass  # 背压：回落同步直写
    with _chain_lock:
        _assign_chain(log)
        db.add(log)
        db.commit()
        db.refresh(log)
        tail = (_last_hash, _last_seq)
    # 同步路径同样要外送（启动告警/背压回落都属于合规上不能缺的行）
    _ship_rows([log])
    _emit_external_anchor(*tail)
    return log


def flush_audit(timeout: float = 5.0) -> bool:
    """等待异步队列全部落库（测试断言 / 关停前调用）。

    返回 True = 队列已清空且全部提交；False = 超时仍有未落库行。
    重复调用安全（队列空时立即返回）。
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if _audit_q.unfinished_tasks == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)


def shutdown_audit(timeout: float = 5.0) -> None:
    """停止消费线程并把剩余审计行全部落库（FastAPI lifespan 收尾调用）。"""
    global _consumer_thread
    t = _consumer_thread
    if t is None or not t.is_alive():
        return
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            _audit_q.put(_SHUTDOWN, timeout=remaining)
            _wake.set()
            break
        except queue.Full:
            time.sleep(0.01)  # 队列满：消费线程正在消化，稍后再投递哨兵
    t.join(timeout=max(0.1, deadline - time.monotonic()))


def verify_chain(db: Session, limit: int = 5000) -> dict:
    """
    校验审计链完整性（顺序不敏感设计，避免 ts 碰撞误报）：
     1. 逐行独立重算 row_hash（内容自洽性）；
     2. 邻链链接统计：prev_hash 指向前一行 row_hash（删中间行检出）；
     3. 序号断档统计（删任意行检出，含删尾行）。
    返回 {ok, checked, broken_rows, broken_links, seq_gaps}。
    broken_rows>0 = 内容被篡改；broken_links>0 = 删中间行；
    seq_gaps>0 = 有行被删。删尾行的截断攻击由启动锚点机制检出（resume_chain）。

    排序口径：按 seq 而非 (ts, id)。seq 是链分配时的单调序号
    （_assign_chain 持 _chain_lock 顺序发放），是唯一的权威链序；
    ts 在同一批次内可能碰撞（utcnow 微秒分辨率），id 是随机 UUID，
    用 (ts, id) 兜底会在碰撞时按 UUID 排序，把好链误报成 broken_links。
    """
    rows = db.execute(
        select(AuditLog)
        .where(AuditLog.row_hash != "")
        .order_by(AuditLog.seq)
        .limit(min(limit, 20000))
    ).scalars().all()
    broken_rows = 0
    broken_links = 0
    first_broken_id = ""
    prev = ""
    for r in rows:
        if _chain_hash(r.prev_hash, _canonical(r)) != r.row_hash:
            broken_rows += 1
            if not first_broken_id:
                first_broken_id = r.id
        if prev and r.prev_hash != prev:
            broken_links += 1
            if not first_broken_id:
                first_broken_id = r.id
        prev = r.row_hash
    seqs = sorted(int(r.seq) for r in rows if r.seq)
    seq_gaps = sum(1 for a, b in zip(seqs, seqs[1:]) if b != a + 1)
    return {
        "ok": broken_rows == 0 and broken_links == 0 and seq_gaps == 0,
        "checked": len(rows),
        "broken_rows": broken_rows,
        "broken_links": broken_links,
        "seq_gaps": seq_gaps,
        "first_broken_id": first_broken_id,
        "note": "历史行（迁移前写入）不在链上，视为 GENESIS 兼容段",
    }
