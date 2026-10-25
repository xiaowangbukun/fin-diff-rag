# SPDX-License-Identifier: AGPL-3.0-only
"""P0-6：审计日志留存归档（合规留存 ≥6 个月，且归档副本可独立取证）。

分工（与 P0-3 外置副本互补）：
  · `anchors.ship_rows`（在线）：每批新增审计行**实时**外送到日志 sink，
    用于"随发生随对账"；
  · 本脚本（离线）：按留存窗口把**历史区间**导出成带哈希链校验的归档包，
    用于"半年后还要能证明这段时间发生过什么"。

为什么本脚本**不删除**在线审计行：
  审计表的哈希链 + 单调序号是完整证据链，删掉最旧的一段会永久留下
  `seq_gaps`，让 `verify_chain` 从此报警——等于用"清理"换来"永久不可信"。
  在线留存靠容量规划（审计行是结构化元数据，量级远小于问答正文），
  真需要下沉请走"按时间分区 + 分区 detach"方案（见 README「数据保留」）。
  因此本脚本只导出、只校验、只生成清单；删除是单独的、需审批的运维动作。

产出（默认 `archive/`）：
  finrag-audit-<cutoff>Z.ndjson.gz      归档正文（一行一条审计）
  finrag-audit-<cutoff>Z.manifest.json  条数 / 首尾序号 / 链尾哈希 / sha256

用法：
    python scripts/audit_archive.py --months 6 --out archive/
    python scripts/audit_archive.py --months 6 --redact-query   # 只留审计元数据
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

MIN_MONTHS = 6   # 金融行业审计留存底线；低于它直接拒绝（除非显式 --force）


def _fields(redact: bool) -> list[str]:
    base = ["id", "seq", "ts", "user_id", "username", "action", "target_id",
            "target_label", "decision", "reason", "ip", "prev_hash", "row_hash"]
    return base if redact else base + ["query", "detail"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="审计日志归档（P0-6）")
    parser.add_argument("--months", type=int, default=MIN_MONTHS,
                        help=f"归档早于 N 个月前的审计行（默认且最少 {MIN_MONTHS}）")
    parser.add_argument("--out", default="archive", help="归档目录")
    parser.add_argument("--redact-query", action="store_true",
                        help="不导出 query/detail 正文（只留审计元数据）")
    parser.add_argument("--force", action="store_true",
                        help="链校验失败仍导出（仅供取证，清单会标 chain_ok=false）")
    args = parser.parse_args(argv)

    if args.months < MIN_MONTHS and not args.force:
        print(f"拒绝执行：留存窗口不得短于 {MIN_MONTHS} 个月"
              "（确需取证的短窗口导出请加 --force，清单会标注）", file=sys.stderr)
        return 1

    from sqlalchemy import select
    from app.db import SessionLocal
    from app.models import AuditLog
    from app.audit import ANCHOR_FILE, verify_chain

    db = SessionLocal()
    try:
        chain = verify_chain(db)
        if not chain["ok"] and not args.force:
            print(f"拒绝执行：审计链校验未通过 {json.dumps(chain, ensure_ascii=False)}。"
                  "先按告警排查篡改/断档，再做归档。", file=sys.stderr)
            return 2

        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
            days=30 * args.months)
        rows = db.execute(
            select(AuditLog).where(AuditLog.ts < cutoff).order_by(AuditLog.seq)
        ).scalars().all()

        out_dir = Path(args.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = cutoff.strftime("%Y%m%dT%H%M%SZ")
        path = out_dir / f"finrag-audit-{stamp}.ndjson.gz"

        names = _fields(args.redact_query)
        h = hashlib.sha256()
        with gzip.open(path, "wb") as f:
            for r in rows:
                rec = {}
                for n in names:
                    v = getattr(r, n)
                    rec[n] = v.isoformat() if isinstance(v, datetime) else v
                line = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
                f.write(line)
                h.update(line)

        anchor = {}
        try:
            anchor = json.loads(Path(ANCHOR_FILE).read_text(encoding="utf-8"))
        except Exception:
            anchor = {}
        # 本地锚点文件是"按部署"的（谁在写、写哪个库由运行中的服务决定）。
        # 归档脚本可能被指向另一个库（演练/取证），此时锚点属于别的库，
        # 直接写进清单会让人误以为"归档包与锚点同源"。这里显式带上库自身的
        # 链尾并标注锚点是否与本库一致，取证时一眼能分辨。
        db_tail = db.execute(
            select(AuditLog.seq, AuditLog.row_hash)
            .where(AuditLog.row_hash != "")
            .order_by(AuditLog.seq.desc()).limit(1)
        ).first()
        db_tail = ({"seq": int(db_tail.seq), "row_hash": db_tail.row_hash}
                   if db_tail else None)
        anchor_matches = bool(
            db_tail and anchor
            and int(anchor.get("seq") or -1) == db_tail["seq"]
            and str(anchor.get("tail_hash") or "") == db_tail["row_hash"]
        )
        manifest = {
            "app": "finrag",
            "kind": "audit_archive_manifest",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cutoff": cutoff.isoformat(timespec="seconds"),
            "months": args.months,
            "redact_query": bool(args.redact_query),
            "rows": len(rows),
            "first_seq": int(rows[0].seq or 0) if rows else None,
            "last_seq": int(rows[-1].seq or 0) if rows else None,
            "chain_ok_at_export": bool(chain["ok"]),
            "chain_report": chain,
            # 归档时点的链尾与本地锚点：将来取证时"归档包 + 当时锚点"一起
            # 才能证明导出内容与当时的在线库一致。
            "db_tail_at_export": db_tail,
            "anchor_at_export": anchor,
            "anchor_matches_db": anchor_matches,
            "file": path.name,
            "sha256": h.hexdigest(),
        }
        (out_dir / f"finrag-audit-{stamp}.manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
