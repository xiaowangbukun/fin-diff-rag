# SPDX-License-Identifier: AGPL-3.0-only
"""P0-6：PostgreSQL 逻辑备份 / 校验 / 恢复（一次跑完的可执行 runbook）。

为什么必须有脚本而不是"运维记得手敲 pg_dump"：
  · 备份没被**验证**过等于没有备份。这里把"备份 + sha256 + 元数据清单 +
    恢复后一致性校验"固化成命令，演练成本降到一条命令；
  · 元数据清单里带**审计链尾 (seq, row_hash)** 与 alembic 版本：恢复后能
    立刻回答"这份备份是哪一版结构、审计链到哪一行"，而不是只看到文件大小；
  · 保留策略（默认 30 天）内置于备份命令，避免磁盘被历史备份堆满后
    运维手动 rm -rf（更常见的做法是干脆关掉备份）。

用法（需要目标机有 pg_dump / pg_restore，PostgreSQL 客户端工具）：
    python scripts/pg_backup.py backup  --out backups/
    python scripts/pg_backup.py verify  --file backups/finrag-20261025T010203Z.dump
    python scripts/pg_backup.py restore --file backups/xxx.dump \
        --target postgresql://finrag:***@127.0.0.1:5432/finrag_drill --yes

默认连接串取 DATABASE_URL（环境变量 / backend/.env，与 `app.config` 同口径）。
恢复刻意要求显式 --target 且必须带 --yes：这是破坏性操作（--clean 会先删
目标库里的同名对象），不能在"顺手"的默认参数下发生。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"

# 子进程统一按 UTF-8 解码且容错：Windows 上 pg_dump/pg_restore 的提示信息可能是
# 本地代码页（GBK），用默认 locale 解码会在读取阶段抛 UnicodeDecodeError——
# 那会把"恢复失败的真实原因"变成"读输出失败"，波形完全对不上。
_RUN = {"capture_output": True, "text": True, "encoding": "utf-8",
        "errors": "replace"}


def _load_env_file() -> None:
    """轻量 .env 兜底（与 app.config 一致：环境变量优先）。"""
    for p in (BACKEND_DIR / ".env", BACKEND_DIR.parent / ".env"):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _database_url(explicit: str = "") -> str:
    if explicit:
        return explicit
    _load_env_file()
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("缺少连接串：请设置 DATABASE_URL 或显式传 --database-url/--target")
    return url


def _libpq_url(url: str) -> str:
    """SQLAlchemy 方言前缀（+psycopg）不是 libpq 能识别的，去掉。"""
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def _sa_url(url: str) -> str:
    """给 SQLAlchemy 用的连接串：无方言前缀时补 +psycopg。

    本项目只依赖 psycopg v3（requirements.txt 无 psycopg2）。SQLAlchemy 对
    `postgresql://` 默认找 psycopg2，而 runbook 里 --target 示例是 libpq 形态
    的连接串——不补齐就会出现"恢复成功、校验阶段却 ModuleNotFoundError"。
    """
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def _require_tool(name: str) -> str:
    """定位客户端工具：PATH 优先，其次 PG_BIN（Windows 常见：bin 没进 PATH）。"""
    path = shutil.which(name)
    if not path:
        pg_bin = os.getenv("PG_BIN", "").strip()
        if pg_bin:
            candidate = Path(pg_bin) / (name + (".exe" if os.name == "nt" else ""))
            if candidate.is_file():
                return str(candidate)
    if not path:
        raise SystemExit(
            f"未找到 {name}：请在装有 PostgreSQL 客户端工具的机器上执行"
            "（Debian/Ubuntu: postgresql-client；macOS: libpq）。"
            "Windows 便携版可设置 PG_BIN=<PostgreSQL>/bin 后重试。"
        )
    return path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _db_snapshot(url: str) -> dict:
    """只读采集"这份备份对应哪个状态"：审计链尾、各表行数、alembic 版本。"""
    from sqlalchemy import create_engine, text

    engine = create_engine(_sa_url(url))
    out: dict = {}
    with engine.connect() as conn:
        def scalar(sql: str):
            try:
                return conn.execute(text(sql)).scalar()
            except Exception:  # 表可能还不存在（全新库）
                conn.rollback()
                return None

        tail = conn.execute(text(
            "SELECT seq, row_hash, ts FROM audit_logs WHERE row_hash <> '' "
            "ORDER BY seq DESC LIMIT 1"
        )).first()
        out["audit_tail"] = (
            {"seq": int(tail.seq), "row_hash": tail.row_hash,
             "ts": tail.ts.isoformat() if tail.ts else ""} if tail else None
        )
        out["alembic_version"] = scalar("SELECT version_num FROM alembic_version")
        counts = {}
        for table in ("users", "documents", "chunks", "audit_logs",
                      "approval_requests", "auth_sessions", "exposure_ledger"):
            n = scalar(f"SELECT count(*) FROM {table}")
            if n is not None:
                counts[table] = int(n)
        out["row_counts"] = counts
    engine.dispose()
    return out


def cmd_backup(args) -> int:
    url = _database_url(args.database_url)
    pg_dump = _require_tool("pg_dump")
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dump = out_dir / f"finrag-{stamp}.dump"

    # 扩展对象（pgvector）无法在备份侧排除：pg_dump 没有 --exclude-extension
    # （只有 --extension 正向选择），扩展会作为 EXTENSION 条目进 dump。恢复时
    # `--clean` 会据此执行 `DROP EXTENSION vector`，而扩展属主是 DBA 的超级用户
    # 账号（pgvector 未标记 trusted，应用账号既不能 CREATE 也不能 DROP），
    # 于是 "must be owner of extension" + `--single-transaction` 整次回滚。
    # 处置放在恢复侧：按 TOC 过滤掉扩展条目（见 _toc_without_extension），
    # 目标库由 DBA 预先 CREATE EXTENSION，恢复只搬数据与普通对象。
    proc = subprocess.run(
        [pg_dump, "--format=custom", "--no-owner", "--no-privileges",
         "--dbname", _libpq_url(url), "--file", str(dump)],
        **_RUN)
    if proc.returncode != 0:
        print(proc.stderr.strip() or "pg_dump 失败", file=sys.stderr)
        return 1

    manifest = {
        "app": "finrag",
        "kind": "pg_backup_manifest",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dump": dump.name,
        "bytes": dump.stat().st_size,
        "sha256": _sha256(dump),
        "pg_dump_version": subprocess.run(
            [pg_dump, "--version"], **_RUN).stdout.strip(),
        **_db_snapshot(url),
    }
    (dump.with_suffix(".dump.manifest.json")).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    rotated = _rotate(out_dir, args.keep_days)
    print(json.dumps({"backup": str(dump), "sha256": manifest["sha256"],
                      "bytes": manifest["bytes"],
                      "row_counts": manifest["row_counts"],
                      "pruned": rotated}, ensure_ascii=False, indent=2))
    return 0


def _rotate(out_dir: Path, keep_days: int) -> list[str]:
    """保留策略：删掉超过 keep_days 的备份与清单（只认本脚本的命名）。"""
    if keep_days <= 0:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    removed: list[str] = []
    for dump in out_dir.glob("finrag-*.dump"):
        mtime = datetime.fromtimestamp(dump.stat().st_mtime, tz=timezone.utc)
        if mtime >= cutoff:
            continue
        manifest = dump.with_suffix(".dump.manifest.json")
        for p in (dump, manifest):
            if p.is_file():
                p.unlink()
                removed.append(p.name)
    return removed


def _read_manifest(dump: Path) -> dict:
    p = dump.with_suffix(".dump.manifest.json")
    if not p.is_file():
        raise SystemExit(f"缺少清单文件 {p.name}：无法确认备份完整性与对应版本")
    return json.loads(p.read_text(encoding="utf-8"))


def _require_extension(url: str, name: str = "vector") -> None:
    """恢复前确认目标库已装 pgvector 扩展。

    恢复侧刻意把扩展条目从 TOC 里过滤掉（见 `_toc_without_extension`）：扩展
    属主是 DBA 的超级用户，应用账号改不了它，`--clean` 的 DROP EXTENSION 会
    因权限失败并让整次恢复回滚。因此扩展必须**由 DBA 预先装在目标库**，恢复
    只搬数据与普通对象——但 `chunks.embedding` 这类列定义仍依赖扩展类型，
    目标库若没装，pg_restore 会在建表处失败。这里提前失败，并把"该谁做、
    怎么做"写清楚。
    """
    from sqlalchemy import create_engine, text

    engine = create_engine(_sa_url(url))
    try:
        with engine.connect() as conn:
            present = conn.execute(
                text("SELECT 1 FROM pg_extension WHERE extname = :n"),
                {"n": name},
            ).scalar()
    except Exception as exc:  # 连接串写错/DBA 未授权：同样是"现在就该停"
        raise SystemExit(
            f"无法连接目标库，恢复中止：{exc}\n"
            "请确认 --target 连接串可达，且该账号能查询 pg_extension。"
        ) from exc
    finally:
        engine.dispose()
    if not present:
        raise SystemExit(
            f"目标库未安装扩展 {name}，恢复中止（否则建表阶段会失败并整体回滚）。\n"
            f"请让 DBA 用超级用户在目标库执行：CREATE EXTENSION IF NOT EXISTS {name};\n"
            "说明见 docs/BACKUP-RESTORE.md「恢复目标库的前置条件」。"
        )


def _toc_without_extension(pg_restore: str, dump: Path) -> tuple[list[str], list[str]]:
    """取 TOC 并剔除扩展条目，返回 (保留行, 被剔除行)。

    为什么必须过滤：`pg_dump` 没有 `--exclude-extension`（只有 `--extension`
    正向选择），扩展必然作为 EXTENSION/COMMENT 条目进 dump；`--clean` 就会
    执行 `DROP EXTENSION vector`。pgvector 未标记 trusted，属主是 DBA 的超级
    用户，应用账号执行即报 "must be owner of extension"，且 `--single-transaction`
    会把整次恢复回滚（表现为"退出码非 0 + 行数全 0"，极易被误读成备份坏了）。
    过滤同时保留完整对象清单供人工核对。
    """
    proc = subprocess.run([pg_restore, "--list", str(dump)],
                          **_RUN)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or "pg_restore --list 失败")
    keep: list[str] = []
    dropped: list[str] = []
    for line in proc.stdout.splitlines():
        # 两种形态都要挡：
        #   "2; 3079 722478 EXTENSION - vector"
        #   "5241; 0 0 COMMENT - EXTENSION vector"（COMMENT 的"类型-名称"分隔不同）
        if re.match(
            r"^\s*\d+;\s+\d+\s+\d+\s+(?:COMMENT\s+-\s+)?EXTENSION(?:\s+-\s+|\s+)vector\b",
            line,
        ):
            dropped.append(line.strip())
            continue
        keep.append(line)
    return keep, dropped


def cmd_verify(args) -> int:
    dump = Path(args.file).resolve()
    if not dump.is_file():
        raise SystemExit(f"备份文件不存在：{dump}")
    manifest = _read_manifest(dump)
    actual = _sha256(dump)
    ok_hash = actual == manifest.get("sha256")
    pg_restore = _require_tool("pg_restore")
    proc = subprocess.run([pg_restore, "--list", str(dump)],
                          **_RUN)
    if proc.returncode != 0:
        print(proc.stderr.strip() or "pg_restore --list 失败", file=sys.stderr)
        return 1
    tables = sum(1 for line in proc.stdout.splitlines()
                 if " TABLE DATA " in line or line.strip().startswith("TABLE DATA"))
    report = {
        "file": str(dump),
        "sha256_ok": ok_hash,
        "expected_sha256": manifest.get("sha256"),
        "actual_sha256": actual,
        "table_data_entries": tables,
        "manifest_audit_tail": manifest.get("audit_tail"),
        "manifest_alembic_version": manifest.get("alembic_version"),
        "manifest_row_counts": manifest.get("row_counts"),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not ok_hash:
        print("备份文件与清单哈希不符：备份可能被截断/篡改，禁止用于恢复",
              file=sys.stderr)
        return 2
    return 0


def cmd_restore(args) -> int:
    dump = Path(args.file).resolve()
    if not dump.is_file():
        raise SystemExit(f"备份文件不存在：{dump}")
    if not args.yes:
        raise SystemExit(
            "拒绝执行：restore 会 --clean 掉目标库中的同名对象（破坏性）。"
            "确认目标库是演练/新实例后追加 --yes。")
    if cmd_verify(argparse.Namespace(file=str(dump))) != 0:
        raise SystemExit("备份校验未通过，终止恢复")
    manifest = _read_manifest(dump)
    _require_extension(args.target)
    pg_restore = _require_tool("pg_restore")
    target = _libpq_url(args.target)
    keep, dropped = _toc_without_extension(pg_restore, dump)
    # -L 用过滤后的 TOC：既不 DROP EXTENSION（属主是 DBA，应用账号无权），
    # 也保证 --clean 只清理本次真正要恢复的对象，不误伤目标库里的其他东西。
    toc_fd, toc_path = tempfile.mkstemp(prefix="finrag-restore-", suffix=".list")
    with os.fdopen(toc_fd, "w", encoding="utf-8") as f:
        f.write("\n".join(keep) + "\n")
    try:
        proc = subprocess.run(
            [pg_restore, "--clean", "--if-exists", "--no-owner", "--no-privileges",
             "--single-transaction", "-L", toc_path, "--dbname", target, str(dump)],
            **_RUN,
        )
    finally:
        Path(toc_path).unlink(missing_ok=True)
    if dropped:
        print(json.dumps({"toc_filtered_out": dropped}, ensure_ascii=False, indent=2))
    # pg_restore 对"对象不存在"类告警返回非 0 是常见现象（--clean 清空库时），
    # 因此这里以"恢复后数据校验"为准，而不是只看退出码。
    warning = (proc.stderr or "").strip()
    snapshot = _db_snapshot(args.target)
    expected = manifest.get("audit_tail") or {}
    actual = snapshot.get("audit_tail") or {}
    checks = {
        "exit_code": proc.returncode,
        "audit_tail_seq_match": expected.get("seq") == actual.get("seq"),
        "audit_tail_hash_match": expected.get("row_hash") == actual.get("row_hash"),
        "alembic_version_match":
            manifest.get("alembic_version") == snapshot.get("alembic_version"),
        "row_counts": snapshot.get("row_counts"),
        "stderr_tail": warning[-400:],
    }
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    ok = (checks["audit_tail_seq_match"] and checks["audit_tail_hash_match"]
          and checks["alembic_version_match"])
    if not ok:
        print("恢复后校验未通过：请勿切流量，按 runbook 排查（docs/BACKUP-RESTORE.md）",
              file=sys.stderr)
        return 2
    print("恢复完成且一致性与清单相符。下一步：alembic upgrade head 后再启动服务。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="fin-rag PostgreSQL 备份 / 校验 / 恢复（P0-6）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="逻辑备份 + 生成清单 + 轮转")
    b.add_argument("--out", default="backups", help="备份目录（默认 backups/）")
    b.add_argument("--keep-days", type=int, default=30, help="保留天数，0=不轮转")
    b.add_argument("--database-url", default="", help="源库连接串（默认 DATABASE_URL）")
    b.set_defaults(func=cmd_backup)

    v = sub.add_parser("verify", help="校验哈希与清单（恢复前必跑）")
    v.add_argument("--file", required=True, help=".dump 文件路径")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("restore", help="恢复到指定库（破坏性，需 --yes）")
    r.add_argument("--file", required=True)
    r.add_argument("--target", required=True, help="目标库连接串（演练/新实例）")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(func=cmd_restore)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
