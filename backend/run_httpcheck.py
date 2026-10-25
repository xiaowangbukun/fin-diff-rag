# SPDX-License-Identifier: AGPL-3.0-only
"""http_check 的运行包装（#21 PG-only 迁移配套）。

http_check 的账本/样本集夹具（reset_ledger / reset_sample_docs）要直连库，
进程环境里必须有正确的 DATABASE_URL——SQLite 时代有默认文件库兜底，
#21 后 DATABASE_URL 缺失时 app.db 用连不上的占位串，夹具会静默跳过
（只打一行 [..] 提示），反复执行时的基线就会被上一轮数据污染。

**夹具必须连服务端正在用的那个库**：服务端通常按 `backend/.env` 启动，
夹具若一律按测试库 `finrag_smoke` 去清，清的就是另一个库——上一轮遗留的
"全文读取 3 次"仍在服务端库里，混合密级那条断言会直接拿到 429。
取值优先级：进程环境变量 → `backend/.env` 的 DATABASE_URL → smoke 库兜底。

本包装把连接串注入环境后用 runpy 原样执行 http_check.py——不改它的
任何代码，断言与输出行为完全一致。口令同样从 smoke.py 现读。
"""
import os
import re
import runpy
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

_PWD = re.search(
    r'quote\("([^"]+)"', (BASE / "smoke.py").read_text(encoding="utf-8")
).group(1)
_SMOKE_DSN = f"postgresql+psycopg://finrag:{quote(_PWD, safe='')}@127.0.0.1:5432/finrag_smoke"


def _server_dsn() -> str:
    """服务端连接串：环境变量优先，其次 backend/.env，最后回落 smoke 库。"""
    for p in (BASE / ".env", BASE.parent / ".env"):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == "DATABASE_URL" and v.strip().strip('"').strip("'"):
                return v.strip().strip('"').strip("'")
    return _SMOKE_DSN


os.environ.setdefault("DATABASE_URL", _server_dsn())
# http_check 客户端本身不上传文件，但 app.config 导入期会建 UPLOAD_DIR，
# 不给 DATA_DIR 就会在仓库里建 backend/data——指到临时目录保持仓库干净。
os.environ.setdefault(
    "DATA_DIR", str(Path(tempfile.mkdtemp(prefix="finrag-hcclient-")) / "data")
)

sys.argv = ["http_check.py"]
runpy.run_path(str(BASE / "http_check.py"), run_name="__main__")
