# SPDX-License-Identifier: AGPL-3.0-only
"""http_check 的配套服务启动器（#21 PG-only 迁移配套）。

为什么需要它：http_check 断言的对象是"真实运行中的服务"（非 TestClient，
走真实端口与中间件，见其模块 docstring）。而 #21 移除本地哈希向量通道后，
无 EMBED_API_KEY 时 lifespan 里的 ensure_seed 文档入库会撞 503——真实
服务进程没有 pytest conftest 的替身注入，离线环境根本起不来。

本启动器在 uvicorn import app 之前装好确定性 fake embedder（smoke_fake，
与 tests/conftest.py 同口径），让离线环境也能对 8000 端口跑全量 HTTP 断言。
用法：python httpcheck_serve.py（跑完用 killport.py 收端口）。

口令从 smoke.py 现读（不在本文件落第二份）：smoke.py 的连接串已在同机
验证过（251/251 全绿），单一来源，避免两处口令改一处漏一处。
"""
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

_PWD = re.search(
    r'quote\("([^"]+)"', (BASE / "smoke.py").read_text(encoding="utf-8")
).group(1)
os.environ.setdefault(
    "DATABASE_URL",
    f"postgresql+psycopg://finrag:{quote(_PWD, safe='')}@127.0.0.1:5432/finrag_smoke",
)
# 离线口径与 smoke / conftest 一致：无 Key 显式放行 + 替身向量供给；
# JWT 固定密钥（http_check 多账号登录，进程内一致即可）；
# DATA_DIR 走临时目录，运行时不往仓库写。
os.environ.setdefault("EMBED_REQUIRE_API_KEY", "false")
os.environ.setdefault("JWT_SECRET", "httpcheck-secret-" + "x" * 32)
os.environ.setdefault(
    "DATA_DIR", str(Path(tempfile.mkdtemp(prefix="finrag-httpcheck-")) / "data")
)

from smoke_fake import install_fake_embedder  # noqa: E402

# 必须在 uvicorn import app.main 之前：app.embed 的 embedder 单例在
# import 时创建，装替身改的是实例属性，晚于 import 就赶不上首批 embedding。
install_fake_embedder()

import uvicorn  # noqa: E402

if __name__ == "__main__":
    # 刻意不用 --reload：reload 会派生子进程，替身注入只在本进程生效，
    # 子进程里 ensure_seed 又会撞 503。
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000)
