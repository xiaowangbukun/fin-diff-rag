# SPDX-License-Identifier: AGPL-3.0-only
"""启动入口：python run.py [--port 8000]  |  python run.py build-index"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402


def _build_index() -> int:
    """手动建向量索引：pgvector HNSW 不支持 CONCURRENTLY，大表必须低峰执行。"""
    from app.db import SessionLocal
    from app.vindex import ensure_vector_index

    db = SessionLocal()
    try:
        result = ensure_vector_index(db)
        print(f"build-index 结果：{result}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    # 用位置子命令而非 argparse 的 add_subparsers：本工具只有 build-index 一个
    # 附加动作，子解析器会引入"必须传子命令"的隐式行为，破坏原有的纯 flag 用法。
    args = sys.argv[1:]
    if args and args[0] == "build-index":
        sys.exit(_build_index())

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parsed = parser.parse_args()
    uvicorn.run("app.main:app", host=parsed.host, port=parsed.port, reload=parsed.reload)
