# SPDX-License-Identifier: Apache-2.0
"""smoke 专用确定性词袋 embedder 替身（#21 PG-only 迁移配套）。

#21 把本地哈希向量通道随 SQLite 降级链路一并移除后，无 EMBED_API_KEY 时
embedding 只会明确失败（503），不再有"能跑但向量无语义"的中间态。smoke
是离线回归基线——无 Key、零外呼、结果必须逐轮可复现——由本模块把
embedder 单例的 `_remote` 换成确定性词袋向量。

算法与 tests/conftest.py 的 fake embedder 逐字一致（分词口径、md5 散列、
L2 归一化全相同）：同文本永远同向量，共享词汇的文本余弦更高。两边同口径
才能保证"pytest 验证过的检索行为"与"smoke 验证的行为"是同一套语义。

刻意不动 `api_mode`：smoke 迁移前就跑在无 Key 语义下（api_mode=False），
检索的 is_reliable 与意图锚句阈值走本地证据口径（retrieve.py / intent.py
的消费方见其注释）。改 True 会换上 API 模式阈值，反而改变冒烟断言历来
验证的行为——替身只补"向量通道"，不补"密钥语义"。
"""
import hashlib
import math
import re

# 与 conftest._fake_remote 同一分词口径：ASCII 词（字母数字串）/ 汉字单字
_TOKEN = re.compile(r"[a-zA-Z0-9]+|[\u4e00-\u9fff]")


def fake_remote(texts: list[str]) -> list[list[float]]:
    """确定性词袋向量：同文本永远同向量，共享词汇的文本余弦更高。

    维度从 app.config.EMBED_DIM 动态读取（不在导入期固化）：建表按该维度
    建 vector(N) 列，替身必须同维度，否则首次写入撞 pgvector dimension
    mismatch——而那个报错点离"维度从哪来"的现场很远，极难诊断。
    """
    from app.config import EMBED_DIM

    out: list[list[float]] = []
    for t in texts:
        toks = _TOKEN.findall(t.lower())
        vec = [0.0] * EMBED_DIM
        for tok in toks:
            h = int(hashlib.md5(tok.encode("utf-8")).digest()[:8].hex(), 16)
            vec[h % EMBED_DIM] += 1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        out.append([v / norm for v in vec])
    return out


def install_fake_embedder() -> None:
    """把替身装进 embedder 单例（实例属性覆盖类方法，对所有 import 方生效）。

    约束：必须在任何 embedding 发生之前调用（首次上传/检索之前）。
    重复调用安全（幂等，同函数引用）。
    """
    from app.embed import embedder

    embedder._remote = fake_remote
