# SPDX-License-Identifier: AGPL-3.0-only
"""ORM 模型：部门 / 用户 / 文档 / ACL / 切片 / 审计。"""
import json
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint, text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from pgvector.sqlalchemy import Vector

from .config import EMBED_DIM
from .db import Base


def new_id() -> str:
    return str(uuid.uuid4())


class Embedding(TypeDecorator):
    """PostgreSQL + pgvector 的 vector(EMBED_DIM) 列；业务代码统一用 list[float]。

    #21 前这里是"双方言适配器"：PG 存 vector 列、SQLite 存 JSON 文本，
    并由此引入过两类隐患——① `Vector is None`（pgvector 未装）时静默降级成
    Text 列，出现"连的是 PG、列却是 Text"的半 PG 状态；② 结果侧要为 SQLite
    的 JSON 字符串留反序列化回退。SQLite 链路移除后，pgvector 从"可选增强"
    变成硬依赖：直接 import，装不上就在导入期明确失败，而不是运行时静默
    降级成另一种存储语义。
    """

    impl = Vector(EMBED_DIM)
    cache_ok = True

    def load_dialect_impl(self, dialect):
        # 运行期读取 EMBED_DIM：models 模块级是 import 时绑定，
        # 这里求值保证测试改维度后建表口径同步。
        return dialect.type_descriptor(Vector(EMBED_DIM))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return list(value)

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, list):
            return value
        return list(value)


class Department(Base):
    __tablename__ = "departments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    code: Mapped[str] = mapped_column(String(32), default="")
    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("departments.id"), nullable=True
    )


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(64), default="")
    dept_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("departments.id"), nullable=True
    )
    roles: Mapped[str] = mapped_column(Text, default="[]")  # JSON 数组
    clearance: Mapped[int] = mapped_column(Integer, default=1)  # 0公开 1内部 2机密 3绝密
    pwd_hash: Mapped[str] = mapped_column(String(128), default="")
    salt: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    # 用户风险分（P1-7）：触发防拼图 block / 单文档停机阈值时累加，
    # 按 last_risk_ts 惰性衰减（每满 30 天 -1），不额外起定时任务。
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_risk_ts: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # 首次登录强制改密：管理员建号/重置口令后置 True。改密成功前除
    # /auth/me、/auth/change-password、/auth/logout 外一律 403（见 security）。
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    # 会话代次：改密 / 管理员重置 / 登出时 +1，令牌里的 ver 对不上即失效。
    # 没有这一列就只能等 JWT 自然过期，口令泄露后 12 小时内无法止血。
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    # ---- 第二因子：TOTP（闭环项 3 · S3）----
    # totp_secret 存密文（totp.seal 的 enc:v1: 前缀）；totp_confirmed_at 非空
    # 才算"已绑定"——只发密钥未验码属于待绑定态，不允许参与登录校验。
    # totp_last_step 记录已成功用过的时间步，防同一口令在窗口内重放。
    totp_secret: Mapped[str] = mapped_column(Text, default="")
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    # 一次性恢复码：JSON {"generated_at": ..., "codes": [{"h": 摘要, "used_at": ...}]}。
    # 只存 HMAC 摘要（见 app/recovery.py），明文只在生成时返回一次。
    recovery_codes: Mapped[str] = mapped_column(Text, default="")
    # ---- 单点登录：OIDC subject（issuer 内唯一）----
    # 与本地 username 分开存：IdP 侧改名/换登录名时，sub 仍然稳定；
    # 首次 SSO 登录按 username claim 匹配到本地账号后绑定 sub，此后以 sub 为准。
    # 唯一约束做"部分索引"：空串代表未绑定 SSO，不能互相冲突。
    oidc_subject: Mapped[str] = mapped_column(String(255), default="")
    # ---- IdP 密级同步溯源（OIDC_CLAIM_SYNC_MODE=authoritative 用）----
    # idp_clearance_synced：上一次 claim 同步写入的密级（0 = 从未同步过）；
    # idp_clearance_base：同步前本地已有的密级基线（-1 = 尚未记录）。
    # 目的：让 IdP 侧撤权（把密级调低）能真正回落，但**只回落到本地基线**——
    # 本地管理员另行授予的更高密级不会被 IdP 覆盖。两者都为"本地改过"留下
    # 判据：当前密级若不等于 max(base, synced)，说明是本地改的，基线应重置。
    idp_clearance_synced: Mapped[int] = mapped_column(Integer, default=0)
    idp_clearance_base: Mapped[int] = mapped_column(Integer, default=-1)

    __table_args__ = (
        Index("uq_users_oidc_subject", "oidc_subject", unique=True,
              postgresql_where=text("oidc_subject <> ''")),
    )

    def role_list(self) -> list[str]:
        try:
            return json.loads(self.roles or "[]")
        except Exception:
            return []


class AuthSession(Base):
    """服务端会话（P0-4）：空闲超时与单端吊销的事实来源。

    没有这张表时，"踢掉某一台设备"和"离开工位自动失效"都做不到：
    令牌一旦签发就只能等 12 小时自然过期，或者把整个账号所有设备一起踢
    （token_version）。令牌里的 sid 指向本表主键。

    只存会话元数据，不存令牌本身——库泄露不能直接换取会话。
    """
    __tablename__ = "auth_sessions"
    sid: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    # 吊销时刻非空即失效（登出 / 管理员踢端 / 改密后批量吊销）
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(255))
    source_name: Mapped[str] = mapped_column(String(255), default="")
    doc_type: Mapped[str] = mapped_column(String(32), default="txt")
    owner_dept_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("departments.id"), nullable=True
    )
    clearance: Mapped[int] = mapped_column(Integer, default=1)
    # open=全公司可见 / dept=归属部门可见 / restrict=仅 ACL 白名单可见
    acl_mode: Mapped[str] = mapped_column(String(16), default="dept")
    tags: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    pii_hits: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(16), default="ready")
    # 解析质量标记（P1）：ok=正常 / low=可读比例低（疑似乱码，建议核对原文）/
    # ocr=扫描件 OCR 来源。旧库由 migrate.py 白名单补列，默认 'ok'。
    parse_quality: Mapped[str] = mapped_column(String(16), default="ok")
    # 版本号（P2-10）：内容每次变更 +1，引用带上版本，事后可还原"当时看到哪版"。
    version: Mapped[int] = mapped_column(Integer, default=1)
    # 提示注入风险标记（P1-4）：入库时扫描正文，命中"忽略规则/输出提示词"
    # 类注入话术的次数。0 = 未检出；>0 = 上传审计已记 decision=flag。
    inject_risk: Mapped[int] = mapped_column(Integer, default=0)

    chunks: Mapped[list["Chunk"]] = relationship(
        "Chunk", cascade="all, delete-orphan", backref="doc"
    )


class DocAcl(Base):
    __tablename__ = "doc_acl"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    doc_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    subject_type: Mapped[str] = mapped_column(String(16))  # user / dept / role
    subject_key: Mapped[str] = mapped_column(String(64))
    effect: Mapped[str] = mapped_column(String(8), default="allow")  # allow / deny
    # 临时授权到期时间：到期自动失效，无需人工回收（治"临时授权扁平化"）
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    granted_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Chunk(Base):
    __tablename__ = "chunks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    doc_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("documents.id", ondelete="CASCADE")
    )
    seq: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[str] = mapped_column(Text)
    content_len: Mapped[int] = mapped_column(Integer, default=0)
    # 颗粒度下沉：切片级密级。NULL = 继承文档密级；
    # 显式设置时该切片按此密级隔离，实现「同文档跨密级」（治段落级撕裂）。
    clearance: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    embedding: Mapped[list | None] = mapped_column(Embedding(), nullable=True)

    __table_args__ = (Index("ix_chunks_doc_seq", "doc_id", "seq"),)


class ExposureLedger(Base):
    """
    防拼图攻击账本：用户 × 文档 × 滚动时间窗。

    单次问答永远"合法"，只有跨会话累积才暴露意图，因此必须在服务端记账。
    window_key 使用滚动小时桶编号，天然过期，无需清理任务。
    """
    __tablename__ = "exposure_ledger"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    doc_id: Mapped[str] = mapped_column(String(36))
    window_key: Mapped[str] = mapped_column(String(16))      # 滚动窗口桶编号
    seen_chunks: Mapped[str] = mapped_column(Text, default="[]")  # 已披露切片 id 明细
    seen_count: Mapped[int] = mapped_column(Integer, default=0)   # 真值，明细可能被截断
    char_total: Mapped[int] = mapped_column(Integer, default=0)
    query_count: Mapped[int] = mapped_column(Integer, default=0)
    full_read_count: Mapped[int] = mapped_column(Integer, default=0)
    last_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "doc_id", "window_key", name="uq_exposure"),
        Index("ix_exposure_user_window", "user_id", "window_key"),
    )


class ApprovalRequest(Base):
    """密级变更审批单（P2-9）。

    文档降密等于把原本受限的内容开放出去，是**不可逆**的信息外流——
    必须由申请人之外的人复核，且复核人自身密级要够得上目标密级。
    全程留痕，拒绝也要写理由，否则审批流就成了没有责任的橡皮图章。
    """
    __tablename__ = "approval_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # doc_id 是"审批对象 id"（列名为历史兼容）：subject_type=document 时是文档
    # id，subject_type=user 时是用户 id。加 subject_type 是为了让用户权限变更
    # 与文档变更共用同一条审批流（同一张表=同一份审计口径），同时不必为
    # 两种对象各写一套列表/裁决逻辑。
    doc_id: Mapped[str] = mapped_column(String(36), index=True)
    subject_type: Mapped[str] = mapped_column(String(16), default="document")
    kind: Mapped[str] = mapped_column(String(16), default="clearance")  # clearance/acl/acl_grant/user_privilege
    # 展示用的"从 → 到"。acl_grant 要存 "user:<36 位 UUID>"（41 字符），
    # 32 会被 PG 拒写（StringDataRightTruncation）——展示列必须比业务值宽。
    from_value: Mapped[str] = mapped_column(String(160), default="")
    to_value: Mapped[str] = mapped_column(String(160), default="")
    # acl / acl_grant 的结构化载荷（JSON）：归属部门 UUID、授权对象与有效期。
    # 塞进 from/to 会超 32 字符被截断，截断后的 "restrict|9f8e..." 审批通过时
    # 根本无法还原目标部门——宁可加一列也不要存半截凭据。
    payload: Mapped[str] = mapped_column(Text, default="")
    requester_id: Mapped[str] = mapped_column(String(36), default="")
    requester_name: Mapped[str] = mapped_column(String(64), default="")
    approver_id: Mapped[str] = mapped_column(String(36), default="")
    approver_name: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending/approved/rejected
    reason: Mapped[str] = mapped_column(Text, default="")
    decided_reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DocumentVersion(Base):
    """文档版本快照（P2-10）。

    只存"哪个版本在何时以何密级存在"的元数据，**本表不存全文**——
    content_hash 标识该版本的内容状态（同内容重复入库可识别），
    提取文本只存在于切片表；上传原文默认不落盘（仅在解析期间写
    临时文件、用后即删，见 ingest.parse_bytes），不放大泄露面。

    例外是显式开启 `ORIGINAL_STORE_ENABLED` 后的**原件留存**：原始字节写进
    对象存储（MinIO/S3），本表只记 original_key / sha256 / size 作为台账，
    供人工审查与完整性复核。开关默认关闭，关闭时下面四列恒为空。

    (doc_id, version) 唯一：版本链的意义就在于"一个版本号对应且仅对应
    一次内容状态"，同号多行会让"当时看到哪版"的追溯出现歧义。
    历史库（无约束时期写入，含重试路径）可能已有重复行，由 migrate.py
    先去重再建同名唯一索引，旧库平滑落地；干净库由 create_all 直接带出。
    """
    __tablename__ = "document_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    doc_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    content_hash: Mapped[str] = mapped_column(String(64), default="")
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    clearance: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    # ---- 原件留存（ORIGINAL_STORE_ENABLED 时才有值，默认关闭）----
    # original_key 为空 = 该版本没有留存原件（开关关闭 / 纯文本手动录入 /
    # 写入失败但宽容放行）。审查端据此区分"没有原件"与"原件在对象存储里"，
    # 不会把缺失当成已留存。sha256/size 是台账侧指纹，用于取回时比对；
    # 对象侧元数据里另存一份，两边不一致即判定被替换。
    original_key: Mapped[str] = mapped_column(String(512), default="")
    original_sha256: Mapped[str] = mapped_column(String(64), default="")
    original_size: Mapped[int] = mapped_column(Integer, default=0)
    original_stored_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("doc_id", "version", name="uq_document_versions"),
    )


class LoginAttempt(Base):
    """登录失败计数（跨 worker 共享版，见 app/loginthrottle.py）。

    一行一个 key（用户名，或"用户名#mfa"的第二因子计数）。刻意用
    "计数器 + 窗口起点"而不是一行一次失败：多 worker 并发写入时，
    单行 UPDATE 加上 SELECT ... FOR UPDATE 天然串行化，不会像
    "插入时间戳行"那样在计数与加锁之间留下竞态窗口。
    """
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    fails: Mapped[int] = mapped_column(Integer, default=0)
    first_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    user_id: Mapped[str] = mapped_column(String(36), default="")
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(32))     # login/upload/search/chat/grant...
    target_id: Mapped[str] = mapped_column(String(36), default="")
    target_label: Mapped[str] = mapped_column(String(255), default="")
    query: Mapped[str] = mapped_column(Text, default="")
    decision: Mapped[str] = mapped_column(String(16), default="allow")  # allow / deny / mask
    reason: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    # 防篡改哈希链（P0-2）：row_hash = sha256(prev_hash + "|" + canonical(业务字段))。
    # 迁移动旧库的历史行两列为空，视为 GENESIS；新写入行起受链保护。
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")
    # 单调序号：删中间行会留下序号断档（邻链检查只对删中间行有效，
    # seq 断档 + 启动锚点比对覆盖"删尾行截断攻击"——纯库内链防不住截断）。
    seq: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (Index("ix_audit_row_hash", "row_hash"),)
