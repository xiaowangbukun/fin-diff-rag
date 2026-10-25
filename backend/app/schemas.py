# SPDX-License-Identifier: AGPL-3.0-only
from typing import Any

from pydantic import BaseModel, Field

from .config import MAX_DOC_CHARS


class LoginIn(BaseModel):
    # 长度约束不是洁癖：超长 username 会在 PG 侧撞 DataError 500
    # （SQLite 不拦），在边界拒掉才是 422 明确错误。
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    # 只做边界（1–256），强度由 password_policy 统一判定：
    # 策略要能给出中文原因（弱口令/含用户名/类别不足），写死在 pydantic 里
    # 会变成 422 的英文字段错误，前端没法直接展示。
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class MfaLoginIn(BaseModel):
    """第二步：口令已过，凭挑战票据 + 动态口令（或一次性恢复码）换正式会话。"""
    challenge: str = Field(min_length=10, max_length=4096)
    # 两者二选一：code = TOTP 动态口令；recovery_code = 恢复码（手机丢失时用）。
    # 只做长度边界，格式/配对校验在路由里给中文原因。
    code: str = Field(default="", max_length=12)
    recovery_code: str = Field(default="", max_length=32)


class TotpSetupIn(BaseModel):
    # 绑定第二因子必须重新验口令：只偷到会话（未拿到口令）的人
    # 不能把自己的 TOTP 绑上去，否则原主后续登录反而被攻击者控住。
    password: str = Field(min_length=1, max_length=256)


class TotpConfirmIn(BaseModel):
    code: str = Field(min_length=4, max_length=12)


class TotpDisableIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class RecoveryRegenerateIn(BaseModel):
    """重新生成恢复码：同样要求口令再验（旧码库会被整组作废）。"""
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    id: str
    username: str
    display_name: str
    dept_id: str | None = None
    dept_name: str = ""
    roles: list[str] = []
    clearance: int = 1
    clearance_name: str = ""
    is_admin: bool = False
    must_change_password: bool = False
    # 前端据此显示"已开启动态口令 / 未绑定 / 必须绑定"三态
    mfa_enabled: bool = False
    mfa_setup_required: bool = False
    # 剩余可用恢复码数量（0 且已绑定 TOTP = 手机丢失时只能找管理员）
    recovery_codes_remaining: int = 0


class LoginOut(BaseModel):
    token: str
    user: UserOut


class AclIn(BaseModel):
    subject_type: str  # user / dept / role
    subject_key: str
    effect: str = "allow"
    # 临时授权：到期自动失效（小时）。不传 = 长期有效；传负值可用于构造"已过期"授权做验证。
    expires_hours: int | None = None


class DocOut(BaseModel):
    id: str
    title: str
    doc_type: str = ""
    clearance: int = 1
    clearance_name: str = ""
    acl_mode: str = "dept"
    owner_dept: str = ""
    tags: str = ""
    pii_hits: int = 0
    # 提示注入风险（P1-4）：入库扫描命中"忽略规则/输出提示词"类话术的次数，0 = 未检出
    inject_risk: int = 0
    chunk_count: int = 0
    # 解析质量：ok=正常 / low=可读比例低（疑似乱码，建议核对原文）/ ocr=扫描件 OCR 来源
    parse_quality: str = "ok"
    # 切片级最高密级：None = 全文同密级；有值 = 同文档跨密级（段落级撕裂已启用防护）
    max_chunk_clearance: int | None = None
    created_at: str = ""
    acl: list[dict[str, Any]] = []


class DocCreateIn(BaseModel):
    # title 上限 200 < 库列 255：曾经的静默截断（title[:255]）在这里变成
    # 明确的 422，调用方看得见；content 与 config.MAX_DOC_CHARS 联动，
    # 与 ingest 卡口同一口径（schema 拦 API 路径，ingest 拦内部路径）。
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=MAX_DOC_CHARS)
    clearance: int = Field(default=1, ge=0, le=3)
    acl_mode: str = "dept"
    owner_dept_id: str | None = None
    tags: str = Field(default="", max_length=200)
    doc_type: str = Field(default="txt", max_length=32)


class DocUpdateIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    clearance: int | None = Field(default=None, ge=0, le=3)
    acl_mode: str | None = None
    owner_dept_id: str | None = None
    tags: str | None = Field(default=None, max_length=200)


class ChunkOut(BaseModel):
    id: str
    seq: int
    content: str


class Citation(BaseModel):
    doc_id: str
    doc_title: str
    clearance: int
    clearance_name: str
    seq: int
    score: float = 0.0
    snippet: str = ""


class ChatIn(BaseModel):
    query: str
    # top_k 夹 0–50：retrieve 的候选池本来就会夹 CANDIDATE_POOL，但调用方
    # 传 9999 应当场被拒（422），而不是靠下游悄悄打折。
    top_k: int = Field(default=0, ge=0, le=50)
    stream: bool = False


class ChatOut(BaseModel):
    answer: str
    citations: list[Citation] = []
    blocked: bool = False
    block_reason: str = ""
    denied_docs: list[dict[str, Any]] = []
    # 若关闭权限控制本会命中的越权文档数——仅统计口径。
    # 注意：该数字对普通用户是强旁路信号（可用于推断高密文档存在与否），故非管理员恒为 0。
    probe_total: int = 0
    masked: bool = False
    degraded: bool = False
    audit_id: str = ""
    jigsaw: dict[str, Any] = {}    # 防拼图裁决报告：level/message/docs/window
    # 意图识别网关结果：level(safe/risky/danger) / action(pass/constrain/block) / signals
    intent: dict[str, Any] = {}
    # 双校验架构指标：mode / coarse(粗筛排除量) / fine(精校验明细) / implicit_verify
    verify: dict[str, Any] = {}
    # Fail-Secure 标记：True 表示本轮已降级为仅公开域作答（未连接内部知识库）
    fail_secure: bool = False
    # 提示注入标记（P1-4）：True = 本轮回答检出疑似注入话术（已留痕，
    # 默认不拦截；INJECT_BLOCK_OUTPUT=true 时回答已被安全拒答替换）
    inject_flag: bool = False


class AuditOut(BaseModel):
    id: str
    ts: str
    username: str
    action: str
    target_label: str = ""
    query: str = ""
    decision: str = ""
    reason: str = ""
    prev_hash: str = ""
    row_hash: str = ""


class StatsOut(BaseModel):
    # 数值字段可空：非管理员/合规角色拿不到全库计数（见 routers/admin.py
    # 的 stats()）——None 而非 0，0 会被读成"没有拦截"，那是假的安全感。
    docs: int | None = None
    chunks: int | None = None
    users: int | None = None
    audits: int | None = None
    denied_7d: int | None = None
    throttled_7d: int | None = None
    jigsaw_risk: int | None = None
    blocked_7d: int | None = None
    storage: str = ""
    llm_mode: str = ""
    embed_mode: str = ""
