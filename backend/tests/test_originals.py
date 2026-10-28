# SPDX-License-Identifier: AGPL-3.0-only
"""原件留存（app/originals.py + routers/originals.py）。

要钉死的口径：
  · 开关关闭 → 行为与改造前完全一致：不写对象存储、不产生台账、不留审计；
  · 开关打开 → 原件按 doc_id/版本 定位，sha256 同时落台账与对象元数据；
  · 写失败：默认宽容（文档照常入库，但 original.stored=false + 审计 flag），
    严格模式则回滚整次入库（绝不留下"有文档、没原件、看不出来"的半成品）；
  · 审查端：仅管理员、且受密级闸门约束；原件哈希与台账不一致时拒发；
  · 每次下载/复核都留审计，普通用户拿不到原件。
"""
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app import audit, blobstore, config
from app.main import app as real_app
from app.models import AuditLog, DocumentVersion, User, new_id
from app.security import hash_password
from sqlalchemy import select

API = "/api/v1"
PWD = "Original-Test!2026"


class FakeStore:
    """进程内 S3 替身：只实现 originals.py 用到的四个方法。"""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.meta: dict[str, dict] = {}
        self.fail = None

    def put(self, key: str, data: bytes, digest: str = "") -> dict:
        if self.fail is not None:
            raise self.fail
        self.objects[key] = data
        self.meta[key] = {"sha256": digest or hashlib.sha256(data).hexdigest()}
        return {"key": key, "size": len(data), "etag": "etag",
                "sha256": digest or hashlib.sha256(data).hexdigest()}

    def get_bytes(self, key: str, max_bytes: int | None = None) -> bytes:
        if key not in self.objects:
            raise blobstore.OriginalStoreError(f"no such object: {key}")
        data = self.objects[key]
        if max_bytes and len(data) > max_bytes:
            raise blobstore.OriginalStoreError("too large")
        return data

    def stat(self, key: str) -> dict:
        if key not in self.objects:
            raise blobstore.OriginalStoreError(f"no such object: {key}")
        return {"key": key, "size": len(self.objects[key]), "etag": "etag",
                "sha256": self.meta.get(key, {}).get("sha256", "")}


@pytest.fixture
def client():
    return TestClient(real_app)


@pytest.fixture
def store(monkeypatch):
    """开启原件留存并把后端换成 FakeStore（不打真实对象存储）。"""
    fake = FakeStore()
    monkeypatch.setattr(config, "ORIGINAL_STORE_ENABLED", True)
    monkeypatch.setattr(config, "ORIGINAL_STORE_STRICT", False)
    monkeypatch.setattr(config, "ORIGINAL_STORE_BUCKET", "finrag-originals")
    monkeypatch.setattr(config, "ORIGINAL_STORE_PREFIX", "originals")
    monkeypatch.setattr(config, "ORIGINAL_STORE_GET_MAX_MB", 32)
    monkeypatch.setattr(blobstore, "get_store", lambda: fake)
    return fake


def _mk_user(db, name, *, clearance=1, roles=("research",)):
    pwd, salt = hash_password(PWD)
    u = User(id=new_id(), username=name, display_name=name, clearance=clearance,
             roles=json.dumps(list(roles)), pwd_hash=pwd, salt=salt, status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.commit()
    return u


def _hdr(client, name):
    r = client.post(f"{API}/auth/login", json={"username": name, "password": PWD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _upload(client, hdr, content=b"finrag original retention test\n", name="a.txt",
            title="原件样本", clearance=1, acl_mode="open"):
    return client.post(
        f"{API}/docs/upload", headers=hdr,
        files={"file": (name, content, "text/plain")},
        data={"title": title, "clearance": str(clearance), "acl_mode": acl_mode},
    )


def _logs(db, action):
    audit.flush_audit()
    db.expire_all()
    return db.execute(select(AuditLog).where(AuditLog.action == action)).scalars().all()


# ------------------------------------------------------------------ 键与开关


def test_key_layout_uses_server_side_fields_only():
    """对象键只由 doc_id / 版本 / 白名单后缀拼出，用户文件名不参与。"""
    assert blobstore.key_for("d-1", 2, "PDF") == "originals/d-1/v2/original.pdf"
    assert blobstore.key_for("d-1", 1, "") == "originals/d-1/v1/original.bin"
    risky = blobstore.key_for("d-1", 1, "../../etc/passwd")
    assert ".." not in risky and "/etc/" not in risky
    assert risky.startswith("originals/d-1/v1/original.")


def test_disabled_switch_returns_none(monkeypatch):
    monkeypatch.setattr(config, "ORIGINAL_STORE_ENABLED", False)
    blobstore.reset_store()
    assert blobstore.get_store() is None


def test_disabled_switch_skips_ledger_and_audit(db, client, monkeypatch):
    """关闭时与改造前一致：响应说没启用，版本台账没有原件列，不写 store_original。"""
    monkeypatch.setattr(config, "ORIGINAL_STORE_ENABLED", False)
    blobstore.reset_store()
    _mk_user(db, "origin_off")
    hdr = _hdr(client, "origin_off")
    r = _upload(client, hdr)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["original"]["enabled"] is False and body["original"]["stored"] is False
    db.expire_all()
    row = db.execute(select(DocumentVersion)
                     .where(DocumentVersion.doc_id == body["id"])).scalars().first()
    assert row is not None and row.original_key == ""
    assert _logs(db, "store_original") == []


# ------------------------------------------------------------------ 上传写入


def test_upload_stores_original_and_records_ledger(db, client, store):
    payload = b"secret-bytes-0123456789\n" * 10
    _mk_user(db, "origin_on")
    hdr = _hdr(client, "origin_on")
    r = _upload(client, hdr, payload)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["original"]["stored"] is True
    digest = hashlib.sha256(payload).hexdigest()
    assert body["original"]["sha256"] == digest
    assert body["original"]["size"] == len(payload)

    key = blobstore.key_for(body["id"], 1, "txt")
    assert store.objects[key] == payload
    assert store.meta[key]["sha256"] == digest

    db.expire_all()
    row = db.execute(select(DocumentVersion)
                     .where(DocumentVersion.doc_id == body["id"])).scalars().first()
    assert row.original_key == key
    assert row.original_sha256 == digest
    assert row.original_size == len(payload)
    assert row.original_stored_at is not None

    logs = _logs(db, "store_original")
    assert len(logs) == 1 and logs[0].decision == "allow"
    assert digest[:16] in logs[0].reason


def test_non_strict_failure_keeps_doc_but_flags(db, client, store):
    """默认宽容：对象存储故障不该让知识库停摆，但必须显性标记缺失。"""
    store.fail = blobstore.OriginalStoreError("uplink down")
    _mk_user(db, "origin_soft")
    hdr = _hdr(client, "origin_soft")
    r = _upload(client, hdr, b"still ingestible\n")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["original"]["enabled"] is True and body["original"]["stored"] is False
    assert "uplink down" in body["original"]["reason"]

    db.expire_all()
    row = db.execute(select(DocumentVersion)
                     .where(DocumentVersion.doc_id == body["id"])).scalars().first()
    assert row is not None and row.original_key == ""
    logs = _logs(db, "store_original")
    assert len(logs) == 1 and logs[0].decision == "flag"


def test_strict_failure_rejects_upload_and_rolls_back(db, client, store, monkeypatch):
    """「承诺留存却悄悄没留」最难排查：严格模式宁可拒绝入库。"""
    monkeypatch.setattr(config, "ORIGINAL_STORE_STRICT", True)
    store.fail = blobstore.OriginalStoreError("bucket forbidden")
    _mk_user(db, "origin_strict")
    hdr = _hdr(client, "origin_strict")
    r = _upload(client, hdr, b"must not be kept\n")
    assert r.status_code == 503, r.text

    db.expire_all()
    assert db.execute(select(DocumentVersion)).scalars().all() == []
    from app.models import Document
    assert db.execute(select(Document)).scalars().all() == []
    deny = [x for x in _logs(db, "upload") if x.decision == "deny"]
    assert len(deny) == 1 and "已回滚入库" in deny[0].reason


# ------------------------------------------------------------------ 审查端


def test_meta_requires_admin(db, client, store):
    _mk_user(db, "origin_plain")
    admin = _mk_user(db, "origin_admin", clearance=3, roles=("admin",))
    assert admin.id
    hdr_plain = _hdr(client, "origin_plain")
    r = _upload(client, hdr_plain)
    doc_id = r.json()["id"]

    assert client.get(f"{API}/admin/documents/{doc_id}/original/meta").status_code == 401
    assert client.get(f"{API}/admin/documents/{doc_id}/original/meta",
                      headers=hdr_plain).status_code == 403


def test_meta_lists_versions_with_original(db, client, store):
    _mk_user(db, "origin_meta")
    _mk_user(db, "origin_meta_admin", clearance=3, roles=("admin",))
    hdr = _hdr(client, "origin_meta")
    body = _upload(client, hdr, b"v1 bytes\n").json()
    ahdr = _hdr(client, "origin_meta_admin")

    r = client.get(f"{API}/admin/documents/{body['id']}/original/meta", headers=ahdr)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["enabled"] is True and data["total"] == 1
    item = data["items"][0]
    assert item["stored"] is True and item["version"] == 1 and item["is_current"] is True
    assert item["size"] == len(b"v1 bytes\n")
    assert item["sha256"] == hashlib.sha256(b"v1 bytes\n").hexdigest()


def test_download_returns_bytes_with_hash_header_and_audit(db, client, store):
    _mk_user(db, "origin_get")
    _mk_user(db, "origin_get_admin", clearance=3, roles=("admin",))
    body = _upload(client, _hdr(client, "origin_get"), b"download-me\n").json()
    ahdr = _hdr(client, "origin_get_admin")

    r = client.get(f"{API}/admin/documents/{body['id']}/original", headers=ahdr)
    assert r.status_code == 200, r.text
    assert r.content == b"download-me\n"
    digest = hashlib.sha256(b"download-me\n").hexdigest()
    assert r.headers["x-original-sha256"] == digest
    assert r.headers["x-original-version"] == "1"
    assert r.headers["cache-control"] == "no-store"
    assert "attachment" in r.headers["content-disposition"]

    logs = [x for x in _logs(db, "view_original") if x.decision == "allow"]
    assert len(logs) == 1 and digest[:16] in logs[0].reason


def test_download_denied_below_clearance(db, client, store):
    """admin 不等于能读一切：密级不够一律 404 掩码（存在性也是敏感信息）。"""
    _mk_user(db, "origin_lowadmin", clearance=1, roles=("admin",))
    _mk_user(db, "origin_conf", clearance=3)
    body = _upload(client, _hdr(client, "origin_conf"), b"top secret\n",
                   clearance=3).json()
    low = _hdr(client, "origin_lowadmin")
    r = client.get(f"{API}/admin/documents/{body['id']}/original", headers=low)
    assert r.status_code == 404
    deny = [x for x in _logs(db, "view_original") if x.decision == "deny"]
    assert len(deny) == 1 and "密级" in deny[0].reason


def test_download_refuses_tampered_object(db, client, store):
    """对象被替换时必须拒发：把不一致的字节交给审查端比报错危险得多。"""
    _mk_user(db, "origin_tamper")
    _mk_user(db, "origin_tamper_admin", clearance=3, roles=("admin",))
    body = _upload(client, _hdr(client, "origin_tamper"), b"original content\n").json()
    key = blobstore.key_for(body["id"], 1, "txt")
    store.objects[key] = b"tampered content!\n"
    ahdr = _hdr(client, "origin_tamper_admin")

    r = client.get(f"{API}/admin/documents/{body['id']}/original", headers=ahdr)
    assert r.status_code == 409, r.text
    deny = [x for x in _logs(db, "view_original") if x.decision == "deny"]
    assert len(deny) == 1 and "不一致" in deny[0].reason


def test_verify_reports_match_then_mismatch(db, client, store):
    _mk_user(db, "origin_verify")
    _mk_user(db, "origin_verify_admin", clearance=3, roles=("admin",))
    body = _upload(client, _hdr(client, "origin_verify"), b"verify me\n").json()
    ahdr = _hdr(client, "origin_verify_admin")

    ok = client.post(f"{API}/admin/documents/{body['id']}/original/verify",
                     headers=ahdr).json()
    assert ok["ok"] is True and ok["expected"] == ok["actual"]

    store.objects[blobstore.key_for(body["id"], 1, "txt")] = b"swapped\n"
    bad = client.post(f"{API}/admin/documents/{body['id']}/original/verify",
                      headers=ahdr).json()
    assert bad["ok"] is False and bad["expected"] != bad["actual"]
    flags = [x for x in _logs(db, "verify_original") if x.decision == "flag"]
    assert len(flags) == 1


def test_verify_without_original_is_explicit(db, client, monkeypatch):
    """没有原件时不得返回"一致"：明确 ok=false + 原因。"""
    monkeypatch.setattr(config, "ORIGINAL_STORE_ENABLED", False)
    blobstore.reset_store()
    _mk_user(db, "origin_none")
    _mk_user(db, "origin_none_admin", clearance=3, roles=("admin",))
    body = _upload(client, _hdr(client, "origin_none")).json()
    ahdr = _hdr(client, "origin_none_admin")
    out = client.post(f"{API}/admin/documents/{body['id']}/original/verify",
                      headers=ahdr).json()
    assert out["ok"] is False and "未启用" in out["reason"]


def test_versions_endpoint_exposes_original_flag(db, client, store):
    _mk_user(db, "origin_ver")
    body = _upload(client, _hdr(client, "origin_ver"), b"versioned\n").json()
    r = client.get(f"{API}/docs/{body['id']}/versions", headers=_hdr(client, "origin_ver"))
    assert r.status_code == 200, r.text
    original = r.json()["versions"][0]["original"]
    assert original["stored"] is True and original["size"] == len(b"versioned\n")
