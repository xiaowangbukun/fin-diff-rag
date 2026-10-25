# SPDX-License-Identifier: Apache-2.0
"""审计锚点外置（P0-2 增强）：把链尾追加到应用不可回写的位置。

为什么这组用例重要：
  · 本地锚点（data/audit_anchor.json）与库同生共灭，拿到"库写 + 应用磁盘写"
    双权限的人可以重算全链并改写锚点——外置记录是唯一的独立见证。
  · 外置记录必须带签名：否则网关侧/文件里的一条普通 JSON 就能冒充锚点，
    把"被截断"伪装成"正常"。
  · 外置 sink 故障绝不能影响审计写入：合规底线不能被外部依赖拖垮。
"""
import http.server
import json
import threading
import time
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app import anchors, audit, config
from app.main import app as real_app
from app.models import AuditLog, User, new_id
from app.security import hash_password

API = "/api/v1"


@pytest.fixture
def anchor_file(tmp_path, monkeypatch):
    path = tmp_path / "worm" / "audit_anchor.jsonl"
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", str(path))
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_INTERVAL_SECONDS", 0.0)
    anchors.reset_state()
    yield path
    anchors.reset_state()


@pytest.fixture(autouse=True)
def _reset_anchor_state():
    anchors.reset_state()
    yield
    anchors.reset_state()


def _tail(db):
    return audit.resume_chain(db)


# ---------------------------------------------------------------- 单元口径

def test_emit_appends_signed_record(anchor_file):
    record = anchors.emit("H" * 64, 7, force=True)
    assert record and record["seq"] == 7
    lines = anchor_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    saved = json.loads(lines[0])
    assert saved["sig"] and saved["sig"] == record["sig"]
    assert saved["tail_hash"] == "H" * 64
    # 只追加：第二次外发不重写既有行
    anchors.emit("G" * 64, 8, force=True)
    assert len(anchor_file.read_text(encoding="utf-8").strip().splitlines()) == 2
    records = anchors.read_external()
    assert [r["seq"] for r in records] == [7, 8]
    assert all(r["sig_ok"] for r in records)


def test_check_still_finds_anchor_when_row_batches_flood_the_tail(anchor_file):
    """行副本把尾部灌满后，启动比对不能退化成"暂无记录"。

    锚点按 INTERVAL 限频、行副本按批次写入，高峰期尾部几百行可能全是
    audit_rows。若 check() 只扫最近 200 行就断言"外置锚点暂无记录"，
    截断检测会在最需要它的时刻（正是刚被大量写入之后重启）静默失效。
    """
    anchors.emit("A" * 64, 100, force=True)          # 一条已验证锚点
    for i in range(300):                              # 之后灌入 300 条行副本
        anchors.ship_rows([{"seq": 100 + i, "row_hash": f"{i:064d}",
                           "prev_hash": "", "ts": "", "action": "qa",
                           "decision": "allow", "username": "u",
                           "target_label": "", "ip": ""}])
    assert len(anchors.read_external(limit=200)) == 200   # 尾部全是行副本
    # 库内尾行序号 90 < 锚点 100 → 必须判定为截断
    res = anchors.check("B" * 64, 90)
    assert res["truncated"] is True
    assert res["external_seq"] == 100


def test_read_external_reads_only_tail(anchor_file):
    """巡检只读尾部 N 行：外置 sink 是半年期只追加文件，整文件读入不可接受。

    这条用例同时验证跨块读取（每块 64KB，300 条约 90KB）不会截断首行或多读。
    """
    for i in range(1, 301):
        anchors.emit(f"{'H' * 63}{i % 10}", i, force=True)
    records = anchors.read_external(limit=5)
    assert [r["seq"] for r in records] == [296, 297, 298, 299, 300]
    assert all(r["sig_ok"] for r in records)
    # limit 大于文件行数时返回全部（不倒序、不丢行）
    assert len(anchors.read_external(limit=1000)) == 300


def test_tampered_external_record_fails_signature(anchor_file):
    """防：改文件里的序号/哈希，把截断伪装成正常。"""
    anchors.emit("H" * 64, 7, force=True)
    lines = anchor_file.read_text(encoding="utf-8").strip().splitlines()
    forged = json.loads(lines[0])
    forged["seq"] = 6                      # 攻击者想"少一行"
    anchor_file.write_text(json.dumps(forged, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    records = anchors.read_external()
    assert records[0]["sig_ok"] is False


def test_emit_is_rate_limited_but_force_bypasses(anchor_file):
    assert anchors.emit("H" * 64, 3) is not None
    # 同一 seq、间隔内：跳过（避免每批审计都写一次 WORM）
    assert anchors.emit("H" * 64, 3) is None
    # seq 前进但间隔未到：仍跳过
    assert anchors.emit("H" * 64, 4) is None
    assert anchors.emit("H" * 64, 4, force=True) is not None
    assert len(anchors.read_external()) == 2


def test_key_rotation_is_distinguished_from_tampering(anchor_file, monkeypatch):
    """防误报：轮换签名密钥后历史记录必然验签失败，不能一律算成"被伪造"。

    没有这层区分时，只要运维把 AUDIT_ANCHOR_HMAC_KEY 从"派生自 JWT"改成
    独立值，巡检就会报出成百上千条 bad_signature，真正被篡改的那条反而
    被噪声淹没。key_id 让"旧密钥下的记录"可解释、单列且依旧不采信。
    """
    monkeypatch.setattr(config, "AUDIT_ANCHOR_HMAC_KEY", "old-key-0001")
    anchors.emit("A" * 64, 21, force=True)
    old_records = anchors.read_external()
    assert old_records[0]["sig_ok"] is True
    assert old_records[0]["key_id"] == anchors.key_id()

    monkeypatch.setattr(config, "AUDIT_ANCHOR_HMAC_KEY", "new-key-0002")
    rotated = anchors.read_external()
    assert rotated[0]["sig_ok"] is False
    assert rotated[0]["sig_state"] == "stale_key"

    status = anchors.check("B" * 64, 21)
    assert status["bad_signature"] == 0, "旧密钥记录不应被算作疑似篡改"
    assert status["stale_key_records"] == 1
    assert status["key_id"] == anchors.key_id()
    # 不可验证的记录永远不参与"链尾是否被改"的裁决
    assert status["external_seq"] == 0

    # 新密钥下的记录恢复正常，且与旧记录在同一只追加流里互不干扰
    anchors.emit("C" * 64, 22, force=True)
    latest = anchors.check("C" * 64, 22)
    assert latest["ok"] is True and latest["external_seq"] == 22
    assert latest["stale_key_records"] == 1


def test_forged_record_with_wrong_key_id_is_not_whitelisted(anchor_file, monkeypatch):
    """防绕过：改了内容的记录不能靠"伪造一个陌生 key_id"混进旧密钥豁免里。

    分类只影响**统计口径**，不影响信任判定——任何时候只有验签通过的记录
    才会被用于链尾比对；被改过的记录无论被归到哪一类都不会被采信。
    """
    anchors.emit("A" * 64, 31, force=True)
    lines = anchor_file.read_text(encoding="utf-8").strip().splitlines()
    forged = json.loads(lines[0])
    forged["tail_hash"] = "Z" * 64
    forged["key_id"] = "deadbeefcafe"        # 冒充"另一把密钥"下的记录
    anchor_file.write_text(json.dumps(forged, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    status = anchors.check("A" * 64, 31)
    assert status["external_seq"] == 0
    assert status["bad_signature"] + status["stale_key_records"] == 1
    # 关键：伪记录没有被当作可信锚点（否则会误判成"链尾被改"或"正常"）
    assert status["tampered"] is False and status["truncated"] is False


def test_startup_warning_only_without_dedicated_key(anchor_file, monkeypatch):
    """sink 启用但没配独立 HMAC 密钥 → 启动必须明确告警（不静默耦合 JWT）。"""
    monkeypatch.setattr(config, "AUDIT_ANCHOR_HMAC_KEY", "")
    assert "JWT_SECRET" in anchors.startup_warning()

    monkeypatch.setattr(config, "AUDIT_ANCHOR_HMAC_KEY", "dedicated-key-123")
    assert anchors.startup_warning() == ""

    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_HMAC_KEY", "")
    assert anchors.startup_warning() == "", "没配 sink 就不该告警"


def test_check_detects_truncation_and_tampered_tail(anchor_file):
    anchors.emit("A" * 64, 9, force=True)
    ok = anchors.check("A" * 64, 9)
    assert ok["ok"] is True and ok["truncated"] is False

    trunc = anchors.check("B" * 64, 8)      # 库内少了一行
    assert trunc["ok"] is False and trunc["truncated"] is True
    assert trunc["external_seq"] == 9 and trunc["db_seq"] == 8

    tamper = anchors.check("B" * 64, 9)     # 序号相同但链尾哈希不符
    assert tamper["ok"] is False and tamper["tampered"] is True


def test_disabled_sink_is_noop():
    assert anchors.enabled() is False
    assert anchors.emit("H" * 64, 5, force=True) is None
    assert anchors.read_external() == []
    assert anchors.check("H" * 64, 5)["ok"] is True


def test_http_sink_receives_record_with_signature(monkeypatch):
    """POST sink：网关侧能拿到可验签的锚点（签名走 header 与 body 双份）。"""
    received: list[dict] = []
    headers_seen: list[dict] = []

    class _H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8"))
            received.append(body)
            headers_seen.append({"sig": self.headers.get("X-Finrag-Signature"),
                                 "kind": self.headers.get("X-Finrag-Kind")})
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):   # 静音
            return

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
        monkeypatch.setattr(config, "AUDIT_ANCHOR_URL",
                            f"http://127.0.0.1:{srv.server_port}/anchor")
        monkeypatch.setattr(config, "AUDIT_ANCHOR_INTERVAL_SECONDS", 0.0)
        rec = anchors.emit("C" * 64, 12, force=True)
        assert rec is not None
        assert received and received[0]["seq"] == 12
        assert headers_seen[0]["sig"] == rec["sig"]
        assert headers_seen[0]["kind"] == "audit-anchor"
        body = dict(received[0])
        sig = body.pop("sig")
        assert anchors._sign(body) == sig          # 网关侧可独立验签
    finally:
        srv.shutdown()
        srv.server_close()


def test_unreachable_http_sink_never_raises(monkeypatch):
    """防：日志网关挂掉导致审计写入失败（合规底线不能被外部依赖拖垮）。"""
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "http://127.0.0.1:1/anchor")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(config, "AUDIT_ANCHOR_TIMEOUT", 1)
    assert anchors.emit("D" * 64, 13, force=True) is None   # 失败返回 None
    # 失败不抛：调用方（audit）继续正常写审计
    assert anchors.check("D" * 64, 13)["enabled"] is True


# ---------------------------------------------------------------- 与链联动

def test_chain_truncation_detected_by_external_anchor(db, anchor_file):
    """删尾行截断：本地锚点被同步篡改后，外置锚点仍能检出。"""
    for i in range(3):
        audit.write_log(db, action="search", reason=f"row {i}", sync=True)
    tail = audit.resume_chain(db)
    assert tail["seq"] >= 3
    latest = anchors.read_external()[-1]
    assert latest["seq"] == tail["seq"]

    # 模拟攻击者：删掉最新一行，并把本地锚点改成"正常"的样子
    row = db.query(AuditLog).filter(AuditLog.seq == tail["seq"]).one()
    db.delete(row)
    db.commit()
    audit.ANCHOR_FILE.write_text(json.dumps(
        {"tail_hash": "deadbeef", "seq": tail["seq"] - 1}), encoding="utf-8")

    audit.resume_chain(db)          # 模拟重启
    alarms = [r for r in db.query(AuditLog).filter(AuditLog.action == "system").all()
              if "外置锚点" in (r.reason or "")]
    assert alarms, "外置锚点应检出尾行被截断"
    assert "截断" in alarms[0].reason


def test_anchor_survives_restart_and_matches_db(db, anchor_file):
    audit.write_log(db, action="search", reason="a", sync=True)
    audit.write_log(db, action="search", reason="b", sync=True)
    tail = audit.resume_chain(db)
    assert anchors.check(tail["tail_hash"], tail["seq"])["ok"] is True


# ---------------------------------------------------------------- HTTP 接口

@pytest.fixture
def client():
    return TestClient(real_app)


def _mk_user(db, username, roles, clearance=1, password="Adm1n-Passw0rd!2026"):
    pwd_hash, salt = hash_password(password)
    u = User(id=new_id(), username=username, display_name=username,
             clearance=clearance, roles=json.dumps(roles),
             pwd_hash=pwd_hash, salt=salt, status=True,
             must_change_password=False, token_version=0)
    db.add(u)
    db.commit()
    return u


def test_admin_can_flush_and_inspect_anchor(db, client, anchor_file):
    _mk_user(db, "root", ["admin"], clearance=3)
    token = client.post(f"{API}/auth/login",
                        json={"username": "root",
                              "password": "Adm1n-Passw0rd!2026"}).json()["token"]
    hdr = {"Authorization": f"Bearer {token}"}

    status0 = client.get(f"{API}/admin/audit/anchor", headers=hdr).json()
    assert status0["external"]["enabled"] is True
    assert status0["external"]["file"] is True

    flushed = client.post(f"{API}/admin/audit/anchor", headers=hdr)
    assert flushed.status_code == 200, flushed.text
    assert flushed.json()["seq"] >= 1
    assert flushed.json()["sig"]

    status1 = client.get(f"{API}/admin/audit/anchor", headers=hdr).json()
    assert status1["external"]["records"] >= 1
    assert status1["external"]["bad_signature"] == 0


def test_non_admin_cannot_read_or_flush_anchor(db, client, anchor_file):
    _mk_user(db, "bob", ["research"])
    token = client.post(f"{API}/auth/login",
                        json={"username": "bob",
                              "password": "Adm1n-Passw0rd!2026"}).json()["token"]
    hdr = {"Authorization": f"Bearer {token}"}
    assert client.get(f"{API}/admin/audit/anchor", headers=hdr).status_code == 403
    assert client.post(f"{API}/admin/audit/anchor", headers=hdr).status_code == 403


def test_flush_without_sink_returns_400(db, client, monkeypatch):
    monkeypatch.setattr(config, "AUDIT_ANCHOR_EXTERNAL_FILE", "")
    monkeypatch.setattr(config, "AUDIT_ANCHOR_URL", "")
    _mk_user(db, "root2", ["admin"], clearance=3)
    token = client.post(f"{API}/auth/login",
                        json={"username": "root2",
                              "password": "Adm1n-Passw0rd!2026"}).json()["token"]
    r = client.post(f"{API}/admin/audit/anchor",
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
    assert "AUDIT_ANCHOR" in r.json()["detail"]
