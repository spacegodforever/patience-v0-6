"""v0.6 steps 1-2: per-approver accounts and the tamper-evident audit log."""
import base64, json, os, subprocess, sys
import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    monkeypatch.delenv("PATIENCE_API_TOKEN", raising=False)
    import approvers, identity, api
    approvers.add("alice", "alice-password-1", "admin", pin="123456")
    approvers.add("bob", "bob-password-12", "approver")
    key = identity.add_agent("agent1")
    return TestClient(api.app), key


def risky(c, key):
    r = c.post("/v1/check", headers={"Authorization": f"Bearer {key}"},
               json={"tool": "refund", "args": {"amount": 5000, "order": "A1"}})
    assert r.json()["decision"] == "needs_approval"
    return r.json()["request_id"]


# ---- accounts ----
def test_passwords_and_pins_stored_as_scrypt(c, tmp_path):
    raw = (tmp_path / "approvers.yaml").read_text()
    assert "alice-password-1" not in raw and "123456" not in raw and raw.count("scrypt$") == 3


def test_weak_password_and_pin_rejected():
    import approvers
    with pytest.raises(ValueError):
        approvers.add("x", "short")
    with pytest.raises(ValueError):
        approvers.add("x", "long-enough-pw", pin="12")
    with pytest.raises(ValueError):
        approvers.add("x", "long-enough-pw", role="god")


def test_approval_records_approver_time_reason(c):
    client, key = c
    rid = risky(client, key)
    r = client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "bob-password-12"),
                    json={"reason": "customer verified"})
    assert r.status_code == 200 and r.json()["approver"] == "bob"
    import api, audit
    st = api._engine().state
    d = st.requests[rid]["decided"]
    assert d["approver"] == "bob" and d["reason"] == "customer verified" and d["at"] and d["via"] == "api"
    assert st.approval_log[-1]["approver"] == "bob"
    ev = [x for x in audit.read() if x["event"] == "approval.approved"]
    assert ev and ev[-1]["actor"] == "bob" and ev[-1]["data"]["reason"] == "customer verified"


def test_denial_records_reason(c):
    client, key = c
    rid = risky(client, key)
    client.post(f"/v1/requests/{rid}/deny", headers=basic("alice", "alice-password-1"), json={"reason": "fraud"})
    import api
    assert api._engine().state.requests[rid]["decided"]["reason"] == "fraud"


def test_bad_credentials_and_agent_keys_cannot_approve(c):
    client, key = c
    rid = risky(client, key)
    assert client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "wrong")).status_code == 403
    assert client.post(f"/v1/requests/{rid}/approve", headers=basic("mallory", "x" * 12)).status_code == 403
    assert client.post(f"/v1/requests/{rid}/approve", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    import audit
    assert any(x["event"] == "auth.failed" for x in audit.read())


def test_disabled_approver_rejected(c):
    client, key = c
    import approvers
    approvers.disable("bob")
    rid = risky(client, key)
    assert client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "bob-password-12")).status_code == 403


def test_brute_force_throttled(c):
    client, key = c
    rid = risky(client, key)
    for _ in range(5):
        client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "nope"))
    assert client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "bob-password-12")).status_code == 403


def test_legacy_token_needs_explicit_flag(c, monkeypatch):
    client, key = c
    monkeypatch.setenv("PATIENCE_APPROVER_TOKEN", "shared")
    monkeypatch.delenv("PATIENCE_LEGACY_APPROVER_TOKEN")
    rid = risky(client, key)
    assert client.post(f"/v1/requests/{rid}/approve", headers={"X-Approver-Token": "shared"}).status_code == 403
    monkeypatch.setenv("PATIENCE_LEGACY_APPROVER_TOKEN", "1")
    r = client.post(f"/v1/requests/{rid}/approve", headers={"X-Approver-Token": "shared"})
    assert r.status_code == 200 and r.json()["approver"] == "legacy-token"


# ---- audit log ----
def test_audit_chain_records_check_approve_execute(c, monkeypatch):
    client, key = c
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    from executors.mock import MockExecutor
    MockExecutor.reset()
    H = {"Authorization": f"Bearer {key}"}
    body = {"tool": "refund", "args": {"amount": 5000, "order": "A1"}, "idempotency_key": "audit-key-1"}
    rid = client.post("/v1/execute", headers=H, json=body).json()["request_id"]
    client.post(f"/v1/requests/{rid}/approve", headers=basic("bob", "bob-password-12"))
    assert client.post("/v1/execute", headers=H, json={**body, "idempotency_key": "audit-key-2",
                                                        "request_id": rid}).status_code == 200
    import audit
    events = [x["event"] for x in audit.read()]
    for e in ("check", "approval.approved", "execute.claimed", "execute.executed"):
        assert e in events
    assert audit.verify()["ok"]


def _log(n=4):
    import audit
    for i in range(n):
        audit.append("test", "me", i=i)
    return audit.path()


def _rewrite(p, lines):
    p.write_text("".join(l + "\n" for l in lines))


def test_tampered_record_detected():
    import audit
    p = _log()
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["data"]["i"] = 99
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    _rewrite(p, lines)
    r = audit.verify()
    assert not r["ok"] and "modified" in r["error"]


def test_rehashed_record_breaks_chain():
    import audit
    p = _log()
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1]); rec["data"]["i"] = 99; rec["hash"] = audit._digest(rec)
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    _rewrite(p, lines)
    assert not audit.verify()["ok"]


def test_deleted_reordered_truncated_detected():
    import audit
    p = _log()
    good = p.read_text().splitlines()
    _rewrite(p, good[:1] + good[2:]);  assert not audit.verify()["ok"]
    _rewrite(p, [good[1], good[0]] + good[2:]);  assert not audit.verify()["ok"]
    _rewrite(p, good[:-1]);  r = audit.verify(); assert not r["ok"] and "truncated" in r["error"]
    _rewrite(p, good);  assert audit.verify()["ok"]


def test_audit_cli_verify_exit_codes(tmp_path):
    p = _log()
    env = {**os.environ, "PATIENCE_AUDIT_PATH": str(p)}
    ok = subprocess.run([sys.executable, "audit.py", "verify"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert ok.returncode == 0 and "OK" in ok.stdout
    p.write_text(p.read_text().replace('"i":2', '"i":7'))
    bad = subprocess.run([sys.executable, "audit.py", "verify"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert bad.returncode == 1 and "TAMPERED" in bad.stdout


def test_dashboard_shows_audit_status(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "d.json"))
    p = _log()
    monkeypatch.chdir(ROOT)
    at = AppTest.from_file(os.path.join(ROOT, "dashboard.py"), default_timeout=30).run()
    assert any("chain intact" in s.value for s in at.sidebar.success)
    p.write_text(p.read_text().replace('"i":2', '"i":7'))
    at = AppTest.from_file(os.path.join(ROOT, "dashboard.py"), default_timeout=30).run()
    assert any("TAMPERED" in s.value for s in at.sidebar.error)
