import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient

DEMOS = [
    ("[DEMO] Agent wants to summarize this week's class sign-ups for Ascend Collective.", "allow"),
    ("[DEMO] Agent wants to publish a new class schedule to the studio Instagram.", "needs_approval"),
    ("[DEMO] Agent wants to email all 400 members a 20% price increase.", "needs_approval"),
    ("[DEMO] Agent wants to issue refunds to 12 members totaling $1,800.", "needs_approval"),
    ("[DEMO] Agent wants to delete last year's member records to free up space.", "needs_approval"),
    ("what can i use for this information deck", "allow"),
]

@pytest.fixture
def client(tmp_path, monkeypatch):
    for v in ("PATIENCE_LLM_API_KEY", "PATIENCE_API_TOKEN", "PATIENCE_APPROVER_TOKEN"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    import api
    return TestClient(api.app)

def test_health(client):
    assert client.get("/health").json()["status"] == "ok"

@pytest.mark.parametrize("text,expected", DEMOS)
def test_check_demos(client, text, expected, tmp_path):
    r = client.post("/v1/check", json={"action": text, "requester": "test"}).json()
    assert r["decision"] == expected
    st = client.get(f"/v1/requests/{r['request_id']}").json()["status"]
    assert st == ("allowed" if expected == "allow" else "pending")
    if expected == "needs_approval":
        assert r["irreversible"] is True and r["risk_categories"]
        from engine import Patience
        s = Patience(str(tmp_path / "state.json")).state  # same state the dashboard reads
        assert r["approval_key"] in s.blocked_actions and r["approval_key"] not in s.authorized_actions

def test_approve_flow(client, monkeypatch):
    monkeypatch.setenv("PATIENCE_APPROVER_TOKEN", "boss")
    r = client.post("/v1/check", json={"action": DEMOS[3][0]}).json()
    other = client.post("/v1/check", json={"action": DEMOS[4][0]}).json()
    rid = r["request_id"]
    assert client.post(f"/v1/requests/{rid}/approve").status_code == 403
    assert client.post(f"/v1/requests/{rid}/approve", headers={"X-Approver-Token": "nope"}).status_code == 403
    ok = client.post(f"/v1/requests/{rid}/approve", headers={"X-Approver-Token": "boss"})
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    assert client.get(f"/v1/requests/{rid}").json()["status"] == "approved"
    assert client.get(f"/v1/requests/{other['request_id']}").json()["status"] == "pending"  # per-request
    d = client.post(f"/v1/requests/{other['request_id']}/deny", headers={"X-Approver-Token": "boss"})
    assert d.json()["status"] == "denied"

def test_approvals_disabled_without_token(client):
    r = client.post("/v1/check", json={"action": DEMOS[3][0]}).json()
    resp = client.post(f"/v1/requests/{r['request_id']}/approve", headers={"X-Approver-Token": "x"})
    assert resp.status_code == 403 and "Approver login required" in resp.json()["detail"]

def test_dashboard_approval_visible_via_api(client, tmp_path):
    r = client.post("/v1/check", json={"action": DEMOS[2][0]}).json()
    from engine import Patience
    Patience(str(tmp_path / "state.json")).authorize(r["approval_key"])  # what the Authorize button does
    assert client.get(f"/v1/requests/{r['request_id']}").json()["status"] == "approved"

def test_duplicate_pending_defers(client):
    client.post("/v1/check", json={"action": DEMOS[4][0]})
    assert client.post("/v1/check", json={"action": DEMOS[4][0]}).json()["decision"] == "defer"

def test_caller_auth(client, monkeypatch):
    monkeypatch.setenv("PATIENCE_API_TOKEN", "secret")
    assert client.post("/v1/check", json={"action": "hi"}).status_code == 401
    assert client.post("/v1/check", json={"action": "hi"}, headers={"Authorization": "Bearer bad"}).status_code == 401
    ok = client.post("/v1/check", json={"action": "hi"}, headers={"Authorization": "Bearer secret"})
    assert ok.status_code == 200
    assert client.get(f"/v1/requests/{ok.json()['request_id']}").status_code == 401
    assert client.get("/health").status_code == 200

def test_concurrent_writes_not_lost(tmp_path):
    import threading
    from engine import Patience
    path = str(tmp_path / "c.json")
    def go(i):
        Patience(path).cycle(f"note {i}")
    ts = [threading.Thread(target=go, args=(i,)) for i in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(Patience(path).state.observations) == 20
