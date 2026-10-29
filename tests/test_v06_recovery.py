"""v0.6 step 8: crash recovery - stuck 'executing' -> needs_review, never auto-retried."""
import base64
import pytest
from fastapi.testclient import TestClient


def basic(u, p):
    return {"Authorization": "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    monkeypatch.setenv("PATIENCE_EXECUTE_LIVE", "1")
    import approvers, identity, api
    approvers.add("root", "root-password-1", "admin")
    approvers.add("bob", "bob-password-12", "approver")
    return api, identity.add_agent("a1")


def crash_mid_execution(api, key, monkeypatch, idem="idem-crash-001"):
    from executors.mock import MockExecutor

    class Crash(BaseException):
        pass

    def boom(*a, **k):
        raise Crash  # process dies mid-call (BaseException is not caught by the gateway)
    monkeypatch.setattr(MockExecutor, "run", boom)
    c = TestClient(api.app)
    with pytest.raises(BaseException):
        c.post("/v1/execute", headers={"Authorization": f"Bearer {key}"},
               json={"tool": "lookup_order", "args": {"order": "A1"}, "idempotency_key": idem})
    p = api._engine()
    rid = [r for r in p.state.requests.values() if (r.get("execution") or {}).get("status") == "executing"][0]["request_id"]
    return rid


def test_startup_flags_stuck_as_needs_review(env, monkeypatch):
    api, key = env
    rid = crash_mid_execution(api, key, monkeypatch)
    calls = []
    from executors.mock import MockExecutor
    monkeypatch.setattr(MockExecutor, "run", lambda *a, **k: calls.append(a) or {"ok": True})
    with TestClient(api.app) as c:  # runs startup
        h = {"Authorization": f"Bearer {key}"}
        assert c.get(f"/v1/requests/{rid}", headers=h).json()["status"] == "needs_review"
        r = c.post("/v1/execute", headers=h, json={"tool": "lookup_order", "args": {"order": "A1"},
                                                    "idempotency_key": "idem-crash-001"})
        assert r.status_code == 409 and "review" in r.json()["detail"]
        r = c.post("/v1/execute", headers=h, json={"tool": "lookup_order", "args": {"order": "A1"},
                                                    "idempotency_key": "idem-crash-002", "request_id": rid})
        assert r.status_code == 409
    assert calls == []  # never auto-retried
    import audit
    assert any(e["event"] == "execute.needs_review" for e in audit.read())


def test_admin_reconcile_and_resolve(env, monkeypatch):
    api, key = env
    monkeypatch.setenv("PATIENCE_RECONCILE_ON_STARTUP", "0")
    rid = crash_mid_execution(api, key, monkeypatch)
    c = TestClient(api.app)
    # recent claims are left alone by default (might still be running)
    assert c.post("/v1/admin/reconcile", headers=basic("root", "root-password-1")).json()["flagged"] == []
    r = c.post("/v1/admin/reconcile", headers=basic("root", "root-password-1"), json={"min_age_seconds": 0})
    assert r.json()["flagged"][0]["request_id"] == rid
    assert c.get("/v1/admin/needs_review", headers=basic("root", "root-password-1")).json()["requests"][0]["request_id"] == rid
    r = c.post(f"/v1/admin/requests/{rid}/resolve", headers=basic("root", "root-password-1"),
               json={"outcome": "executed", "note": "checked: it went through"})
    assert r.json()["status"] == "executed"
    assert c.get(f"/v1/requests/{rid}", headers={"Authorization": f"Bearer {key}"}).json()["status"] == "executed"
    assert c.post(f"/v1/admin/requests/{rid}/resolve", headers=basic("root", "root-password-1"),
                  json={"outcome": "failed"}).status_code == 409


def test_reconcile_admin_only(env):
    api, key = env
    c = TestClient(api.app)
    assert c.post("/v1/admin/reconcile", headers=basic("bob", "bob-password-12")).status_code == 403
    assert c.post("/v1/admin/reconcile", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    assert c.post("/v1/admin/reconcile", headers={"X-Approver-Token": "x"}).status_code == 403
    assert c.post("/v1/admin/reconcile").status_code == 403
