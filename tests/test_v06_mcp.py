"""v0.6 step 6: MCP server tools, wired in-process to the real API (no network)."""
import asyncio, json, os, sys, subprocess
import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    import identity, api, patience_mcp
    key = identity.add_agent("mcp-agent")
    monkeypatch.setenv("PATIENCE_AGENT_KEY", key)
    client = TestClient(api.app)

    def call(method, path, body=None):
        r = client.request(method, path, json=body, headers={"Authorization": f"Bearer {os.environ['PATIENCE_AGENT_KEY']}"})
        return r.json() if r.status_code < 400 else {"error": f"HTTP {r.status_code}", "detail": r.json().get("detail")}
    monkeypatch.setattr(patience_mcp, "_call", call)
    return patience_mcp


def test_tools_registered(m):
    tools = asyncio.run(m.server.list_tools())
    names = {t.name for t in tools}
    assert {"check_action", "execute_action", "request_status"} <= names


def test_check_and_status(m):
    r = m.check_action(tool="refund", args={"amount": 5000, "order": "A1"})
    assert r["decision"] == "needs_approval" and r["preview"]["summary"].startswith("Refund")
    assert m.request_status(r["request_id"])["status"] == "pending"
    e = m.execute_action("refund", {"amount": 5000, "order": "A1"}, "idem-mcp-0001", r["request_id"])
    assert e.get("status") == "pending_approval"  # not approved -> not run


def test_safe_action_executes(m):
    r = m.check_action(action="look up order status", tool="lookup_order", args={"order": "A1"})
    assert r["decision"] == "allow"
    e = m.execute_action("lookup_order", {"order": "A1"}, "idem-mcp-0002", r["request_id"])
    assert e.get("status") == "executed", e


def test_bad_key_is_refused(m, monkeypatch):
    monkeypatch.setenv("PATIENCE_AGENT_KEY", "pk_wrong")
    assert m.check_action(action="anything")["error"].startswith("HTTP 401")


def test_empty_check(m):
    assert "error" in m.check_action()


def test_stdio_server_starts():
    # real stdio handshake: initialize + tools/list
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "patience_mcp.py")], cwd=ROOT, text=True,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for x in msgs:
            p.stdin.write(json.dumps(x) + "\n")
        p.stdin.flush()
        tl = None
        for _ in range(10):
            o = json.loads(p.stdout.readline())
            if o.get("id") == 2:
                tl = o
                break
    finally:
        p.kill()
    assert {t["name"] for t in tl["result"]["tools"]} >= {"check_action", "execute_action", "request_status"}
