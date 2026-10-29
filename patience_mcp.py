"""PATIENCE MCP server (stdio): check_action, execute_action, request_status.

It is a thin client of the PATIENCE HTTP API, so agent identity, budgets, approvals and the
audit log all apply exactly as for any other agent. The agent key comes from the environment
and is never a tool argument.

Env: PATIENCE_URL (default http://127.0.0.1:8765), PATIENCE_AGENT_KEY (from `patience init`
or `python identity.py add <name>`).

Claude Desktop / Cursor config:
  {"mcpServers": {"patience": {"command": "python", "args": ["/path/to/patience_mcp.py"],
     "env": {"PATIENCE_URL": "http://127.0.0.1:8765", "PATIENCE_AGENT_KEY": "pk_..."}}}}
"""
from __future__ import annotations
import envfile
envfile.load()
import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

VERSION = "0.6"
server = _Server("patience")


def _base() -> str:
    return os.environ.get("PATIENCE_URL", "http://127.0.0.1:8765").rstrip("/")


def _call(method: str, path: str, body: Optional[dict] = None) -> dict:
    """HTTP transport to the PATIENCE API (patched in tests)."""
    h = {"Content-Type": "application/json"}
    if os.environ.get("PATIENCE_AGENT_KEY"):
        h["Authorization"] = f"Bearer {os.environ['PATIENCE_AGENT_KEY']}"
    req = urllib.request.Request(_base() + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read()).get("detail")
        except Exception:
            detail = None
        return {"error": f"HTTP {e.code}", "detail": detail}
    except urllib.error.URLError as e:
        return {"error": "PATIENCE API unreachable", "detail": str(e.reason)[:200]}


def check_action(action: str = "", tool: str = "", args: Optional[dict] = None, context: str = "") -> dict:
    """Ask PATIENCE before doing anything risky. Describe the action in plain words and/or give the
    tool name and arguments. Returns decision (allow | needs_approval | clarify | defer | block),
    the reason, a human-readable preview and a request_id. Only proceed when decision is allow, or
    after request_status shows approved."""
    body: dict[str, Any] = {}
    if action:
        body["action"] = action
    if tool:
        body["tool"], body["args"] = tool, args or {}
    if context:
        body["context"] = context
    if not body:
        return {"error": "Give an action description or a tool name."}
    return _call("POST", "/v1/check", body)


def execute_action(tool: str, args: dict, idempotency_key: str, request_id: str = "") -> dict:
    """Have PATIENCE perform the action itself (gateway mode), using credentials you never see.
    Allowed or human-approved requests only, at most once per approval. Reuse the same
    idempotency_key when retrying."""
    body = {"tool": tool, "args": args, "idempotency_key": idempotency_key}
    if request_id:
        body["request_id"] = request_id
    return _call("POST", "/v1/execute", body)


def request_status(request_id: str) -> dict:
    """Status of an earlier check: pending, approved, denied, executed, allowed or needs_review."""
    return _call("GET", f"/v1/requests/{request_id}")


for _f in (check_action, execute_action, request_status):
    server.tool()(_f)


def main():
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
