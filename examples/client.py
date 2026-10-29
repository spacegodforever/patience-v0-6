"""Gate a real action behind PATIENCE.

    from client import ask_patience
    if ask_patience("Email all 400 members a 20% price increase"):
        send_the_email()
"""
from __future__ import annotations
import os
import time
import requests

URL = os.environ.get("PATIENCE_URL", "http://127.0.0.1:8765")


def _headers():
    # your per-agent key from `python identity.py add <name>`; identity comes from the key
    t = os.environ.get("PATIENCE_AGENT_KEY") or os.environ.get("PATIENCE_API_TOKEN")
    return {"Authorization": f"Bearer {t}"} if t else {}


def ask_patience(action: str | None = None, context: str | None = None,
                 wait_seconds: int = 300, poll_every: float = 5.0,
                 tool: str | None = None, args: dict | None = None) -> bool:
    """True only if PATIENCE allows the action or a human approves it.
    Anything else (clarify, defer, denied, timeout, PATIENCE unreachable) is False: fail closed."""
    try:
        r = requests.post(f"{URL}/v1/check", headers=_headers(), timeout=10,
                          json={k: v for k, v in {"action": action, "context": context,
                                                  "tool": tool, "args": args}.items() if v is not None})
        r.raise_for_status()
        res = r.json()
    except requests.RequestException as e:
        print("PATIENCE unreachable, not acting:", e)
        return False
    print(f"PATIENCE: {res['decision']} - {res['reason']}")
    if res["decision"] == "allow":
        return True
    if res["decision"] not in ("needs_approval", "clarify"):
        return False
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        s = requests.get(f"{URL}/v1/requests/{res['request_id']}", headers=_headers(), timeout=10).json()
        if s["status"] == "approved":
            return True
        if s["status"] == "denied":
            return False
        time.sleep(poll_every)
    print("No human decision in time, not acting.")
    return False


def send_email(to: str, subject: str, body: str):
    print(f"(pretend) sending email to {to}: {subject}")


if __name__ == "__main__":
    if ask_patience("Email all 400 members a 20% price increase.", wait_seconds=60):
        send_email("all-members@example.com", "Price update", "...")
    else:
        print("Email NOT sent.")


def execute_via_patience(tool: str, args: dict, wait_seconds: int = 600, poll_every: float = 5.0) -> dict | None:
    """Gateway mode: PATIENCE holds the tool credentials and runs the call itself
    (this agent never has the SMTP password / webhook URL). Waits for approval if needed."""
    import uuid
    idem = str(uuid.uuid4())
    body = {"tool": tool, "args": args, "idempotency_key": idem}
    r = requests.post(f"{URL}/v1/execute", headers=_headers(), json=body, timeout=30)
    if r.status_code == 202:
        rid = r.json()["request_id"]
        print("Waiting for human approval of", rid)
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            time.sleep(poll_every)
            st = requests.get(f"{URL}/v1/requests/{rid}", headers=_headers(), timeout=10).json()["status"]
            if st == "denied":
                return None
            if st == "approved":
                r = requests.post(f"{URL}/v1/execute", headers=_headers(), timeout=30,
                                  json={**body, "request_id": rid})  # same args, or approval won't match
                break
        else:
            return None
    if r.status_code != 200:
        print("PATIENCE refused:", r.status_code, r.text[:200])
        return None
    return r.json()
