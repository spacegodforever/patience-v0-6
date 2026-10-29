"""v0.6 steps 3-4: previews, notifications, signed one-tap links (forged/expired/replayed/changed)."""
import re, time
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    monkeypatch.setenv("PATIENCE_NOTIFY_WEBHOOK_URL", "https://hooks.example.com/x")
    monkeypatch.setenv("PATIENCE_NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.setenv("PATIENCE_PUBLIC_URL", "https://patience.example.com")
    import approvers, identity, api, notify
    sent = []
    monkeypatch.setattr(notify, "_post", lambda url, body, h: sent.append((url, body, h)) or 200)
    monkeypatch.setattr(notify, "_smtp_send", lambda m: sent.append(("smtp", m, None)))
    approvers.add("bob", "bob-password-12", "approver", pin="246810")
    key = identity.add_agent("agent1")
    return TestClient(api.app), key, sent


def risky(client, key):
    r = client.post("/v1/check", headers={"Authorization": f"Bearer {key}"},
                    json={"tool": "refund", "args": {"amount": 5000, "order": "A1"}})
    assert r.json()["decision"] == "needs_approval"
    return r.json()


def link_tokens(rid):
    import api, notify
    p = api._engine()
    req = p.state.requests[rid]
    msg = notify.compose(req, api.request_hash(req))
    return {a: u.rsplit("/l/", 1)[1] for a, u in msg["links"].items()}


# ---- previews ----
def test_check_returns_preview(c):
    client, key, _ = c
    body = risky(client, key)
    assert body["preview"]["summary"].startswith("Refund $5,000.00") and body["preview"]["amount_total"] == 5000


def test_preview_email_and_records():
    import previews
    pv = previews.preview("send_email", {"to": ["a@x.com", "b@x.com", "c@x.com"], "subject": "Hi",
                                         "body": "Big news " * 50})
    assert pv["recipients"] == 3 and "3 recipients" in pv["summary"] and len(pv["message_sample"]) <= 205
    assert previews.preview("delete_records", {"ids": [1, 2, 3, 4]})["records_affected"] == 4
    assert previews.preview(None, None, "email all 400 customers", ["mass_communication"])["recipients"] == 400


# ---- notifications ----
def test_alert_dry_run_by_default(c):
    client, key, sent = c
    body = risky(client, key)
    assert sent == []  # dry-run: nothing leaves the box
    import audit
    ev = [e for e in audit.read() if e["event"] == "notify"][-1]
    assert {r["channel"] for r in ev["data"]["results"]} == {"slack", "webhook"}
    assert all(r["dry_run"] for r in ev["data"]["results"])
    assert "/l/" not in str(audit.read())  # tokens never land in the audit log


def test_alert_live_sends_signed_links(c, monkeypatch):
    client, key, sent = c
    monkeypatch.setenv("PATIENCE_EXECUTE_LIVE", "1")
    monkeypatch.setenv("PATIENCE_WEBHOOK_SECRET", "whsec")
    risky(client, key)
    urls = [s[0] for s in sent]
    assert "https://hooks.slack.com/services/T/B/X" in urls and "https://hooks.example.com/x" in urls
    wh = [s for s in sent if s[0].startswith("https://hooks.example.com")][0]
    assert wh[2]["X-Patience-Signature"].startswith("sha256=")
    assert b"https://patience.example.com/l/" in wh[1]


def test_alert_email_live(c, monkeypatch):
    client, key, sent = c
    for k, v in {"PATIENCE_EXECUTE_LIVE": "1", "PATIENCE_NOTIFY_EMAIL_TO": "boss@x.com",
                 "PATIENCE_SMTP_HOST": "smtp.x.com", "PATIENCE_SMTP_FROM": "patience@x.com"}.items():
        monkeypatch.setenv(k, v)
    risky(client, key)
    m = [s[1] for s in sent if s[0] == "smtp"][0]
    assert m["To"] == "boss@x.com" and "Approve:" in m.get_content()


def test_no_alert_for_safe_actions(c):
    client, key, sent = c
    client.post("/v1/check", headers={"Authorization": f"Bearer {key}"}, json={"action": "read the docs"})
    import audit
    assert not [e for e in audit.read() if e["event"] == "notify"]


# ---- signed links ----
def test_link_get_shows_preview_and_does_not_approve(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["approve"]
    r = client.get(f"/l/{t}")
    assert r.status_code == 200 and "Refund $5,000.00" in r.text and r.headers["Referrer-Policy"] == "no-referrer"
    import api
    assert api._status(api._engine().state, api._engine().state.requests[rid]) == "pending"


def test_link_requires_login_or_pin(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["approve"]
    assert client.post(f"/l/{t}", data={"user": "bob"}).status_code == 403
    assert client.post(f"/l/{t}", data={"user": "bob", "pin": "000000"}).status_code == 403
    r = client.post(f"/l/{t}", data={"user": "bob", "pin": "246810", "reason": "ok by phone"})
    assert r.status_code == 200 and "approved" in r.text
    import api
    d = api._engine().state.requests[rid]["decided"]
    assert d["approver"] == "bob" and d["via"] == "link" and d["reason"] == "ok by phone"


def test_link_password_and_deny(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    r = client.post(f"/l/{link_tokens(rid)['deny']}", data={"user": "bob", "password": "bob-password-12"})
    assert r.status_code == 200 and "denied" in r.text


def test_forged_link_rejected(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["deny"]
    import base64, json
    p64, sig = t.split(".")
    pl = json.loads(base64.urlsafe_b64decode(p64 + "=" * (-len(p64) % 4)))
    pl["a"] = "approve"  # flip deny -> approve, keep old signature
    forged = base64.urlsafe_b64encode(json.dumps(pl, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode()
    r = client.post(f"/l/{forged}.{sig}", data={"user": "bob", "pin": "246810"})
    assert r.status_code == 403 and "signature" in r.text
    # signed with a different secret
    import links
    import os
    os.environ["PATIENCE_LINK_SECRET"] = "another-secret-another-secret-123"
    other = links.make(rid, "approve", "x" * 64)
    os.environ["PATIENCE_LINK_SECRET"] = "test-link-secret-0123456789abcdef"
    assert client.post(f"/l/{other}", data={"user": "bob", "pin": "246810"}).status_code == 403
    assert client.get("/l/garbage").status_code == 403


def test_expired_link_rejected(c, monkeypatch):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["approve"]
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 901)
    r = client.post(f"/l/{t}", data={"user": "bob", "pin": "246810"})
    assert r.status_code == 403 and "expired" in r.text


def test_replayed_link_rejected(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["approve"]
    assert client.post(f"/l/{t}", data={"user": "bob", "pin": "246810"}).status_code == 200
    r = client.post(f"/l/{t}", data={"user": "bob", "pin": "246810"})
    assert r.status_code == 409 and "already used" in r.text
    import audit
    assert any(e["event"] == "link.rejected" for e in audit.read())


def test_link_bound_to_request_hash(c):
    client, key, _ = c
    rid = risky(client, key)["request_id"]
    t = link_tokens(rid)["approve"]
    import api
    p = api._engine()
    with p.memory_store.locked():
        p.refresh()
        p.state.requests[rid]["args_hash"] = "0" * 64  # request mutated after alert
        p.memory_store.save(p.state)
    r = client.post(f"/l/{t}", data={"user": "bob", "pin": "246810"})
    assert r.status_code == 409 and "changed" in r.text


def test_links_disabled_without_secret(c, monkeypatch):
    monkeypatch.delenv("PATIENCE_LINK_SECRET")
    import notify, links
    msg = notify.compose({"request_id": "r", "action": "x", "tool": None, "args": None}, "h")
    assert msg["links"] == {} and "dashboard" in msg["text"]
    with pytest.raises(links.LinkError):
        links.make("r", "approve", "h")
