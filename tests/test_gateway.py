"""Closing the 3 gaps: enforced routing (/v1/execute), dashboard lock, per-agent identity."""
import os, sys, json
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi.testclient import TestClient
import risk_policy

APPR = {"X-Approver-Token": "appr"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setenv("PATIENCE_APPROVER_TOKEN", "appr")
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    for v in ("PATIENCE_API_TOKEN", "PATIENCE_LLM_API_KEY", "PATIENCE_EXECUTE_LIVE", "PATIENCE_SMTP_HOST",
              "PATIENCE_WEBHOOK_URL", "PATIENCE_DASHBOARD_PASSWORD", "PATIENCE_DASHBOARD_PASSWORD_SHA256"):
        monkeypatch.delenv(v, raising=False)
    import identity, api
    from executors.mock import MockExecutor
    keys = {n: identity.add_agent(n) for n in ("alice", "bob")}
    return TestClient(api.app), keys, MockExecutor.reset(), tmp_path


def H(k):
    return {"Authorization": f"Bearer {k}"}


RISKY = {"tool": "refund", "args": {"amount": 5000, "order": "A-1001", "reason": "damaged"}}
SAFE = {"tool": "search_docs", "args": {"query": "refund policy"}}


def ex(c, k, idem, req=RISKY, **extra):
    return c.post("/v1/execute", headers=H(k), json={**req, "idempotency_key": idem, **extra})


# ---------------- identity ----------------
def test_unknown_or_missing_key_is_401(env):
    c, keys, _, _ = env
    assert c.post("/v1/check", json={"action": "read the docs"}).status_code == 401
    assert c.post("/v1/check", headers=H("pat_forged"), json={"action": "read the docs"}).status_code == 401
    assert ex(c, "pat_forged", "idem-0001").status_code == 401


def test_keys_stored_hashed_and_revocable(env):
    c, keys, _, tmp = env
    raw = (tmp / "agents.yaml").read_text()
    assert keys["alice"] not in raw and "key_sha256" in raw
    import identity
    identity.revoke_agent("alice")
    assert c.post("/v1/check", headers=H(keys["alice"]), json={"action": "read the docs"}).status_code == 401


def test_spoofed_requester_rejected_and_identity_from_key(env):
    c, keys, _, _ = env
    r = c.post("/v1/check", headers=H(keys["alice"]), json={"action": "read the docs", "requester": "bob"})
    assert r.status_code == 400
    r = c.post("/v1/check", headers=H(keys["alice"]), json={"action": "read the docs", "requester": "alice"})
    rid = r.json()["request_id"]
    import api
    assert api._engine().state.requests[rid]["identity"] == "alice"
    # bob can't even see alice's request
    assert c.get(f"/v1/requests/{rid}", headers=H(keys["bob"])).status_code == 404


def test_budget_per_identity_text_checks(env, monkeypatch):
    c, keys, _, _ = env
    a, b = H(keys["alice"]), H(keys["bob"])
    # free-text refunds count against amount_total under the caller's identity once approved
    for i in range(4):
        d = c.post("/v1/check", headers=a, json={"action": f"issue refund of $500 for order {i}"}).json()
        assert "budget_exceeded" not in d["risk_categories"], d
        assert c.post(f"/v1/requests/{d['request_id']}/approve", headers=APPR).status_code == 200
    d = c.post("/v1/check", headers=a, json={"action": "issue refund of $500 for order 9"}).json()
    assert "budget_exceeded" in d["risk_categories"], d
    # bob's identity has its own budget
    d = c.post("/v1/check", headers=b, json={"action": "issue refund of $500 for order 9"}).json()
    assert "budget_exceeded" not in d["risk_categories"]


def test_budget_per_identity_tool_calls(env):
    c, keys, _, _ = env
    for _ in range(10):
        assert c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 200}}
                      ).json()["decision"] == "allow"
    assert c.post("/v1/check", headers=H(keys["alice"]), json={"tool": "refund", "args": {"amount": 200}}
                  ).json()["decision"] == "needs_approval"
    assert c.post("/v1/check", headers=H(keys["bob"]), json={"tool": "refund", "args": {"amount": 200}}
                  ).json()["decision"] == "allow"


def test_trigger_worker_budgeted_under_its_identity(tmp_path, monkeypatch):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    from engine import Patience
    p = Patience(str(tmp_path / "s.json"))
    for i in range(3):
        p.cycle(f"issue refund of $900 for order {i}", source="llm_trigger_worker", identity="trigger_worker")
    ids = {u.get("identity") for u in p.state.usage_log} | {u["identity"] for u in p.state.pending_usage.values()}
    assert "trigger_worker" in ids
    out = p.cycle("issue refund of $900 for order 9", identity="trigger_worker")
    assert "budget_exceeded" in out["assessment"]["risk_categories"] or not out["verification"]["verified"]


def test_trigger_worker_routes_through_cycle(tmp_path, monkeypatch):
    import trigger_worker
    src = open(trigger_worker.__file__).read()
    assert "identity=IDENTITY" in src and "blocked_actions.append(action)" not in src


# ---------------- gateway / enforced routing ----------------
def test_safe_call_executes_once(env):
    c, keys, mock, _ = env
    r = ex(c, keys["alice"], "idem-safe-1", SAFE)
    assert r.status_code == 200 and r.json()["status"] == "executed", r.text
    assert len(mock.calls) == 1 and mock.calls[0]["meta"]["identity"] == "alice"


def test_execute_without_approval_is_held(env):
    c, keys, mock, _ = env
    r = ex(c, keys["alice"], "idem-risky-1")
    assert r.status_code == 202 and r.json()["status"] == "pending_approval"
    rid = r.json()["request_id"]
    # retrying with the request id before approval still doesn't run
    assert ex(c, keys["alice"], "idem-risky-2", request_id=rid).status_code == 202
    assert mock.calls == []


def test_approved_then_execute_exactly_once_with_exact_args(env):
    c, keys, mock, _ = env
    rid = ex(c, keys["alice"], "idem-key-a1").json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=APPR).status_code == 200
    r = ex(c, keys["alice"], "idem-key-a2", request_id=rid)
    assert r.status_code == 200 and r.json()["status"] == "executed", r.text
    assert len(mock.calls) == 1 and mock.calls[0]["args"] == RISKY["args"]
    # replay with the same idempotency key: stored result, no second run
    r2 = ex(c, keys["alice"], "idem-key-a2", request_id=rid)
    assert r2.status_code == 200 and r2.json()["replayed"] is True and len(mock.calls) == 1
    # replay with a NEW key against the used approval: refused
    assert ex(c, keys["alice"], "idem-key-a3", request_id=rid).status_code == 409
    assert len(mock.calls) == 1
    assert c.get(f"/v1/requests/{rid}", headers=H(keys["alice"])).json()["status"] == "executed"


def test_args_swapped_after_approval_need_new_approval(env):
    c, keys, mock, _ = env
    rid = ex(c, keys["alice"], "idem-key-s1").json()["request_id"]
    c.post(f"/v1/requests/{rid}/approve", headers=APPR)
    swapped = {"tool": "refund", "args": {**RISKY["args"], "amount": 50000}}
    r = ex(c, keys["alice"], "idem-key-s2", swapped, request_id=rid)
    assert r.status_code == 409 and "new approval" in r.json()["detail"]
    other_tool = {"tool": "delete_records", "args": RISKY["args"]}
    assert ex(c, keys["alice"], "idem-key-s3", other_tool, request_id=rid).status_code == 409
    assert mock.calls == []


def test_idempotency_key_reuse_with_other_args_rejected(env):
    c, keys, mock, _ = env
    assert ex(c, keys["alice"], "idem-key-k1", SAFE).status_code == 200
    other = {"tool": "search_docs", "args": {"query": "something else"}}
    assert ex(c, keys["alice"], "idem-key-k1", other).status_code == 409
    assert ex(c, keys["bob"], "idem-key-k1", SAFE).status_code == 409  # other identity can't read the result
    assert len(mock.calls) == 1


def test_other_agent_cannot_use_my_approval(env):
    c, keys, mock, _ = env
    rid = ex(c, keys["alice"], "idem-key-o1").json()["request_id"]
    c.post(f"/v1/requests/{rid}/approve", headers=APPR)
    assert ex(c, keys["bob"], "idem-key-o2", request_id=rid).status_code == 404
    assert mock.calls == []


def test_denied_request_never_executes(env):
    c, keys, mock, _ = env
    rid = ex(c, keys["alice"], "idem-key-d1").json()["request_id"]
    c.post(f"/v1/requests/{rid}/deny", headers=APPR)
    assert ex(c, keys["alice"], "idem-key-d2", request_id=rid).status_code == 403
    assert mock.calls == []


def test_agents_cannot_approve(env):
    c, keys, _, _ = env
    rid = ex(c, keys["alice"], "idem-key-p1").json()["request_id"]
    assert c.post(f"/v1/requests/{rid}/approve", headers=H(keys["alice"])).status_code == 403


def test_executor_failure_is_at_most_once(env):
    c, keys, mock, _ = env
    mock.fail_next = True
    r = ex(c, keys["alice"], "idem-fail-1", SAFE)
    assert r.status_code == 502 and "mock failure" not in r.text  # sanitized
    r2 = ex(c, keys["alice"], "idem-fail-1", SAFE)
    assert r2.json()["status"] == "failed" and r2.json()["replayed"] and mock.calls == []


def test_execute_requires_agent_mode_and_executor(env, monkeypatch, tmp_path):
    c, keys, _, _ = env
    monkeypatch.delenv("PATIENCE_EXECUTOR_MOCK")
    assert ex(c, keys["alice"], "idem-none-1", SAFE).status_code == 501  # disabled until configured
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("PATIENCE_EXECUTOR_MOCK", "1")
    assert c.post("/v1/execute", json={**SAFE, "idempotency_key": "idem-none-2"}).status_code == 403


def test_dry_run_does_not_consume_approval(env, monkeypatch):
    c, keys, _, _ = env
    monkeypatch.delenv("PATIENCE_EXECUTOR_MOCK")
    monkeypatch.setenv("PATIENCE_WEBHOOK_URL", "https://hooks.example.com/abc")
    rid = ex(c, keys["alice"], "idem-key-w1").json()["request_id"]
    c.post(f"/v1/requests/{rid}/approve", headers=APPR)
    r = ex(c, keys["alice"], "idem-key-w2", request_id=rid)
    assert r.status_code == 200 and r.json()["status"] == "dry_run", r.text
    assert "hooks.example.com" not in r.text  # the credential-bearing URL never reaches the agent
    # approval is still usable once live sending is switched on
    assert c.get(f"/v1/requests/{rid}", headers=H(keys["alice"])).json()["status"] == "approved"


# ---------------- executors ----------------
def test_smtp_dry_run_and_header_injection(monkeypatch):
    monkeypatch.setenv("PATIENCE_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("PATIENCE_SMTP_FROM", "bot@example.com")
    monkeypatch.setenv("PATIENCE_SMTP_PASSWORD", "s3cret")
    monkeypatch.delenv("PATIENCE_EXECUTE_LIVE", raising=False)
    monkeypatch.delenv("PATIENCE_EXECUTOR_MOCK", raising=False)
    import executors
    e = executors.get_executor("send_email")
    out = e.run("send_email", {"recipients": ["a@x.com"], "subject": "hi", "body": "b"}, {})
    assert out["dry_run"] and "s3cret" not in json.dumps(out)
    with pytest.raises(executors.ExecutionError):
        e.run("send_email", {"recipients": ["a@x.com\nBcc: all@x.com"], "subject": "hi", "body": "b"}, {})


def test_webhook_requires_https(monkeypatch):
    monkeypatch.delenv("PATIENCE_EXECUTOR_MOCK", raising=False)
    monkeypatch.setenv("PATIENCE_WEBHOOK_URL", "http://evil.example.com/x")
    import executors
    e = executors.get_executor("crm_update")
    with pytest.raises(executors.ExecutionError):
        e.run("crm_update", {"a": 1}, {"idempotency_key": "k"})


def test_no_executor_when_unconfigured(monkeypatch):
    for v in ("PATIENCE_EXECUTOR_MOCK", "PATIENCE_SMTP_HOST", "PATIENCE_WEBHOOK_URL"):
        monkeypatch.delenv(v, raising=False)
    import executors
    assert executors.get_executor("send_email") is None


# ---------------- dashboard lock (per-approver accounts since v0.6) ----------------
def _p(tmp_path):
    from engine import Patience
    p = Patience(str(tmp_path / "dl.json"))
    p.cycle("delete all customer records now")
    return p


def test_dashboard_cannot_approve_without_login(tmp_path, monkeypatch):
    for v in ("PATIENCE_DASHBOARD_PASSWORD", "PATIENCE_DASHBOARD_PASSWORD_SHA256", "PATIENCE_LEGACY_DASHBOARD_PASSWORD"):
        monkeypatch.delenv(v, raising=False)
    import dashboard_auth as a
    p = _p(tmp_path)
    key = p.state.blocked_actions[0]
    s = {"patience_authed_at": 10**12, "approver": {"user": "x", "role": "admin"}}  # forged session
    assert not a.can_approve(s)
    with pytest.raises(PermissionError):
        a.approve(p, key, s)
    p.refresh()
    assert key not in p.state.authorized_actions


def test_dashboard_login_per_user_and_lockout(tmp_path, monkeypatch):
    import dashboard_auth as a, approvers
    monkeypatch.setattr(a.time, "sleep", lambda s: None)
    approvers.add("carol", "correct-horse-1", "approver")
    p = _p(tmp_path)
    key = p.state.blocked_actions[0]
    s = {}
    with pytest.raises(PermissionError):
        a.approve(p, key, s)
    assert not a.login(s, "carol", "wrong")
    assert a.login(s, "carol", "correct-horse-1")
    rec = a.approve(p, key, s, reason="checked with finance")
    assert rec["approver"] == "carol" and rec["reason"] == "checked with finance" and rec["via"] == "dashboard"
    a.logout(s)
    for _ in range(5):
        a.login(s, "carol", "nope")
    assert not a.login(s, "carol", "correct-horse-1")  # locked out


def _apptest(tmp_path, monkeypatch, user):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "d.json"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    from engine import Patience
    p = Patience(str(tmp_path / "d.json"))
    p.cycle("delete all customer records now")
    assert p.state.blocked_actions
    if user:
        import approvers
        approvers.add(user, "pw-1234567890", "admin")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    monkeypatch.chdir(root)
    return AppTest.from_file(os.path.join(root, "dashboard.py"), default_timeout=30).run()


def _approve_buttons(at):
    return [b for b in at.button if b.label.startswith(("Authorize", "Approve"))]


def test_dashboard_readonly_without_accounts(tmp_path, monkeypatch):
    at = _apptest(tmp_path, monkeypatch, None)
    assert any("READ-ONLY" in w.value for w in at.warning)
    assert not _approve_buttons(at)


def test_dashboard_locked_until_login(tmp_path, monkeypatch):
    at = _apptest(tmp_path, monkeypatch, "dana")
    assert not _approve_buttons(at)
    assert not any("Blocked" in w.value for w in at.warning)  # nothing rendered before login
    at.text_input[0].input("dana")
    at.text_input[1].input("pw-1234567890")
    at.button[0].click().run()
    assert _approve_buttons(at)


# ---------------- LLM double call ----------------
def test_council_skips_llm_when_second_opinion_on(monkeypatch):
    import adapters, second_opinion, llm_adapter
    monkeypatch.setattr(llm_adapter, "llm_enabled", lambda: True)
    monkeypatch.setattr(second_opinion, "enabled", lambda: True)
    names = [type(a).__name__ for a in adapters.ModelCouncil().adapters]
    assert "LLMAdapter" not in names
    monkeypatch.setattr(second_opinion, "enabled", lambda: False)
    assert "LLMAdapter" in [type(a).__name__ for a in adapters.ModelCouncil().adapters]
