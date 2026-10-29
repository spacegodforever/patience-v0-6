"""v0.6 step 7: metrics, pending queue, audit search, admin-only audited policy editor."""
import base64, os, shutil
import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "s.json"))
    monkeypatch.setenv("PATIENCE_AGENTS", str(tmp_path / "agents.yaml"))
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    pol = tmp_path / "policy.yaml"
    shutil.copy(os.path.join(ROOT, "policies", "default.yaml"), pol)
    monkeypatch.setenv("PATIENCE_POLICY", str(pol))
    import approvers, identity, api, risk_policy
    risk_policy.reload_policy()
    approvers.add("root", "root-password-1", "admin")
    approvers.add("bob", "bob-password-12", "approver")
    key = identity.add_agent("a1")
    c = TestClient(api.app)
    h = {"Authorization": f"Bearer {key}"}
    rids = [c.post("/v1/check", headers=h, json={"tool": "refund", "args": {"amount": 5000 + i, "order": f"A{i}"}}).json()["request_id"]
            for i in range(3)]
    c.post("/v1/check", headers=h, json={"action": "look up the weather"})
    yield api, rids, pol
    risk_policy.reload_policy()


def test_metrics(env):
    api, rids, _ = env
    import dashboard_ops as ops
    p = api._engine()
    ops.decide_pending(p, rids[0], True, {"user": "bob", "role": "approver"}, "ok")
    ops.decide_pending(p, rids[1], False, {"user": "bob", "role": "approver"}, "no")
    m = ops.metrics(api._engine().state)
    assert m["checks"] == 4 and m["approvals"] == 1 and m["denials"] == 1 and m["status"]["pending"] == 1
    assert m["blocks_by_category"]
    kinds = {s["metric"]: s["count"] for s in m["series"]}
    assert kinds["checks"] == 4 and kinds["approvals"] == 1 and kinds["denials"] == 1


def test_pending_queue_with_previews_and_decide(env):
    api, rids, _ = env
    import dashboard_ops as ops
    p = api._engine()
    q = ops.pending_queue(p.state)
    assert [r["request_id"] for r in q] == rids and q[0]["preview"]["summary"].startswith("Refund")
    with pytest.raises(PermissionError):
        ops.decide_pending(p, rids[0], True, None)
    rec = ops.decide_pending(p, rids[0], True, {"user": "bob", "role": "approver"}, "checked")
    assert rec["approver"] == "bob" and rec["via"] == "dashboard"
    with pytest.raises(ValueError):  # already decided
        ops.decide_pending(api._engine(), rids[0], False, {"user": "bob", "role": "approver"})


def test_audit_search(env):
    api, rids, _ = env
    import dashboard_ops as ops
    assert len(ops.search_audit(event="check")) == 4
    hits = ops.search_audit(rids[1])
    assert hits and all(rids[1] in str(e["data"]) for e in hits)
    assert ops.search_audit("no-such-thing-xyz") == []


def test_policy_editor_non_admin_refused(env):
    api, _, pol = env
    import dashboard_ops as ops, audit
    before = pol.read_text()
    with pytest.raises(PermissionError):
        ops.save_policy(before + "\n# hacked\n", {"user": "bob", "role": "approver"})
    with pytest.raises(PermissionError):
        ops.save_policy(before + "\n# hacked\n", None)
    assert pol.read_text() == before
    assert any(e["event"] == "policy.denied" and e["actor"] == "bob" for e in audit.read())


def test_policy_editor_validates_before_save(env):
    api, _, pol = env
    import dashboard_ops as ops
    before = pol.read_text()
    root = {"user": "root", "role": "admin"}
    for bad in ("categories: [unclosed", "just a string", "thresholds: {}\n", "categories: {}\nthresholds: {}\n"):
        with pytest.raises(ValueError):
            ops.save_policy(bad, root)
    assert pol.read_text() == before


def test_policy_editor_admin_save_is_audited(env):
    api, _, pol = env
    import dashboard_ops as ops, audit, yaml, risk_policy
    raw = yaml.safe_load(pol.read_text())
    raw["thresholds"]["mass_recipients"] = 7
    new = yaml.safe_dump(raw, sort_keys=False)
    res = ops.save_policy(new, {"user": "root", "role": "admin"}, "tighten mass threshold")
    assert res["changed"] and risk_policy.get_policy().mass == 7
    ev = [e for e in audit.read() if e["event"] == "policy.updated"][-1]
    assert ev["actor"] == "root" and ev["data"]["note"] == "tighten mass threshold" and "mass_recipients" in ev["data"]["diff"]
    assert audit.verify()["ok"]


def _login(tmp_path, monkeypatch, user, role):
    from streamlit.testing.v1 import AppTest
    import approvers
    approvers.add(user, "pw-1234567890", role)
    monkeypatch.chdir(ROOT)
    at = AppTest.from_file(os.path.join(ROOT, "dashboard.py"), default_timeout=30).run()
    at.text_input[0].input(user)
    at.text_input[1].input("pw-1234567890")
    at.button[0].click().run()
    assert not at.exception, at.exception
    return at


def test_dashboard_tabs_queue_and_policy_admin_only(env, tmp_path, monkeypatch):
    at = _login(tmp_path, monkeypatch, "carl", "approver")
    labels = [b.label for b in at.button]
    assert labels.count("Approve") == 3 and labels.count("Deny") == 3
    assert "Save policy" not in labels
    assert any("Only admins" in i.value for i in at.info)
    at = _login(tmp_path, monkeypatch, "ada", "admin")
    assert "Save policy" in [b.label for b in at.button]


def test_dashboard_queue_approve_records_reason(env, tmp_path, monkeypatch):
    api, rids, _ = env
    at = _login(tmp_path, monkeypatch, "carl", "approver")
    at.text_input(key=f"why-{rids[0]}").input("verified by phone")
    [b for b in at.button if b.key == f"qa-{rids[0]}"][0].click().run()
    d = api._engine().state.requests[rids[0]]["decided"]
    assert d["approver"] == "carl" and d["reason"] == "verified by phone" and d["via"] == "dashboard"
