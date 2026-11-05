"""L0: tag org decisions + persist episodes/options. Gate path unchanged."""
from __future__ import annotations
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import org_learning


@pytest.fixture
def client(tmp_path, monkeypatch):
    for v in ("PATIENCE_LLM_API_KEY", "PATIENCE_API_TOKEN", "PATIENCE_APPROVER_TOKEN",
              "PATIENCE_AGENTS"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("PATIENCE_STATE_PATH", str(tmp_path / "state.json"))
    import api
    return TestClient(api.app)


def test_should_tag_rules():
    assert org_learning.should_tag(situation_kind="org_decision", options=[], consequence=0.1)
    assert org_learning.should_tag(situation_kind=None, options=[{"id": "a", "summary": "A"},
                                                                {"id": "b", "summary": "B"}],
                                   consequence=0.70)
    assert not org_learning.should_tag(situation_kind=None, options=[{"id": "a", "summary": "A"},
                                                                     {"id": "b", "summary": "B"}],
                                       consequence=0.69)
    assert not org_learning.should_tag(situation_kind=None, options=[{"id": "a", "summary": "A"}],
                                       consequence=0.9)
    assert not org_learning.should_tag(situation_kind="routine", options=[], consequence=0.9)


def test_normalize_options_caps_and_skips_empty():
    opts = org_learning.normalize_options([
        {"id": "a", "summary": "Accept", "tier": 3, "reversible": False},
        {"summary": "  "},
        "plain string option",
        {"id": "b", "summary": "Defer", "tier": "x"},
    ] + [{"id": str(i), "summary": f"o{i}"} for i in range(10)])
    assert opts[0]["tier"] == 3 and opts[0]["reversible"] is False
    assert any(o["summary"] == "plain string option" for o in opts)
    assert all("summary" in o and o["summary"].strip() for o in opts)
    assert len(opts) <= 8


def test_routine_path_untagged(client, tmp_path):
    r = client.post("/v1/check", json={"action": "summarize today's standup notes"}).json()
    assert r["decision"] in ("allow", "needs_approval", "clarify", "defer", "block")
    assert r.get("situation_kind") == "routine"
    assert "episode_id" not in r
    from engine import Patience
    s = Patience(str(tmp_path / "state.json")).state
    assert s.episodes == []


def test_explicit_flag_tags_and_persists(client, tmp_path):
    body = {
        "action": "Negotiate first design-partner deal terms",
        "situation_kind": "org_decision",
        "domain": "partnership",
        "options": [
            {"id": "accept", "summary": "Accept as-is", "tier": 3, "reversible": False},
            {"id": "pilot", "summary": "30-day reversible pilot", "tier": 2, "reversible": True},
            {"id": "defer", "summary": "Defer for legal template", "tier": 1, "reversible": True},
        ],
    }
    r = client.post("/v1/check", json=body).json()
    assert r["situation_kind"] == "org_decision"
    assert r["domain"] == "partnership"
    assert r["episode_id"]
    assert len(r["options"]) == 3
    assert r["novelty"] == 1.0  # no prior episodes in domain
    st = client.get(f"/v1/requests/{r['request_id']}").json()
    assert st["situation_kind"] == "org_decision"
    assert st["episode_id"] == r["episode_id"]
    from engine import Patience
    s = Patience(str(tmp_path / "state.json")).state
    assert len(s.episodes) == 1
    ep = s.episodes[0]
    assert ep["id"] == r["episode_id"]
    assert ep["request_id"] == r["request_id"]
    assert ep["domain"] == "partnership"
    assert ep["options"][1]["id"] == "pilot"


def test_high_consequence_plus_options_tags(client, tmp_path):
    # Refund language drives consequence ≥ 0.70 via risk_policy / oracle keywords.
    r = client.post("/v1/check", json={
        "action": "Issue refunds to 12 members totaling $1,800 for a pricing error",
        "options": [
            {"id": "full", "summary": "Full refund now"},
            {"id": "partial", "summary": "Partial credit"},
            {"id": "deny", "summary": "Deny and escalate"},
        ],
    }).json()
    assert r["situation_kind"] == "org_decision"
    assert len(r["options"]) == 3
    assert r.get("episode_id")


def test_options_alone_without_high_consequence_not_tagged(client):
    r = client.post("/v1/check", json={
        "action": "what can i use for this information deck",
        "options": [
            {"id": "a", "summary": "Use Notion"},
            {"id": "b", "summary": "Use Google Docs"},
        ],
    }).json()
    assert r.get("situation_kind") == "routine"
    assert "episode_id" not in r


def test_tagging_does_not_bypass_gate(client):
    """Org-decision tag must not allow a risky action without approval."""
    r = client.post("/v1/check", json={
        "action": "Email all 400 members a 20% price increase",
        "situation_kind": "org_decision",
        "domain": "pricing",
        "options": [
            {"id": "send", "summary": "Send now"},
            {"id": "draft", "summary": "Draft only"},
        ],
    }).json()
    assert r["situation_kind"] == "org_decision"
    assert r["decision"] == "needs_approval"
    assert r["approval_key"]


def test_novelty_drops_with_domain_precedents(client, tmp_path):
    body = {
        "action": "Partnership terms round 1",
        "situation_kind": "org_decision",
        "domain": "partnership",
        "options": [{"id": "a", "summary": "A"}, {"id": "b", "summary": "B"}],
    }
    r1 = client.post("/v1/check", json=body).json()
    assert r1["novelty"] == 1.0
    body["action"] = "Partnership terms round 2"
    r2 = client.post("/v1/check", json=body).json()
    assert r2["novelty"] == pytest.approx(1.0 - 1 / 3, abs=0.01)
    from engine import Patience
    assert len(Patience(str(tmp_path / "state.json")).state.episodes) == 2
