import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine import Patience
from oracle import Oracle
from models import Observation, PatienceState

RISKY = [
    ("[DEMO] Agent wants to publish a new class schedule to the studio Instagram.", {"public_publishing"}),
    ("[DEMO] Agent wants to email all 400 members a 20% price increase.", {"mass_communication", "money"}),
    ("[DEMO] Agent wants to issue refunds to 12 members totaling $1,800.", {"money"}),
    ("[DEMO] Agent wants to delete last year's member records to free up space.", {"deletion"}),
]
SAFE = "[DEMO] Agent wants to summarize this week's class sign-ups for Ascend Collective."

@pytest.fixture
def p(tmp_path, monkeypatch):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    return Patience(str(tmp_path / "s.json"))

@pytest.mark.parametrize("text,cats", RISKY)
def test_demo_risky_requires_human_review(p, text, cats):
    out = p.cycle(text, source="demo")
    d = out["decision"]
    assert d["action"] == "human_review"
    assert d["requires_authorization"] is True
    assert d["reversible"] is False
    assert cats <= set(out["assessment"]["risk_categories"])
    assert out["verification"]["verified"] is False
    key = out["verification"]["approval_key"]
    assert key in p.state.blocked_actions and key != "human_review"
    assert key not in p.state.authorized_actions
    assert "human_review" not in p.state.authorized_actions

def test_demo_summarize_still_respond(p):
    out = p.cycle(SAFE, source="demo")
    assert out["decision"]["action"] == "respond"
    assert out["assessment"]["risk_categories"] == []
    assert p.state.blocked_actions == []

def test_plain_chat_question_scoring():
    a = Oracle().assess(Observation("what can i use for this information deck", reliability=.9), PatienceState())
    assert a.risk_categories == [] and a.consequence < .5 and a.irreversible is False

def test_legacy_generic_authorization_is_revoked(tmp_path, monkeypatch):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    p = Patience(str(tmp_path / "s.json"))
    p.state.authorized_actions.append("human_review"); p.memory_store.save(p.state)
    p2 = Patience(str(tmp_path / "s.json"))
    assert "human_review" not in p2.state.authorized_actions
    assert p2.authorize("human_review") is False
    out = p2.cycle(RISKY[2][0])
    assert out["verification"]["verified"] is False

def test_specific_approval_only_covers_that_request(p):
    first = p.cycle(RISKY[2][0])
    assert p.authorize(first["verification"]["approval_key"]) is True
    other = p.cycle(RISKY[3][0])
    assert other["verification"]["verified"] is False
    assert other["verification"]["approval_key"] in p.state.blocked_actions
