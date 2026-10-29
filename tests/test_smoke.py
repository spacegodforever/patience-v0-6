import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def test_council_without_key(monkeypatch):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    from adapters import ModelCouncil
    names = [a.name for a in ModelCouncil().adapters]
    assert names == ["oracle-local", "skeptic", "opportunity"]

def test_council_with_key_adds_llm(monkeypatch):
    monkeypatch.setenv("PATIENCE_LLM_API_KEY", "dummy")
    from adapters import ModelCouncil
    # second opinion on (default with a key): it is the only LLM call, so no council LLM voter
    assert not any(a.name.startswith("llm:") for a in ModelCouncil().adapters)
    monkeypatch.setenv("PATIENCE_LLM_SECOND_OPINION", "0")
    assert any(a.name.startswith("llm:") for a in ModelCouncil().adapters)

def test_llm_failure_fails_safe(monkeypatch):
    monkeypatch.setenv("PATIENCE_LLM_API_KEY", "dummy")
    monkeypatch.setenv("PATIENCE_LLM_BASE_URL", "http://127.0.0.1:9")
    import llm_adapter
    from models import Assessment
    a = Assessment(.5,.5,.5,.5,.5,.5,[],[],[],[])
    v = llm_adapter.LLMAdapter().vote(a)
    assert v.recommendation == "human_review"

def test_governance_cycle(tmp_path, monkeypatch):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    from engine import Patience
    p = Patience(str(tmp_path / "s.json"))
    out = p.cycle("Should we sign a $50k contract with a new vendor tomorrow?")
    assert out["decision"]["action"] in {"respond","research","prototype","human_review"}
    assert "verification" in out

def test_trigger_worker_blocks_llm_actions(tmp_path, monkeypatch):
    monkeypatch.setenv("PATIENCE_LLM_API_KEY", "dummy")
    monkeypatch.chdir(tmp_path)
    import trigger_worker
    monkeypatch.setattr(trigger_worker, "QUEUE", tmp_path / "trigger_queue.jsonl")
    monkeypatch.setattr(trigger_worker, "DONE", tmp_path / "trigger_done.json")
    (tmp_path / "trigger_queue.jsonl").write_text(json.dumps({"trigger_type": "blocked_actions", "prompt": "x"}) + "\n")
    monkeypatch.setattr(trigger_worker, "chat", lambda m: json.dumps({"assessment": "a", "decision": "d", "proposed_action": "send_invoice", "next_checkpoint": "tomorrow", "confidence": 0.7}))
    assert trigger_worker.process_once() == 1
    from engine import Patience
    st = Patience("patience_state.json").state
    # proposals go through the full check under identity "trigger_worker"; the approval key is recorded
    key = st.decisions[-1]["approval_key"]
    assert key in st.blocked_actions and "send invoice" in key and key not in st.authorized_actions
    assert trigger_worker.process_once() == 0  # not reprocessed

def test_trigger_worker_idle_without_key(monkeypatch, tmp_path):
    monkeypatch.delenv("PATIENCE_LLM_API_KEY", raising=False)
    import trigger_worker
    q = tmp_path / "q.jsonl"; q.write_text('{"trigger_type":"x","prompt":"y"}\n')
    monkeypatch.setattr(trigger_worker, "QUEUE", q)
    assert trigger_worker.process_once() == 0
