"""PATIENCE Trigger Worker (v0.5).

Reads queued triggers from trigger_queue.jsonl, asks the LLM to evaluate each
one, and stores the answer in patience_state.json. Any action the model
proposes is run through the full PATIENCE check under the identity
"trigger_worker" (risk policy + rolling budgets), and is never executed here:
risky proposals land in blocked_actions and need YOUR approval on the
dashboard. Processed triggers are recorded in trigger_done.json so they
never run twice.

Run:  python trigger_worker.py          (loops)
      python trigger_worker.py --once   (one pass)
"""
from __future__ import annotations
import hashlib
import json
import sys
import time
from pathlib import Path
from engine import Patience
from models import now_iso
from llm_adapter import chat, _parse_json, llm_enabled

QUEUE = Path("trigger_queue.jsonl")
DONE = Path("trigger_done.json")
POLL_SECONDS = 30
IDENTITY = "trigger_worker"  # budget identity for everything this worker proposes

SYSTEM = (
    "You evaluate PATIENCE triggers. You cannot execute anything. "
    "Reply ONLY with JSON: {\"assessment\": string, \"decision\": string, "
    "\"proposed_action\": short snake_case action name or null, "
    "\"required_authorization\": string or null, \"next_checkpoint\": string, "
    "\"confidence\": 0-1}."
)


def _key(line):
    return hashlib.sha256(line.encode()).hexdigest()


def _load_done():
    return set(json.loads(DONE.read_text())) if DONE.exists() else set()


def process_once():
    if not QUEUE.exists():
        return 0
    if not llm_enabled():
        print("PATIENCE_LLM_API_KEY not set; trigger worker idle (rule-based council still works).")
        return 0
    done = _load_done()
    p = Patience("patience_state.json")
    handled = 0
    for line in QUEUE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or _key(line) in done:
            continue
        event = json.loads(line)
        try:
            out = _parse_json(chat([
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": event["prompt"]},
            ]))
        except Exception as e:
            print("LLM error, will retry next pass:", e)
            break
        action = out.get("proposed_action")
        if not isinstance(action, str) or not action.strip() or action.strip().lower() in {"null", "none", "no_action"}:
            action = None
        else:
            action = action.strip()
        record = {
            "action": action or "no_action",
            "reason": f"[{event['trigger_type']}] {out.get('decision', '')}",
            "confidence": float(out.get("confidence", 0.5)),
            "requires_authorization": bool(action),
            "checkpoint": out.get("next_checkpoint", ""),
            "reversible": True,
            "source": "llm_trigger_worker",
            "assessment": out.get("assessment", ""),
            "timestamp": now_iso(),
        }
        if action:
            # governed like any agent: classified, budgeted under its own identity, blocked if risky
            text = f"{action.replace('_', ' ')}: {out.get('decision', '')}"
            check = p.cycle(text, source="llm_trigger_worker", reliability=.7, identity=IDENTITY)
            record["approval_key"] = check["verification"]["approval_key"]
            record["requires_authorization"] = not check["verification"]["verified"]
            record["risk_categories"] = check["assessment"]["risk_categories"]
        with p.memory_store.locked():
            p.refresh()
            p.state.decisions.append(record)
            if out.get("next_checkpoint"):
                p.state.next_checkpoint = out["next_checkpoint"]
            p.memory_store.record_memory(p.state, "trigger_decision",
                                         record["reason"], record["confidence"])
            p.memory_store.save(p.state)
        done.add(_key(line))
        DONE.write_text(json.dumps(sorted(done)))
        handled += 1
        print("Handled", event["trigger_type"], "->", record["action"])
    return handled


if __name__ == "__main__":
    if "--once" in sys.argv:
        process_once()
    else:
        print("PATIENCE Trigger Worker running. Ctrl+C to stop.")
        while True:
            try:
                process_once()
                time.sleep(POLL_SECONDS)
            except KeyboardInterrupt:
                break
