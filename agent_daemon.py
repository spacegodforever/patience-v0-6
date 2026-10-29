from __future__ import annotations
import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from engine import Patience

class TriggerAgent:
    """
    PATIENCE Trigger Agent

    Watches PATIENCE state and emits model prompts when:
    - a task becomes due
    - an action is blocked
    - uncertainty is high
    - a checkpoint is reached
    - the system has been idle for a configurable interval

    This agent does NOT bypass governance. It only creates trigger requests.
    """

    def __init__(
        self,
        state_path="patience_state.json",
        queue_path="trigger_queue.jsonl",
        poll_seconds=30,
        idle_minutes=30,
    ):
        self.p = Patience(state_path)
        self.queue_path = Path(queue_path)
        self.poll_seconds = max(5, int(poll_seconds))
        self.idle_minutes = max(1, int(idle_minutes))
        self.last_trigger = None
        self.seen = set()

    def _now(self):
        return datetime.now(timezone.utc)

    def _emit(self, trigger_type, payload):
        key = json.dumps({"type": trigger_type, "payload": payload}, sort_keys=True)
        if key in self.seen:
            return False

        event = {
            "timestamp": self._now().isoformat(),
            "trigger_type": trigger_type,
            "payload": payload,
            "prompt": self._build_prompt(trigger_type, payload),
            "status": "queued"
        }

        with self.queue_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        self.last_trigger = self._now()
        self.seen.add(key)
        return True

    def _build_prompt(self, trigger_type, payload):
        s = self.p.state
        return f"""
PATIENCE AGENT TRIGGER

Trigger: {trigger_type}

MISSION:
{s.mission}

CURRENT OBJECTIVE:
{s.current_objective}

PRIORITY:
{s.priority}

END STATE:
{s.end_state}

TRIGGER PAYLOAD:
{json.dumps(payload, indent=2)}

CURRENT BLOCKED ACTIONS:
{json.dumps(s.blocked_actions, indent=2)}

CURRENT ASSUMPTIONS:
{json.dumps(s.assumptions, indent=2)}

CURRENT UNKNOWNS:
{json.dumps(s.unknowns, indent=2)}

INSTRUCTION:
Evaluate this trigger using the PATIENCE framework.
Separate confirmed facts, assumptions, unknowns, and weak signals.
Run a Red Team check.
Choose the smallest useful next action.
Do not bypass authorization gates.
Return:
1. assessment
2. decision
3. required authorization, if any
4. next checkpoint
""".strip()

    def inspect_once(self):
        # Reload state every cycle
        self.p.state = self.p.memory_store.load()
        now = self._now()
        emitted = []

        # Due tasks
        for task in self.p.time.due_tasks(self.p.state, now):
            if self._emit("task_due", task):
                emitted.append(("task_due", task.get("title")))

        # Blocked actions
        for action in sorted(set(self.p.state.blocked_actions)):
            if self._emit("blocked_action", {"action": action}):
                emitted.append(("blocked_action", action))

        # High uncertainty
        if self.p.state.assessments:
            latest = self.p.state.assessments[-1]
            if latest.get("uncertainty", 0) >= 0.6:
                payload = {
                    "uncertainty": latest.get("uncertainty"),
                    "confidence": latest.get("confidence"),
                    "unknowns": latest.get("unknowns", []),
                    "evidence": latest.get("evidence", []),
                }
                if self._emit("high_uncertainty", payload):
                    emitted.append(("high_uncertainty", payload["uncertainty"]))

        # Explicit checkpoint text
        checkpoint = self.p.state.next_checkpoint
        if checkpoint and checkpoint not in ("", "No scheduled checkpoint"):
            if self._emit("checkpoint", {"checkpoint": checkpoint}):
                emitted.append(("checkpoint", checkpoint))

        # Idle trigger: encourages reassessment, not arbitrary action
        if self.last_trigger is None:
            self.last_trigger = now
        elif now - self.last_trigger >= timedelta(minutes=self.idle_minutes):
            payload = {
                "reason": "idle_reassessment",
                "idle_minutes": self.idle_minutes,
                "current_objective": self.p.state.current_objective,
            }
            if self._emit("idle_reassessment", payload):
                emitted.append(("idle_reassessment", self.idle_minutes))

        return emitted

    def run_forever(self):
        print("PATIENCE Trigger Agent running.")
        print(f"Polling every {self.poll_seconds} seconds.")
        print(f"Queue: {self.queue_path.resolve()}")
        try:
            while True:
                emitted = self.inspect_once()
                for item in emitted:
                    print("TRIGGER:", item)
                time.sleep(self.poll_seconds)
        except KeyboardInterrupt:
            print("PATIENCE Trigger Agent stopped.")

if __name__ == "__main__":
    TriggerAgent().run_forever()
