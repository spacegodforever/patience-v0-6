from dataclasses import asdict
from models import Observation, Task
from oracle import Oracle
from adapters import ModelCouncil
from governance import GovernanceGate
from scheduler import TemporalLayer
from memory_store import MemoryStore


def second_opinion_risk(content, tags=(), rules_categories=None):
    """LLM second opinion -> extra_risk dict, or None. Skipped without an API key."""
    import second_opinion
    if not second_opinion.enabled():
        return None
    if rules_categories is None:
        from risk_policy import classify
        rules_categories = classify(content, tags)["categories"]
    op = second_opinion.review(content, rules_categories)
    if op.get("disagree"):
        return {"categories": ["llm_disagreement"], "consequence": .75, "irreversible": False,
                "reasons": [f"LLM second opinion: {op.get('reason', '')}"], "second_opinion": op}
    return {"categories": [], "second_opinion": op}


class Patience:
    # Public mutators reload state under a file lock, then save atomically.
    def __init__(self, state_path="patience_state.json"):
        self.memory_store = MemoryStore(state_path)
        self.state = self.memory_store.load()
        # Repair legacy state: generic standing approvals are not allowed.
        bad = [x for x in self.state.authorized_actions if x in GovernanceGate.NEVER_STANDING]
        if bad:
            self.state.authorized_actions = [x for x in self.state.authorized_actions if x not in bad]
        self.oracle = Oracle()
        self.council = ModelCouncil()
        self.governance = GovernanceGate()
        self.time = TemporalLayer()

    def refresh(self):
        self.state = self.memory_store.load()
        bad = [x for x in self.state.authorized_actions if x in GovernanceGate.NEVER_STANDING]
        if bad:
            self.state.authorized_actions = [x for x in self.state.authorized_actions if x not in bad]

    def _set_mission_unlocked(self, mission, end_state, objective, priority):
        self.state.mission = mission
        self.state.end_state = end_state
        self.state.current_objective = objective
        self.state.priority = priority
        self.memory_store.save(self.state)

    def _authorize_unlocked(self, action):
        if action in GovernanceGate.NEVER_STANDING:
            # Legacy generic entry: clear it, but never grant a standing approval.
            self.state.blocked_actions = [x for x in self.state.blocked_actions if x != action]
            self.memory_store.save(self.state)
            return False
        if action not in self.state.authorized_actions:
            self.state.authorized_actions.append(action)
            pend = self.state.pending_usage.pop(action, None)
            if pend:  # approved work counts toward the agent's rolling budget
                self._record_usage(pend["identity"], pend["tool"], pend["usage"])
        self.state.blocked_actions = [x for x in self.state.blocked_actions if x != action]
        self.memory_store.save(self.state)
        return True

    def _add_task_unlocked(self, title, due_at=None, priority=3):
        self.time.add_task(self.state, Task(title=title, due_at=due_at, priority=priority))
        self.state.next_checkpoint = self.time.next_checkpoint(self.state)
        self.memory_store.save(self.state)

    def _budget_risk(self, identity, tool, usage):
        """Rolling per-identity budgets. Returns (extra_risk or None, usage)."""
        import risk_policy
        crossed = risk_policy.check_budgets(self.state.usage_log, identity, tool, usage, risk_policy.now())
        if not crossed:
            return None
        return {"categories": ["budget_exceeded"], "consequence": .85, "irreversible": True,
                "reasons": ["rolling budget: " + "; ".join(crossed)]}

    def _record_usage(self, identity, tool, usage):
        import risk_policy
        t = risk_policy.now()
        self.state.usage_log = risk_policy.prune_usage(self.state.usage_log, t)
        self.state.usage_log.append({"requester": identity, "tool": tool, "ts": t, "usage": usage})

    def _cycle_unlocked(self, content, source="user", reliability=.9, tags=(), extra_risk=None,
                        identity=None, tool=None, usage=None):
        """extra_risk: optional {"categories": [...], "consequence": float, "irreversible": bool,
        "reasons": [...]} from tool-arg scoring, budgets, or the LLM second opinion. It can only
        ADD risk to the rules assessment, never remove it."""
        obs = Observation(content=content, source=source, reliability=reliability, tags=list(tags or []))
        self.state.observations.append(asdict(obs))

        assessment = self.oracle.assess(obs, self.state)
        if identity:
            # budgets are keyed on the authenticated identity, for tool AND free-text calls
            import risk_policy
            if usage is None:
                usage = risk_policy.text_usage(content, assessment.risk_categories)
            usage = {**usage, "calls": 1}
            tool = tool or "text"
            b = self._budget_risk(identity, tool, usage)
            if b:
                extra_risk = dict(extra_risk or {})
                extra_risk["categories"] = list(extra_risk.get("categories", [])) + b["categories"]
                extra_risk["consequence"] = max(float(extra_risk.get("consequence", 0)), b["consequence"])
                extra_risk["irreversible"] = True
                extra_risk.setdefault("reasons", [])
                extra_risk["reasons"] = list(extra_risk["reasons"]) + b["reasons"]
        if extra_risk and extra_risk.get("categories"):
            for c in extra_risk["categories"]:
                if c not in assessment.risk_categories:
                    assessment.risk_categories.append(c)
                    assessment.unknowns.append(f"Side-effect category '{c}' requires human authorization.")
            assessment.consequence = max(assessment.consequence, float(extra_risk.get("consequence", .75)))
            assessment.irreversible = bool(assessment.irreversible or extra_risk.get("irreversible"))
            if "unknown_side_effect" in assessment.risk_categories and len(assessment.risk_categories) > 1:
                assessment.risk_categories.remove("unknown_side_effect")
        self.state.assessments.append(asdict(assessment))
        self.state.assumptions = assessment.assumptions
        self.state.unknowns = assessment.unknowns

        red = self.oracle.red_team(assessment)

        votes = self.council.deliberate(assessment)
        self.state.model_votes.extend(asdict(v) for v in votes)
        recommendation = self.council.consensus(votes)

        decision = self.governance.decide(recommendation, assessment, red["cheapest_test"])
        self.state.decisions.append(asdict(decision))
        self.state.next_checkpoint = decision.checkpoint

        key = (self.governance.approval_key(decision, obs.content, obs.id)
               if decision.requires_authorization else decision.action)
        allowed = self.governance.may_execute(decision, self.state.authorized_actions, key)
        if not allowed and key not in self.state.blocked_actions:
            self.state.blocked_actions.append(key)
        if identity:
            if allowed:
                self._record_usage(identity, tool, usage)
            else:  # counted only if a human approves it
                self.state.pending_usage[key] = {"identity": identity, "tool": tool, "usage": usage}

        verification = {
            "verified": allowed,
            "status": "ready_or_executed" if allowed else "blocked_pending_authorization",
            "approval_key": key,
            "risk_categories": assessment.risk_categories,
            "budget_reasons": (extra_risk or {}).get("reasons", []),
            "identity": identity,
            "expected_outcome": decision.checkpoint
        }

        self.memory_store.record_memory(
            self.state,
            "decision",
            f"{decision.action}: {decision.reason}",
            decision.confidence
        )
        self.memory_store.save(self.state)

        return {
            "observation": asdict(obs),
            "assessment": asdict(assessment),
            "red_team": red,
            "model_votes": [asdict(v) for v in votes],
            "consensus": recommendation,
            "decision": asdict(decision),
            "verification": verification,
            "next_checkpoint": self.state.next_checkpoint
        }

    def set_mission(self, mission, end_state, objective, priority):
        with self.memory_store.locked():
            self.refresh()
            return self._set_mission_unlocked(mission, end_state, objective, priority)

    def authorize(self, action):
        with self.memory_store.locked():
            self.refresh()
            return self._authorize_unlocked(action)

    def add_task(self, title, due_at=None, priority=3):
        with self.memory_store.locked():
            self.refresh()
            return self._add_task_unlocked(title, due_at, priority)

    def cycle(self, content, source="user", reliability=.9, tags=(), identity=None):
        extra = second_opinion_risk(content, tags)  # network call happens outside the state lock
        with self.memory_store.locked():
            self.refresh()
            return self._cycle_unlocked(content, source, reliability, tags, extra, identity=identity)

    def deny(self, key):
        with self.memory_store.locked():
            self.refresh()
            self.state.blocked_actions = [x for x in self.state.blocked_actions if x != key]
            self.state.authorized_actions = [x for x in self.state.authorized_actions if x != key]
            if key not in self.state.denied_actions:
                self.state.denied_actions.append(key)
            self.state.pending_usage.pop(key, None)
            self.memory_store.save(self.state)
