from models import Assessment, Decision

class GovernanceGate:
    AUTONOMOUS = {"respond","research","summarize","log","wait","remind","inspect_state"}

    def decide(self, recommendation: str, a: Assessment, cheapest_test: str) -> Decision:
        cats = getattr(a, "risk_categories", []) or []
        if cats or recommendation == "human_review" or a.consequence >= .7:
            reason = ("Side-effect categories " + ", ".join(cats) + " require explicit authorization."
                      if cats else "Consequence threshold requires explicit authorization.")
            return Decision(
                action="human_review",
                reason=reason,
                confidence=a.confidence,
                requires_authorization=True,
                checkpoint="After human authorization",
                reversible=not bool(getattr(a, "irreversible", False) or not cats)
            )
        if recommendation == "research":
            return Decision(
                action="research",
                reason=cheapest_test,
                confidence=a.confidence,
                requires_authorization=False,
                checkpoint="After evidence acquisition"
            )
        if recommendation == "prototype":
            return Decision(
                action="prototype",
                reason="Test the opportunity with a reversible prototype.",
                confidence=a.confidence,
                requires_authorization=True,
                checkpoint="After prototype verification"
            )
        return Decision(
            action="respond",
            reason="No elevated consequence or evidence deficit detected.",
            confidence=a.confidence,
            requires_authorization=False,
            checkpoint="After user response"
        )

    # Generic action names that must never be standing-authorized: approving
    # "human_review" once would silently approve every future risky request.
    NEVER_STANDING = {"human_review", "prototype"}

    @staticmethod
    def approval_key(decision: Decision, content: str = "", obs_id: str = "") -> str:
        """Specific, per-request key shown in blocked_actions."""
        snippet = " ".join(content.split())[:80]
        tag = f" #{obs_id[:8]}" if obs_id else ""
        return f"{decision.action}: {snippet}{tag}" if snippet else decision.action

    def may_execute(self, decision: Decision, authorized_actions: list[str], key: str | None = None) -> bool:
        if decision.requires_authorization:
            k = key or decision.action
            if k in self.NEVER_STANDING:
                return False
            return k in authorized_actions
        if decision.action in self.AUTONOMOUS:
            return True
        return decision.action in authorized_actions
