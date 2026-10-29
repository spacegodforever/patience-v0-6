from __future__ import annotations
import re
from typing import Dict, Any, List, Tuple
from models import Assessment, Observation, PatienceState

class Oracle:
    """Assessment of an observation. Risk categories come from risk_policy.classify."""
    # Risk scoring is policy-driven: see risk_policy.py and policies/default.yaml.

    def risk_categories(self, text: str, tags=()):
        from risk_policy import classify
        r = classify(text, tags)
        return r["categories"], r["consequence"], r["irreversible"]

    def assess(self, obs: Observation, state: PatienceState) -> Assessment:
        text = obs.content.lower()
        urgency = .8 if any(w in text for w in ["now","urgent","today","deadline","immediately"]) else .35
        from risk_policy import classify
        if "tool_call" in (obs.tags or []):
            # structured call: risk comes from the tool args (engine extra_risk), not this summary text
            risk = {"categories": [], "consequence": .25, "irreversible": False, "read_only": False}
        else:
            risk = classify(obs.content, obs.tags)
        categories, consequence, irreversible = risk["categories"], risk["consequence"], risk["irreversible"]
        if risk["read_only"]:
            opportunity_ok = False
        else:
            opportunity_ok = True
        opportunity = .8 if opportunity_ok and any(w in text for w in ["build","prototype","launch","test","integrate","improve"]) else .35
        uncertainty = .75 if any(w in text for w in ["maybe","unclear","unknown","guess","possibly","not sure"]) else .3

        objective_words = set(state.current_objective.lower().split())
        overlap = sum(1 for w in objective_words if len(w) > 3 and w in text)
        relevance = min(.95, .55 + overlap * .08) if objective_words else .6

        confidence = max(.05, min(.95,
            .45 * obs.reliability +
            .25 * (1 - uncertainty) +
            .30 * relevance
        ))

        assumptions = []
        unknowns = []
        if obs.reliability < .7:
            assumptions.append("Observation source is not independently verified.")
        if uncertainty >= .6:
            unknowns.append("Material context may be missing.")
        if consequence >= .7:
            unknowns.append("Downstream consequence requires explicit review.")
        for c in categories:
            unknowns.append(f"Side-effect category '{c}' requires human authorization.")

        return Assessment(
            relevance=relevance,
            urgency=urgency,
            uncertainty=uncertainty,
            consequence=consequence,
            opportunity=opportunity,
            confidence=confidence,
            evidence=[obs.content],
            assumptions=assumptions,
            unknowns=unknowns,
            competing_explanations=[
                "Observation is materially correct and actionable.",
                "Observation is directionally correct but incomplete.",
                "Observation is low-signal or misleading and should not drive action."
            ],
            risk_categories=categories,
            irreversible=irreversible,
        )

    def red_team(self, a: Assessment) -> Dict[str, Any]:
        flags = []
        if a.opportunity > .7 and a.consequence > .6:
            flags.append("optimism_bias")
        if a.confidence > .8 and a.uncertainty > .5:
            flags.append("overconfidence")
        if len(a.evidence) == 1:
            flags.append("single_source_dependency")
        if a.urgency > .7:
            flags.append("urgency_pressure")
        return {
            "bias_flags": flags,
            "counterfactual": "What would make the opposite decision correct?",
            "cheapest_test": (
                "Gather one independent source or run one reversible test."
                if a.uncertainty >= .5 or "single_source_dependency" in flags
                else "Proceed with a reversible low-cost step and verify."
            )
        }
