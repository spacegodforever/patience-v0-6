from __future__ import annotations
from typing import List
from models import Assessment, ModelVote

class BaseModelAdapter:
    name = "base"
    def vote(self, assessment: Assessment) -> ModelVote:
        raise NotImplementedError

class OracleAdapter(BaseModelAdapter):
    name = "oracle-local"
    def vote(self, a: Assessment) -> ModelVote:
        if a.consequence >= .7:
            rec = "human_review"
        elif a.uncertainty >= .6:
            rec = "research"
        elif a.opportunity >= .65:
            rec = "prototype"
        else:
            rec = "respond"
        return ModelVote(self.name, rec, a.confidence, "Local structured assessment vote.")

class SkepticAdapter(BaseModelAdapter):
    name = "skeptic"
    def vote(self, a: Assessment) -> ModelVote:
        if a.uncertainty >= .45:
            rec = "research"
        elif a.consequence >= .55:
            rec = "human_review"
        else:
            rec = "respond"
        return ModelVote(
            self.name, rec, max(.2, a.confidence - .1),
            "Conservative dissent-oriented vote.",
            "Prefer evidence acquisition before escalation."
        )

class OpportunityAdapter(BaseModelAdapter):
    name = "opportunity"
    def vote(self, a: Assessment) -> ModelVote:
        if a.consequence >= .8:
            rec = "human_review"
        elif a.opportunity >= .65 and a.uncertainty < .65:
            rec = "prototype"
        else:
            rec = "respond"
        return ModelVote(
            self.name, rec, max(.2, a.confidence - .05),
            "Opportunity-seeking but consequence-aware vote."
        )

class ModelCouncil:
    def __init__(self, adapters: List[BaseModelAdapter] | None = None):
        if adapters is None:
            adapters = [OracleAdapter(), SkepticAdapter(), OpportunityAdapter()]
            # v0.5: optional advisory LLM vote, only when PATIENCE_LLM_API_KEY is set
            try:
                from llm_adapter import LLMAdapter, llm_enabled
                import second_opinion
                # One LLM call per check: when the second opinion is on it is the LLM's only
                # say (it can escalate but never downgrade); the advisory council vote is skipped.
                if llm_enabled() and not second_opinion.enabled():
                    adapters.append(LLMAdapter())
            except ImportError:
                pass
        self.adapters = adapters

    def deliberate(self, assessment: Assessment) -> List[ModelVote]:
        return [adapter.vote(assessment) for adapter in self.adapters]

    def consensus(self, votes: List[ModelVote]) -> str:
        weights = {}
        for v in votes:
            weights[v.recommendation] = weights.get(v.recommendation, 0.0) + v.confidence
        return max(weights, key=weights.get)
