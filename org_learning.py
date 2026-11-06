"""L0: detect and tag organizational decisions; persist episodes + options.

Advisory only — does not change gate outcomes or execution. See Product System
Page section "Organizational decision learning" (PR L0).
"""
from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional
from models import now_iso

ORG_KIND = "org_decision"
ROUTINE_KIND = "routine"


def normalize_options(raw: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """Keep options advisory and small. Unknown shapes become summary-only dicts."""
    out: List[Dict[str, Any]] = []
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            out.append({"id": f"opt-{i+1}", "summary": str(item)[:500]})
            continue
        oid = str(item.get("id") or f"opt-{i+1}")[:80]
        summary = str(item.get("summary") or item.get("action") or "").strip()[:500]
        if not summary:
            continue
        entry: Dict[str, Any] = {"id": oid, "summary": summary}
        if "tier" in item and item["tier"] is not None:
            try:
                entry["tier"] = int(item["tier"])
            except (TypeError, ValueError):
                pass
        if "reversible" in item:
            entry["reversible"] = bool(item["reversible"])
        out.append(entry)
        if len(out) >= 8:
            break
    return out


def should_tag(*, situation_kind: Optional[str], options: List[Dict[str, Any]],
               consequence: float) -> bool:
    """L0 rules: explicit flag, or consequence ≥ 0.70 with ≥ 2 options."""
    if (situation_kind or "").strip().lower() == ORG_KIND:
        return True
    return len(options) >= 2 and float(consequence) >= 0.70


def novelty_for_domain(episodes: List[Dict[str, Any]], domain: Optional[str]) -> float:
    """0..1 from in-domain labelled/any episodes. 1.0 = no precedents (fully novel)."""
    if not domain:
        return 1.0
    n = sum(1 for e in episodes if e.get("domain") == domain and e.get("situation_kind") == ORG_KIND)
    return max(0.0, 1.0 - min(1.0, n / 3.0))


def build_episode(*, request_id: str, action: str, domain: Optional[str],
                  options: List[Dict[str, Any]], consequence: float,
                  risk_categories: List[str], decision: str, approval_key: str,
                  identity: str, novelty: float, votes: Optional[list] = None,
                  assessment: Optional[dict] = None) -> Dict[str, Any]:
    a = assessment or {}
    return {
        "id": str(uuid.uuid4()),
        "request_id": request_id,
        "situation_kind": ORG_KIND,
        "domain": domain,
        "action": action[:4000],
        "options": options,
        "chosen_option_id": None,
        "novelty": round(float(novelty), 3),
        "consequence": float(consequence),
        "risk_categories": list(risk_categories or []),
        "gate_result": decision,
        "approval_key": approval_key,
        "identity": identity,
        "relevance": a.get("relevance"),
        "urgency": a.get("urgency"),
        "uncertainty": a.get("uncertainty"),
        "opportunity": a.get("opportunity"),
        "confidence": a.get("confidence"),
        "votes": votes,
        "label_due_at": None,  # L3 sets 7/30/90d reminders
        "created_at": now_iso(),
    }
