"""Crash recovery: executions left in 'executing' (process died mid-call) become 'needs_review'.

They are NEVER retried automatically: the side effect may or may not have happened.
A human checks the target system and records the outcome with
POST /v1/admin/requests/{id}/resolve {"outcome": "executed"|"failed", "note": "..."}.
"""
from __future__ import annotations
from datetime import datetime, timezone
import audit
from models import now_iso


def _age(ts: str | None) -> float:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()
    except Exception:
        return float("inf")


def reconcile(p, actor: str = "startup", min_age_seconds: float = 0) -> list:
    flagged = []
    with p.memory_store.locked():
        p.refresh()
        for key, rec in p.state.executions.items():
            if rec.get("status") != "executing" or _age(rec.get("claimed_at")) < min_age_seconds:
                continue
            rec.update(status="needs_review", flagged_at=now_iso(),
                       error="Interrupted while executing; outcome unknown. Check the target system, then resolve.")
            req = p.state.requests.get(rec.get("request_id"))
            if req is not None:
                req["execution"] = {**(req.get("execution") or {}), "status": "needs_review",
                                    "flagged_at": rec["flagged_at"]}
            flagged.append({"request_id": rec.get("request_id"), "idempotency_key": key, "tool": rec.get("tool")})
        if flagged:
            p.memory_store.save(p.state)
    for f in flagged:
        audit.append("execute.needs_review", actor, **f)
    return flagged


def resolve(p, request_id: str, outcome: str, who: dict, note: str = "") -> dict:
    if outcome not in ("executed", "failed"):
        raise ValueError("outcome must be executed or failed")
    with p.memory_store.locked():
        p.refresh()
        req = p.state.requests.get(request_id)
        ex = (req or {}).get("execution") or {}
        if ex.get("status") != "needs_review":
            raise LookupError("That request is not awaiting review.")
        rec = p.state.executions[ex["idempotency_key"]]
        rec.update(status=outcome, resolved_by=who["user"], resolved_at=now_iso(), resolution_note=note[:1000])
        if outcome == "executed":
            rec["executed_at"] = rec["resolved_at"]
        req["execution"] = {"status": outcome, "idempotency_key": ex["idempotency_key"],
                            "resolved_by": who["user"], "resolved_at": rec["resolved_at"]}
        p.memory_store.save(p.state)
    audit.append("execute.resolved", who["user"], request_id=request_id, outcome=outcome, note=note[:1000])
    return {"request_id": request_id, "status": outcome}
