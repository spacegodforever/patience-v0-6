"""Logic behind the v0.6 dashboard (kept out of Streamlit so it is unit-testable).

metrics(), pending_queue(), search_audit(), decide_pending() and the admin-only,
audited, validate-before-save policy editor (validate_policy / save_policy).
"""
from __future__ import annotations
import hashlib
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Optional
import yaml
import audit
import decisions
import risk_policy

STATUSES = ("allowed", "pending", "approved", "denied", "executed", "needs_review")


def status(state, req) -> str:
    import api  # single source of truth for request status
    return api._status(state, req)


# ---------------- metrics ----------------
def metrics(state, records: Optional[list] = None) -> dict:
    records = audit.read() if records is None else records
    reqs = list(state.requests.values())
    counts = Counter(status(state, r) for r in reqs)
    decisions_ = Counter(r.get("decision") for r in reqs)
    blocked_cats = Counter(c for r in reqs if r.get("decision") != "allow" for c in (r.get("risk_categories") or []))
    by_day: dict = {}
    for e in records:
        ev, day = e["event"], e["ts"][:10]
        if ev == "check":
            d = by_day.setdefault(day, Counter())
            d["checks"] += 1
            if e["data"].get("decision") != "allow":
                d["held"] += 1
        elif ev in ("approval.approved", "approval.denied"):
            by_day.setdefault(day, Counter())["approvals" if ev.endswith("approved") else "denials"] += 1
    series = [{"day": d, "metric": k, "count": v} for d, c in sorted(by_day.items())
              for k in ("checks", "held", "approvals", "denials") for v in [c.get(k, 0)]]
    return {"checks": len(reqs), "status": dict(counts), "decisions": dict(decisions_),
            "approvals": sum(1 for x in state.approval_log if x["decision"] == "approved"),
            "denials": sum(1 for x in state.approval_log if x["decision"] == "denied"),
            "blocks_by_category": dict(blocked_cats.most_common()), "series": series}


# ---------------- pending queue ----------------
def pending_queue(state) -> list:
    out = [r for r in state.requests.values() if status(state, r) in ("pending", "needs_review")]
    return sorted(out, key=lambda r: r.get("created_at", ""))


def decide_pending(p, request_id: str, approve: bool, who: Optional[dict], reason: str = "") -> dict:
    """Same rules as the API: only pending requests, recorded with approver/time/reason."""
    if not who:
        raise PermissionError("Approver login required.")
    p.refresh()
    req = p.state.requests.get(request_id)
    if not req or status(p.state, req) != "pending":
        raise ValueError("That request is no longer pending.")
    return decisions.decide(p, req["approval_key"], approve, who, reason, via="dashboard", request_id=request_id)


# ---------------- audit search ----------------
def search_audit(query: str = "", event: str = "", limit: int = 500, records: Optional[list] = None) -> list:
    records = audit.read() if records is None else records
    q = (query or "").lower().strip()
    out = []
    for e in reversed(records):
        if event and not e["event"].startswith(event):
            continue
        if q and q not in (f"{e['event']} {e.get('actor')} {e['data']}").lower():
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


# ---------------- policy editor (admin only, audited) ----------------
def policy_path() -> Path:
    return Path(os.environ.get("PATIENCE_POLICY") or risk_policy.DEFAULT_POLICY)


def read_policy() -> str:
    return policy_path().read_text(encoding="utf-8")


REQUIRED_KEYS = ("categories", "thresholds")


def validate_policy(text: str) -> list:
    """Return a list of problems ([] = valid). Parses YAML and builds a real Policy from it."""
    errs = []
    if len(text) > 1_000_000:
        return ["Policy is too large."]
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return [f"YAML syntax error: {str(e)[:300]}"]
    if not isinstance(raw, dict):
        return ["Policy must be a YAML mapping."]
    for k in REQUIRED_KEYS:
        if k not in raw:
            errs.append(f"Missing required section: {k}")
    if errs:
        return errs
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(text)
        tmp = f.name
    try:
        pol = risk_policy.Policy(tmp)
        if not pol.categories:
            errs.append("No categories defined.")
        # smoke: the policy still holds the obvious risky action
        r = risk_policy.classify("delete all customer records", policy=pol)
        if not r.get("categories"):
            errs.append("Sanity check failed: 'delete all customer records' is no longer flagged as risky.")
    except Exception as e:
        errs.append(f"Policy failed to load: {type(e).__name__}: {str(e)[:300]}")
    finally:
        os.unlink(tmp)
    return errs


def save_policy(text: str, who: Optional[dict], note: str = "") -> dict:
    if not who or who.get("role") != "admin":
        audit.append("policy.denied", (who or {}).get("user"), reason="not admin")
        raise PermissionError("Only admins can edit the policy.")
    errs = validate_policy(text)
    if errs:
        raise ValueError("; ".join(errs))
    path = policy_path()
    old = path.read_text(encoding="utf-8")
    old_h, new_h = (hashlib.sha256(x.encode()).hexdigest() for x in (old, text))
    if old_h == new_h:
        return {"changed": False, "sha256": new_h}
    backup = path.with_suffix(path.suffix + ".bak")
    backup.write_text(old, encoding="utf-8")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    risk_policy.reload_policy()
    import difflib
    diff = list(difflib.unified_diff(old.splitlines(), text.splitlines(), "before", "after", lineterm="", n=0))
    audit.append("policy.updated", who["user"], path=str(path), old_sha256=old_h, new_sha256=new_h,
                 note=note[:500], diff="\n".join(diff)[:20000])
    return {"changed": True, "sha256": new_h, "backup": str(backup)}
