"""Dashboard login (per approver account) - used by dashboard.py, unit-testable.

Accounts come from approvers.yaml (python approvers.py add <user> --role admin).
Legacy: PATIENCE_LEGACY_DASHBOARD_PASSWORD=1 plus PATIENCE_DASHBOARD_PASSWORD[_SHA256]
allows one shared password (recorded as approver "legacy-dashboard"); off unless enabled.
No accounts (and no legacy) -> dashboard is READ-ONLY.
Five failed tries lock the session for 5 minutes; a login lasts
PATIENCE_DASHBOARD_SESSION_HOURS (default 8).
"""
from __future__ import annotations
import hashlib
import hmac
import os
import time
import approvers
import audit
import decisions

MAX_TRIES, LOCKOUT_S = 5, 300


def _legacy_hash():
    if os.environ.get("PATIENCE_LEGACY_DASHBOARD_PASSWORD") != "1":
        return None
    h = os.environ.get("PATIENCE_DASHBOARD_PASSWORD_SHA256")
    if h:
        return h.strip().lower()
    pw = os.environ.get("PATIENCE_DASHBOARD_PASSWORD")
    return hashlib.sha256(pw.encode()).hexdigest() if pw else None


def password_configured() -> bool:
    """True when anyone can log in at all (accounts exist, or legacy password explicitly on)."""
    return approvers.configured() or _legacy_hash() is not None


def login(session, user: str, password: str) -> bool:
    now = time.time()
    if session.get("locked_until", 0) > now:
        return False
    who = approvers.verify_password(user, password) if approvers.configured() else None
    if not who and _legacy_hash() and (user or "") in ("", "legacy"):
        if hmac.compare_digest(hashlib.sha256((password or "").encode()).hexdigest(), _legacy_hash()):
            who = {"user": "legacy-dashboard", "role": "approver", "legacy": True}
    if who:
        session["approver"], session["patience_authed_at"], session["failed"] = who, now, 0
        audit.append("auth.login", who["user"], channel="dashboard")
        return True
    session["failed"] = session.get("failed", 0) + 1
    if session["failed"] >= MAX_TRIES:
        session["locked_until"], session["failed"] = now + LOCKOUT_S, 0
    audit.append("auth.failed", (user or "")[:100], channel="dashboard")
    time.sleep(0.5)
    return False


def logout(session):
    session.pop("patience_authed_at", None)
    session.pop("approver", None)


def current(session):
    if not password_configured():
        return None
    t, who = session.get("patience_authed_at"), session.get("approver")
    ttl = float(os.environ.get("PATIENCE_DASHBOARD_SESSION_HOURS", "8")) * 3600
    if not (t and who and time.time() - t < ttl):
        return None
    # re-check the account still exists and is enabled (revocation takes effect immediately)
    if not who.get("legacy"):
        cfg = approvers.load().get(who["user"])
        if not cfg or cfg.get("disabled"):
            return None
        who = {"user": who["user"], "role": cfg.get("role", "approver")}
    return who


def is_authed(session) -> bool:
    return current(session) is not None


def can_approve(session) -> bool:
    return is_authed(session)


def is_admin(session) -> bool:
    who = current(session)
    return bool(who and who["role"] == "admin")


def approve(p, key: str, session, reason: str = "", request_id=None):
    """The only path the dashboard uses to authorize. Refuses without a valid session."""
    who = current(session)
    if not who:
        raise PermissionError("Dashboard approval requires an approver login.")
    return decisions.decide(p, key, True, who, reason, via="dashboard", request_id=request_id)


def deny(p, key: str, session, reason: str = "", request_id=None):
    who = current(session)
    if not who:
        raise PermissionError("Dashboard denial requires an approver login.")
    return decisions.decide(p, key, False, who, reason, via="dashboard", request_id=request_id)
