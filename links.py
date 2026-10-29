"""Short-lived, single-use, HMAC-signed approve/deny links.

token = b64url(payload) "." b64url(HMAC-SHA256(secret, payload))
payload = {"r": request_id, "a": "approve"|"deny", "h": request_hash, "exp": unix, "n": nonce}

* Signed with PATIENCE_LINK_SECRET (32+ chars). Without it, no links are issued.
* Expire after PATIENCE_LINK_TTL_SECONDS (default 900).
* Single use: the nonce is recorded in state.used_links when consumed.
* Bound to the request hash (id + action text + args hash): a changed request invalidates the link.
* A link alone never approves anything: the landing page also needs an approver login or PIN.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time


class LinkError(Exception):
    pass


def _secret() -> bytes:
    s = os.environ.get("PATIENCE_LINK_SECRET", "")
    if len(s) < 32:
        raise LinkError("PATIENCE_LINK_SECRET is not set (32+ characters); one-tap links are disabled.")
    return s.encode()


def enabled() -> bool:
    return len(os.environ.get("PATIENCE_LINK_SECRET", "")) >= 32


def ttl() -> int:
    return int(os.environ.get("PATIENCE_LINK_TTL_SECONDS", "900"))


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make(request_id: str, action: str, request_hash: str, now: float | None = None) -> str:
    if action not in ("approve", "deny"):
        raise ValueError("action must be approve or deny")
    payload = {"r": request_id, "a": action, "h": request_hash, "exp": int((now or time.time()) + ttl()),
               "n": secrets.token_urlsafe(12)}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _b64(raw) + "." + _b64(hmac.new(_secret(), raw, hashlib.sha256).digest())


def parse(token: str, now: float | None = None) -> dict:
    """Verify signature and expiry (NOT single-use; consume() does that under the state lock)."""
    try:
        p64, s64 = (token or "").split(".")
        raw, sig = _unb64(p64), _unb64(s64)
    except Exception:
        raise LinkError("Malformed link.")
    if not hmac.compare_digest(hmac.new(_secret(), raw, hashlib.sha256).digest(), sig):
        raise LinkError("Invalid link signature.")
    payload = json.loads(raw)
    if payload.get("a") not in ("approve", "deny") or not payload.get("n"):
        raise LinkError("Malformed link.")
    if (now or time.time()) > payload["exp"]:
        raise LinkError("This link has expired.")
    return payload


def is_used(state, payload) -> bool:
    return payload["n"] in state.used_links


def consume(p, payload) -> None:
    """Mark the nonce used (call inside p.memory_store.locked()). Prunes expired nonces."""
    if payload["n"] in p.state.used_links:
        raise LinkError("This link was already used.")
    now = time.time()
    p.state.used_links = {k: v for k, v in p.state.used_links.items() if v > now}
    p.state.used_links[payload["n"]] = payload["exp"]
