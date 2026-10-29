"""Per-approver accounts (approvers.yaml, path in PATIENCE_APPROVERS).

    approvers:
      alice: {password: "scrypt$16384$8$1$<salt>$<hash>", role: admin, pin: "scrypt$...", disabled: false}

Roles: approver (approve/deny), admin (also edit policy, reconcile, manage accounts).
Passwords and PINs are stored only as scrypt hashes (stdlib hashlib.scrypt, random salt).

    python approvers.py add <user> [--role approver|admin]   (prompts for password, optional PIN)
    python approvers.py set-pin <user>
    python approvers.py disable <user>
    python approvers.py list
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
import yaml

ROLES = ("approver", "admin")
_N, _R, _P = 2 ** 14, 8, 1
_FAILS: dict = {}  # in-process brute-force throttle: user -> [count, locked_until]
MAX_FAILS, LOCK_S = 5, 300


def approvers_path() -> Path:
    return Path(os.environ.get("PATIENCE_APPROVERS", Path(__file__).with_name("approvers.yaml")))


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(secret.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def check_secret(secret: str, stored: Optional[str]) -> bool:
    try:
        _, n, r, p, salt, h = (stored or "").split("$")
        got = hashlib.scrypt((secret or "").encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(base64.b64decode(h)))
        return hmac.compare_digest(got, base64.b64decode(h))
    except Exception:
        return False


_DUMMY = None


def load() -> dict:
    p = approvers_path()
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return dict(data.get("approvers") or {})


def configured() -> bool:
    return bool(load())


def _save(accts: dict):
    p = approvers_path()
    p.write_text(yaml.safe_dump({"approvers": accts}, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _throttled(user: str) -> bool:
    c = _FAILS.get(user)
    return bool(c and c[1] > time.time())


def _fail(user: str):
    c = _FAILS.setdefault(user, [0, 0])
    c[0] += 1
    if c[0] >= MAX_FAILS:
        c[0], c[1] = 0, time.time() + LOCK_S


def _verify(user: str, secret: str, field: str) -> Optional[dict]:
    global _DUMMY
    user = (user or "").strip()
    if not user or _throttled(user):
        return None
    cfg = load().get(user)
    if not cfg or cfg.get("disabled") or not cfg.get(field):
        _DUMMY = _DUMMY or hash_secret("x")
        check_secret(secret, _DUMMY)  # equalise timing for unknown users
        _fail(user)
        return None
    if not check_secret(secret, cfg[field]):
        _fail(user)
        return None
    _FAILS.pop(user, None)
    role = cfg.get("role", "approver")
    return {"user": user, "role": role if role in ROLES else "approver"}


def verify_password(user: str, password: str) -> Optional[dict]:
    return _verify(user, password, "password")


def verify_pin(user: str, pin: str) -> Optional[dict]:
    return _verify(user, pin, "pin")


def add(user: str, password: str, role: str = "approver", pin: Optional[str] = None) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password or "") < 10:
        raise ValueError("password must be at least 10 characters")
    if pin is not None and (not pin.isdigit() or len(pin) < 6):
        raise ValueError("PIN must be at least 6 digits")
    accts = load()
    accts[user] = {"password": hash_secret(password), "role": role}
    if pin:
        accts[user]["pin"] = hash_secret(pin)
    _save(accts)


def set_pin(user: str, pin: str):
    if not pin.isdigit() or len(pin) < 6:
        raise ValueError("PIN must be at least 6 digits")
    accts = load()
    accts[user]["pin"] = hash_secret(pin)
    _save(accts)


def disable(user: str) -> bool:
    accts = load()
    if user not in accts:
        return False
    accts[user]["disabled"] = True
    _save(accts)
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="approvers.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("user"); a.add_argument("--role", default="approver", choices=ROLES)
    s = sub.add_parser("set-pin"); s.add_argument("user")
    d = sub.add_parser("disable"); d.add_argument("user")
    sub.add_parser("list")
    ns = ap.parse_args(argv)
    if ns.cmd == "add":
        pw = getpass.getpass("Password (10+ chars): ")
        pin = getpass.getpass("Approval PIN for one-tap links (6+ digits, blank to skip): ") or None
        add(ns.user, pw, ns.role, pin)
        print(f"Added {ns.user} ({ns.role}).")
    elif ns.cmd == "set-pin":
        set_pin(ns.user, getpass.getpass("New PIN: "))
        print("PIN set.")
    elif ns.cmd == "disable":
        print("Disabled." if disable(ns.user) else "No such user.")
    else:
        for u, c in sorted(load().items()):
            print(f"{u:20} {c.get('role','approver'):9} {'disabled' if c.get('disabled') else 'active'}"
                  f"{'  pin' if c.get('pin') else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
