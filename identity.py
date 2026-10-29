"""Per-agent identity for the PATIENCE API.

agents.yaml (path: PATIENCE_AGENTS, default ./agents.yaml) stores ONLY hashes:

    agents:
      billing-bot: {key_sha256: "9f86d0...", industry: retail}
      trigger_worker: {key_sha256: "..."}

Create a key (printed once, never stored in clear):
    python identity.py add billing-bot [--industry retail]
    python identity.py revoke billing-bot

The requester is derived from the key; budgets are keyed on it. Keys are 256-bit
random tokens, so a single SHA-256 is an appropriate (non-password) hash; lookup uses
constant-time comparison.

Modes:
  * agents.yaml present with >= 1 agent -> every /v1 call needs "Authorization: Bearer <agent key>"; unknown key -> 401.
  * no agents file -> legacy single-token mode: PATIENCE_API_TOKEN (identity "default"),
    or, if that is unset too, local dev mode (identity "local-dev"). /v1/execute is refused
    outside agent-key mode.
"""
from __future__ import annotations
import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path
from typing import Optional
import yaml


def agents_path() -> Path:
    return Path(os.environ.get("PATIENCE_AGENTS") or Path(__file__).resolve().parent / "agents.yaml")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def load_agents() -> dict:
    p = agents_path()
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {str(k): (v or {}) for k, v in (data.get("agents") or {}).items()}


def agent_mode() -> bool:
    return bool(load_agents())


def resolve(key: Optional[str]) -> Optional[dict]:
    """Return {"id", ...config} for a valid key, else None. Checks every entry (no early exit)."""
    if not key:
        return None
    h = hash_key(key)
    found = None
    for name, cfg in load_agents().items():
        stored = str(cfg.get("key_sha256", ""))
        if stored and hmac.compare_digest(stored, h) and not cfg.get("disabled"):
            found = {"id": name, **{k: v for k, v in cfg.items() if k != "key_sha256"}}
    return found


def _write(agents: dict):
    p = agents_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump({"agents": agents}, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


def add_agent(name: str, industry: Optional[str] = None) -> str:
    agents = load_agents()
    key = "pat_" + secrets.token_urlsafe(32)
    agents[name] = {"key_sha256": hash_key(key), **({"industry": industry} if industry else {})}
    _write(agents)
    return key


def revoke_agent(name: str) -> bool:
    agents = load_agents()
    if name not in agents:
        return False
    del agents[name]
    _write(agents)
    return True


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "add":
        ind = sys.argv[sys.argv.index("--industry") + 1] if "--industry" in sys.argv else None
        print(f"API key for {sys.argv[2]} (shown once; store it in that agent's secret store):")
        print(add_agent(sys.argv[2], ind))
    elif len(sys.argv) >= 3 and sys.argv[1] == "revoke":
        print("revoked" if revoke_agent(sys.argv[2]) else "unknown agent")
    else:
        print(__doc__)
