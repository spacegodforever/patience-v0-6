"""Background worker: periodically flags executions stuck in 'executing' as needs_review
(never retries them) and verifies the audit chain. Safe to run next to the API.

Env: PATIENCE_WORKER_INTERVAL (seconds, default 60), PATIENCE_STUCK_SECONDS (default 900).
"""
from __future__ import annotations
import envfile
envfile.load()
import os
import time
import audit
import reconcile
from engine import Patience


def tick() -> dict:
    p = Patience(os.environ.get("PATIENCE_STATE_PATH", "patience_state.json"))
    flagged = reconcile.reconcile(p, "worker", float(os.environ.get("PATIENCE_STUCK_SECONDS", "900")))
    v = audit.verify()
    if not v["ok"]:
        print(f"[worker] AUDIT LOG TAMPERED: {v['error']}", flush=True)
    return {"flagged": flagged, "audit_ok": v["ok"]}


def main():
    interval = float(os.environ.get("PATIENCE_WORKER_INTERVAL", "60"))
    print(f"[worker] running every {interval:.0f}s", flush=True)
    while True:
        try:
            r = tick()
            if r["flagged"]:
                print(f"[worker] flagged {len(r['flagged'])} stuck execution(s) for review", flush=True)
        except Exception as e:  # keep running; never print secrets
            print(f"[worker] error: {type(e).__name__}", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    main()
