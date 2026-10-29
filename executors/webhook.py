from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import urllib.request
from .base import Executor, ExecutionError, live_mode


class WebhookExecutor(Executor):
    """Generic connector: POST the approved call to a Zapier / Make / n8n catch hook.

    Env: PATIENCE_WEBHOOK_URL_<TOOL> (e.g. PATIENCE_WEBHOOK_URL_REFUND) or PATIENCE_WEBHOOK_URL
    (fallback for every tool). Optional PATIENCE_WEBHOOK_SECRET signs the body:
    header X-Patience-Signature: sha256=<hex hmac>. https only (http allowed for localhost).
    Body: {tool, args, request_id, idempotency_key, identity}. The receiver should dedupe on
    idempotency_key.
    """
    name = "webhook"

    @staticmethod
    def url_for(tool: str):
        env = "PATIENCE_WEBHOOK_URL_" + re.sub(r"[^A-Z0-9]", "_", (tool or "").upper())
        return os.environ.get(env) or os.environ.get("PATIENCE_WEBHOOK_URL")

    def run(self, tool, args, meta):
        url = self.url_for(tool)
        if not url:
            raise ExecutionError("no webhook configured for this tool")
        if not (url.startswith("https://") or re.match(r"http://(127\.0\.0\.1|localhost)(:\d+)?/", url)):
            raise ExecutionError("webhook URL must be https")
        body = json.dumps({"tool": tool, "args": args, **meta}, sort_keys=True, default=str).encode()
        if not live_mode():
            return {"executor": self.name, "live": False, "dry_run": True, "would_post_bytes": len(body)}
        headers = {"Content-Type": "application/json",
                   "Idempotency-Key": str(meta.get("idempotency_key", ""))}
        secret = os.environ.get("PATIENCE_WEBHOOK_SECRET")
        if secret:
            headers["X-Patience-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=30) as r:
                status = r.status
        except Exception as e:  # don't leak the (secret-bearing) hook URL
            raise ExecutionError(f"webhook POST failed ({type(e).__name__})") from None
        if status >= 300:
            raise ExecutionError(f"webhook returned HTTP {status}")
        return {"executor": self.name, "live": True, "http_status": status}
