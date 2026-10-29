"""Approval alerts: SMTP email, Slack incoming webhook, generic webhook.

Sent when a check needs approval. Each alert has the action preview and one-tap
approve/deny links (links.py). DRY-RUN unless PATIENCE_EXECUTE_LIVE=1: messages are
composed and returned but not sent.

Env:
  PATIENCE_PUBLIC_URL              base URL for links (default http://127.0.0.1:8765)
  PATIENCE_NOTIFY_EMAIL_TO         comma-separated approver emails (uses PATIENCE_SMTP_* for the server)
  PATIENCE_NOTIFY_SLACK_WEBHOOK    https://hooks.slack.com/services/...
  PATIENCE_NOTIFY_WEBHOOK_URL      any HTTPS endpoint; JSON body, X-Patience-Signature HMAC if
                                   PATIENCE_WEBHOOK_SECRET is set
The audit log records that an alert went out, never the link tokens.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from typing import Optional
from urllib.parse import urlparse
import audit
import links
import previews
from executors.base import live_mode

TIMEOUT = 5


def channels() -> list:
    out = []
    if os.environ.get("PATIENCE_NOTIFY_EMAIL_TO") and os.environ.get("PATIENCE_SMTP_HOST") \
            and os.environ.get("PATIENCE_SMTP_FROM"):
        out.append("email")
    if os.environ.get("PATIENCE_NOTIFY_SLACK_WEBHOOK"):
        out.append("slack")
    if os.environ.get("PATIENCE_NOTIFY_WEBHOOK_URL"):
        out.append("webhook")
    return out


def _base() -> str:
    return os.environ.get("PATIENCE_PUBLIC_URL", "http://127.0.0.1:8765").rstrip("/")


def _https_ok(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"))


# transports (patched in tests)
def _post(url: str, body: bytes, headers: dict) -> int:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # nosec - URL is operator config, https enforced
        return r.status


def _smtp_send(msg: EmailMessage) -> None:
    host, port = os.environ["PATIENCE_SMTP_HOST"], int(os.environ.get("PATIENCE_SMTP_PORT", "587"))
    ctx = ssl.create_default_context()
    if os.environ.get("PATIENCE_SMTP_SSL") == "1":
        s = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=ctx)
    else:
        s = smtplib.SMTP(host, port, timeout=TIMEOUT)
        s.starttls(context=ctx)
    with s:
        if os.environ.get("PATIENCE_SMTP_USER"):
            s.login(os.environ["PATIENCE_SMTP_USER"], os.environ.get("PATIENCE_SMTP_PASSWORD", ""))
        s.send_message(msg)


def compose(req: dict, request_hash: str) -> dict:
    pv = req.get("preview") or previews.preview(req.get("tool"), req.get("args"), req.get("action"))
    ln = {}
    if links.enabled():
        for a in ("approve", "deny"):
            ln[a] = f"{_base()}/l/{links.make(req['request_id'], a, request_hash)}"
    text = (f"PATIENCE needs your approval ({req.get('identity')}):\n{previews.as_text(pv)}\n"
            f"Why: {req.get('reason')}\nRisk: {', '.join(req.get('risk_categories') or []) or 'n/a'}\n")
    if ln:
        text += (f"\nApprove: {ln['approve']}\nDeny:    {ln['deny']}\n"
                 f"(Links expire in {links.ttl() // 60} min, work once, and need your approver login or PIN.)\n")
    else:
        text += "\nReview it on the dashboard.\n"
    return {"text": text, "links": ln, "preview": pv, "subject": f"[PATIENCE] Approval needed: {pv['summary'][:80]}"}


def alert(req: dict, request_hash: str) -> list:
    chans = channels()
    if not chans:
        return []
    msg = compose(req, request_hash)
    live, results = live_mode(), []
    for ch in chans:
        res = {"channel": ch, "dry_run": not live, "ok": True}
        try:
            if ch == "email":
                m = EmailMessage()
                m["From"] = os.environ["PATIENCE_SMTP_FROM"]
                to = [x.strip() for x in os.environ["PATIENCE_NOTIFY_EMAIL_TO"].split(",") if x.strip()]
                if any("\n" in x or "\r" in x for x in to):
                    raise ValueError("bad recipient")
                m["To"] = ", ".join(to)
                m["Subject"] = msg["subject"].replace("\n", " ").replace("\r", " ")
                m.set_content(msg["text"])
                if live:
                    _smtp_send(m)
            elif ch == "slack":
                url = os.environ["PATIENCE_NOTIFY_SLACK_WEBHOOK"]
                if not urlparse(url).scheme == "https":
                    raise ValueError("Slack webhook must be https")
                blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": msg["text"][:2900]}}]
                if msg["links"]:
                    blocks.append({"type": "actions", "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "Review & approve"},
                         "url": msg["links"]["approve"], "style": "primary"},
                        {"type": "button", "text": {"type": "plain_text", "text": "Review & deny"},
                         "url": msg["links"]["deny"], "style": "danger"}]})
                if live:
                    _post(url, json.dumps({"text": msg["subject"], "blocks": blocks}).encode(),
                          {"Content-Type": "application/json"})
            elif ch == "webhook":
                url = os.environ["PATIENCE_NOTIFY_WEBHOOK_URL"]
                if not _https_ok(url):
                    raise ValueError("webhook must be https")
                body = json.dumps({"event": "approval_needed", "request_id": req["request_id"],
                                   "preview": msg["preview"], "reason": req.get("reason"),
                                   "links": msg["links"]}, default=str).encode()
                h = {"Content-Type": "application/json"}
                sec = os.environ.get("PATIENCE_WEBHOOK_SECRET")
                if sec:
                    h["X-Patience-Signature"] = "sha256=" + hmac.new(sec.encode(), body, hashlib.sha256).hexdigest()
                if live:
                    _post(url, body, h)
        except Exception as e:  # alerts are best-effort; never leak URLs/credentials
            res.update(ok=False, error=type(e).__name__)
        results.append(res)
    audit.append("notify", "patience", request_id=req["request_id"],
                 results=[{k: r[k] for k in r if k != "links"} for r in results])
    return results
