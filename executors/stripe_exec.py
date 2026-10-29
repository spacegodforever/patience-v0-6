"""Stripe executor: refunds and charges via the Stripe REST API.

Env:
  PATIENCE_STRIPE_API_KEY (or STRIPE_API_KEY)  secret or restricted key.
  PATIENCE_STRIPE_ALLOW_LIVE=1                 required before a sk_live_/rk_live_ key is used.
Test-mode keys only by default. Dry-run unless PATIENCE_EXECUTE_LIVE=1.
The gateway idempotency key is passed to Stripe as Idempotency-Key, so a retried
call can't refund or charge twice.

Tools:
  refund (aliases issue_refund, create_refund): payment_intent | charge, amount (major units) or
      amount_cents (omit for a full refund), reason (duplicate|fraudulent|requested_by_customer)
  charge (alias create_charge): amount | amount_cents, currency (default usd), customer, payment_method,
      description. Creates and confirms an off-session PaymentIntent.
"""
from __future__ import annotations
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation
from .base import Executor, ExecutionError, live_mode

API = "https://api.stripe.com"
REFUND_TOOLS = {"refund", "issue_refund", "create_refund"}
CHARGE_TOOLS = {"charge", "create_charge"}
REFUND_REASONS = {"duplicate", "fraudulent", "requested_by_customer"}


def _key() -> str:
    return os.environ.get("PATIENCE_STRIPE_API_KEY") or os.environ.get("STRIPE_API_KEY") or ""


def key_mode(key: str) -> str:
    if key.startswith(("sk_test_", "rk_test_")):
        return "test"
    if key.startswith(("sk_live_", "rk_live_")):
        return "live"
    return "unknown"


def _cents(args: dict) -> int | None:
    if args.get("amount_cents") is not None:
        v = args["amount_cents"]
        if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
            raise ExecutionError("amount_cents must be a positive integer.")
        return v
    if args.get("amount") is None:
        return None
    try:
        d = Decimal(str(args["amount"]).replace(",", "").lstrip("$"))
    except InvalidOperation:
        raise ExecutionError("amount must be a number.")
    if d <= 0 or d != d.quantize(Decimal("0.01")):
        raise ExecutionError("amount must be positive with at most 2 decimals.")
    return int(d * 100)


class StripeExecutor(Executor):
    name = "stripe"
    TOOLS = REFUND_TOOLS | CHARGE_TOOLS

    @staticmethod
    def configured() -> bool:
        return bool(_key())

    # transport (patched in tests; no network calls in the suite)
    @staticmethod
    def _request(path: str, form: dict, headers: dict) -> dict:
        req = urllib.request.Request(API + path, data=urllib.parse.urlencode(form).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read()).get("error", {})
            except Exception:
                err = {}
            raise ExecutionError(f"Stripe error {e.code}: {err.get('code') or err.get('type') or 'request failed'}"
                                 f" - {str(err.get('message', ''))[:200]}")
        except urllib.error.URLError as e:
            raise ExecutionError(f"Stripe unreachable: {type(e.reason).__name__}")

    def _build(self, tool: str, args: dict) -> tuple[str, dict, str]:
        if tool in REFUND_TOOLS:
            form = {}
            target = args.get("payment_intent") or args.get("charge")
            if not target:
                raise ExecutionError("refund needs payment_intent or charge.")
            form["payment_intent" if args.get("payment_intent") else "charge"] = str(target)
            c = _cents(args)
            if c is not None:
                form["amount"] = c
            if args.get("reason"):
                if args["reason"] not in REFUND_REASONS:
                    raise ExecutionError(f"reason must be one of {sorted(REFUND_REASONS)}.")
                form["reason"] = args["reason"]
            desc = f"Refund {'$%.2f' % (c / 100) if c else 'in full'} on {target}"
            return "/v1/refunds", form, desc
        c = _cents(args)
        if c is None:
            raise ExecutionError("charge needs amount or amount_cents.")
        if not args.get("customer") or not args.get("payment_method"):
            raise ExecutionError("charge needs customer and payment_method.")
        cur = str(args.get("currency", "usd")).lower()
        if len(cur) != 3 or not cur.isalpha():
            raise ExecutionError("currency must be a 3-letter code.")
        form = {"amount": c, "currency": cur, "customer": str(args["customer"]),
                "payment_method": str(args["payment_method"]), "confirm": "true", "off_session": "true"}
        if args.get("description"):
            form["description"] = str(args["description"])[:500]
        return "/v1/payment_intents", form, f"Charge {c / 100:.2f} {cur.upper()} to {args['customer']}"

    def run(self, tool: str, args: dict, meta: dict) -> dict:
        tool = tool.lower()
        key = _key()
        mode = key_mode(key)
        if mode == "live" and os.environ.get("PATIENCE_STRIPE_ALLOW_LIVE") != "1":
            raise ExecutionError("Refusing to use a live Stripe key; set PATIENCE_STRIPE_ALLOW_LIVE=1 to allow it.")
        if mode == "unknown":
            raise ExecutionError("Stripe key must be a sk_test_/rk_test_ key (or a live key with the allow flag).")
        path, form, desc = self._build(tool, args)
        idem = f"patience-{meta['idempotency_key']}"
        form["metadata[patience_request_id]"] = meta.get("request_id") or ""
        if not live_mode():
            return {"dry_run": True, "executor": self.name, "stripe_mode": mode, "would": desc,
                    "endpoint": path, "idempotency_key": idem}
        obj = self._request(path, form, {"Authorization": f"Bearer {key}", "Idempotency-Key": idem,
                                         "Content-Type": "application/x-www-form-urlencoded"})
        return {"dry_run": False, "executor": self.name, "stripe_mode": mode, "did": desc,
                "stripe_id": obj.get("id"), "stripe_status": obj.get("status"), "amount": obj.get("amount"),
                "currency": obj.get("currency"), "idempotency_key": idem}
