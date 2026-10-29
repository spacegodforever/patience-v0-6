"""Human-readable previews of what an action will do. Shown in /v1/check, alerts and the dashboard.

preview(tool, args, action_text, categories) ->
  {"summary": "Refund $5,000.00 (order A1)", "lines": [...], "recipients": n|None, "recipient_sample": [...],
   "message_sample": str|None, "amount_total": float|None, "currency": str, "records_affected": n|None}
Text is truncated and control characters are stripped; previews are display-only and never
used to decide anything.
"""
from __future__ import annotations
import re
from typing import Iterable, Optional
import risk_policy

_MSG_KEYS = ("body", "message", "text", "content", "html")
_SUBJ_KEYS = ("subject", "title")
_REC_KEYS = ("record_ids", "ids", "records", "rows", "customer_ids")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(s, n=160) -> str:
    s = _CTRL.sub(" ", str(s)).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _money(x: float, cur: str) -> str:
    sym = {"usd": "$", "eur": "€", "gbp": "£"}.get(cur.lower(), "")
    return f"{sym}{x:,.2f}" + ("" if sym else f" {cur.upper()}")


def preview(tool: Optional[str], args: Optional[dict], action_text: Optional[str] = None,
            categories: Iterable[str] = ()) -> dict:
    args = args or {}
    out = {"summary": "", "lines": [], "recipients": None, "recipient_sample": [], "message_sample": None,
           "amount_total": None, "currency": str(args.get("currency") or "usd").lower()[:3],
           "records_affected": None}
    lines = out["lines"]
    if tool:
        tool = tool.strip().lower()
        usage = risk_policy.tool_usage(tool, args)
        spec = risk_policy.get_policy().tools.get(tool, {}) or {}
        rk = spec.get("recipients_arg")
        if not (rk and args.get(rk) is not None):
            rk = next((k for k in ("recipients", "to") if args.get(k) is not None), None)
        if rk and args.get(rk) is not None:
            r = args[rk]
            lst = r if isinstance(r, (list, tuple)) else [x for x in re.split(r"[,;\s]+", str(r)) if x]
            out["recipients"] = max(usage.get("recipients") or 0, len(lst))
            out["recipient_sample"] = [_clean(x, 60) for x in list(lst)[:3]]
            more = out["recipients"] - len(out["recipient_sample"])
            lines.append(f"Recipients: {out['recipients']} ({', '.join(out['recipient_sample'])}"
                         f"{f' +{more} more' if more > 0 else ''})")
        for k in _SUBJ_KEYS:
            if args.get(k):
                lines.append(f"Subject: {_clean(args[k], 120)}")
                break
        for k in _MSG_KEYS:
            if args.get(k):
                out["message_sample"] = _clean(args[k], 200)
                lines.append(f"Message: \"{out['message_sample']}\"")
                break
        if "amount_total" in usage:
            out["amount_total"] = float(usage["amount_total"])
            cnt = usage.get("count", 1)
            lines.append(f"Amount: {_money(out['amount_total'], out['currency'])}"
                         + (f" ({cnt:g} × {_money(out['amount_total'] / cnt, out['currency'])})" if cnt > 1 else ""))
        for k in _REC_KEYS:
            if isinstance(args.get(k), (list, tuple)):
                out["records_affected"] = len(args[k])
                break
        if out["records_affected"] is None and tool.startswith(("delete", "update", "archive")):
            out["records_affected"] = usage.get("count", 1) if "count" in args else None
        if out["records_affected"] is not None:
            lines.append(f"Records affected: {out['records_affected']}")
        elif args.get("where") or args.get("filter"):
            lines.append(f"Records affected: all matching {_clean(args.get('where') or args.get('filter'), 80)}"
                         " (count unknown)")
        ref = next((args[k] for k in ("order", "order_id", "charge", "payment_intent", "customer") if args.get(k)), None)
        verb = tool.replace("_", " ")
        head = verb.capitalize()
        if out["amount_total"] is not None:
            head += f" {_money(out['amount_total'], out['currency'])}"
        if out["recipients"] is not None:
            head += f" to {out['recipients']} recipient{'s' if out['recipients'] != 1 else ''}"
        if out["records_affected"] is not None:
            head += f" affecting {out['records_affected']} record{'s' if out['records_affected'] != 1 else ''}"
        if ref:
            head += f" ({_clean(ref, 40)})"
        out["summary"] = head
    if action_text:
        cats = set(categories)
        u = risk_policy.text_usage(action_text, cats)
        if not tool:
            out["summary"] = _clean(action_text, 160)
            if "amount_total" in u:
                out["amount_total"] = u["amount_total"]
                lines.append(f"Amount mentioned: {_money(u['amount_total'], out['currency'])}")
            if "recipients" in u and cats & {"communication", "mass_communication"}:
                out["recipients"] = u["recipients"]
                lines.append(f"Recipients (estimated): {u['recipients']}")
        lines.append(f"Request text: \"{_clean(action_text, 200)}\"")
    return out


def as_text(pv: dict) -> str:
    return "\n".join([pv.get("summary") or ""] + [f"  • {l}" for l in pv.get("lines", [])])
