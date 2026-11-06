"""PATIENCE HTTP API (v0.6): ask PATIENCE before you act.

Run:  python api.py            (127.0.0.1:8765)
Env:  PATIENCE_AGENTS          agents.yaml with hashed per-agent keys (see identity.py). When present,
                               every /v1 call needs "Authorization: Bearer <agent key>"; the requester
                               and budgets are derived from that key.
      PATIENCE_API_TOKEN       legacy single shared token (identity "default") when no agents file exists
      PATIENCE_APPROVERS       approvers.yaml (see approvers.py). /approve, /deny and /v1/admin/* take
                               HTTP Basic auth with a per-approver account; every decision records
                               approver, time and reason in the request, state and audit log.
      PATIENCE_LEGACY_APPROVER_TOKEN=1 + PATIENCE_APPROVER_TOKEN
                               legacy shared "X-Approver-Token" (recorded as approver "legacy-token").
                               Off unless explicitly enabled.
      PATIENCE_STATE_PATH      default patience_state.json (same file the dashboard uses)
      PATIENCE_API_HOST / PATIENCE_API_PORT  default 127.0.0.1 / 8765
"""
from __future__ import annotations
import envfile
envfile.load()
import copy
import hashlib
import hmac
import contextlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional
import base64
from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator
from engine import Patience, second_opinion_risk
import risk_policy
import identity
import executors
import approvers
import audit
import decisions
import previews
import links
import notify
import org_learning
import html as _html
from urllib.parse import parse_qs
from fastapi import Request
from fastapi.responses import HTMLResponse
from models import now_iso

VERSION = "0.6"
@contextlib.asynccontextmanager
async def _lifespan(_app):
    _startup_reconcile()
    yield


app = FastAPI(title="PATIENCE", version=VERSION, lifespan=_lifespan)


def _state_path() -> str:
    return os.environ.get("PATIENCE_STATE_PATH", "patience_state.json")


def _engine() -> Patience:
    return Patience(_state_path())


def _eq(a: Optional[str], b: str) -> bool:
    return a is not None and hmac.compare_digest(a.encode(), b.encode())


def require_caller(authorization: Optional[str] = Header(None)) -> dict:
    """Authenticate the caller and return its identity. Never trusts a body field."""
    bearer = authorization[7:] if authorization and authorization.startswith("Bearer ") else None
    if identity.agent_mode():
        who = identity.resolve(bearer)
        if not who:
            raise HTTPException(401, "Missing or unknown agent API key.")
        return {**who, "mode": "agent"}
    token = os.environ.get("PATIENCE_API_TOKEN")
    if token:
        if not bearer or not _eq(bearer, token):
            raise HTTPException(401, "Missing or invalid bearer token.")
        return {"id": "default", "mode": "token"}
    return {"id": "local-dev", "mode": "dev"}


def _basic(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Basic "):
        return None
    try:
        user, _, pw = base64.b64decode(authorization[6:]).decode().partition(":")
        return user, pw
    except Exception:
        return None


def legacy_token_enabled() -> bool:
    return os.environ.get("PATIENCE_LEGACY_APPROVER_TOKEN") == "1" and bool(os.environ.get("PATIENCE_APPROVER_TOKEN"))


def require_approver(authorization: Optional[str] = Header(None),
                     x_approver_token: Optional[str] = Header(None)) -> dict:
    """A human approver: per-user HTTP Basic (approvers.yaml). Agent bearer keys never qualify."""
    creds = _basic(authorization)
    if creds:
        who = approvers.verify_password(*creds)
        if who:
            return who
        audit.append("auth.failed", creds[0][:100], channel="api")
        raise HTTPException(403, "Invalid approver credentials.")
    if x_approver_token is not None and legacy_token_enabled():
        if _eq(x_approver_token, os.environ["PATIENCE_APPROVER_TOKEN"]):
            return {"user": "legacy-token", "role": "approver", "legacy": True}
        raise HTTPException(403, "Invalid approver token.")
    raise HTTPException(403, "Approver login required (HTTP Basic with an approvers.yaml account).")


def require_admin(who: dict = Depends(require_approver)) -> dict:
    if who.get("role") != "admin":
        raise HTTPException(403, "Admin role required.")
    return who


class CheckIn(BaseModel):
    """Either a free-text `action`, or a structured `tool` + `args` (preferred), or both."""
    action: Optional[str] = Field(None, min_length=1, max_length=4000)
    tool: Optional[str] = Field(None, min_length=1, max_length=100)
    args: Optional[Dict[str, Any]] = None
    context: Optional[str] = Field(None, max_length=8000)
    requester: Optional[str] = Field(None, max_length=200)
    metadata: Optional[Dict[str, Any]] = None
    # L0 org-decision learning (advisory tagging; does not bypass the gate)
    situation_kind: Optional[str] = Field(None, max_length=40)
    domain: Optional[str] = Field(None, max_length=80)
    options: Optional[List[Dict[str, Any]]] = None

    @model_validator(mode="after")
    def _need_one(self):
        if not self.action and not self.tool:
            raise ValueError("Send either 'action' (text) or 'tool' (+ 'args').")
        if len(json.dumps(self.args or {}, default=str)) > 8000:
            raise ValueError("args too large")
        if self.options is not None and len(json.dumps(self.options, default=str)) > 16000:
            raise ValueError("options too large")
        return self


def _describe(body: CheckIn) -> str:
    if body.action:
        return body.action
    return f"{body.tool}({json.dumps(body.args or {}, sort_keys=True, default=str)[:400]})"


def _merge(*parts):
    cats, cons, irr, reasons = [], .25, False, []
    for p in parts:
        if not p:
            continue
        for c in p.get("categories", []):
            if c not in cats:
                cats.append(c)
        if p.get("categories"):
            cons = max(cons, float(p.get("consequence", .75)))
            irr = irr or bool(p.get("irreversible"))
        reasons += p.get("reasons", [])
    return {"categories": cats, "consequence": cons, "irreversible": irr, "reasons": reasons}


def args_hash(tool: str, args: Optional[dict]) -> str:
    """Approval binding: sha256 of the canonical tool + args."""
    canon = json.dumps({"tool": (tool or "").strip().lower(), "args": args or {}},
                       sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def request_hash(req: dict) -> str:
    """Binds signed links to exactly what the approver saw: the request id, action text and args."""
    canon = json.dumps({"id": req["request_id"], "action": req.get("action"), "tool": req.get("tool"),
                        "args_hash": req.get("args_hash")}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def _status(state, req) -> str:
    key = req["approval_key"]
    es = (req.get("execution") or {}).get("status")
    if es == "executed":
        return "executed"
    if es == "needs_review":
        return "needs_review"
    if not req["requires_authorization"]:
        return "allowed"
    if key in state.denied_actions:
        return "denied"
    if key in state.authorized_actions:
        return "approved"
    return "pending"


def _map(decision: str, allowed: bool, duplicate: bool) -> str:
    if decision == "research":
        return "clarify"         # evidence is thin: caller should add context or a human must approve
    if allowed:
        return "allow"
    if duplicate:
        return "defer"           # an identical request is already waiting for a human
    return "needs_approval"


@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION, "time": now_iso(),
            "auth": "agent_keys" if identity.agent_mode() else (
                "shared_token" if os.environ.get("PATIENCE_API_TOKEN") else "dev_open")}


def _check_impl(body: CheckIn, caller: dict) -> dict:
    if body.requester and caller["mode"] == "agent" and body.requester != caller["id"]:
        raise HTTPException(400, "requester is derived from your API key; do not send a different one.")
    who = caller["id"]  # caller-supplied requester is never used for identity or budgets
    p = _engine()
    action_desc = _describe(body)
    text = action_desc if not body.context else f"{action_desc}\nContext: {body.context}"
    industry = caller.get("industry") or (body.metadata or {}).get("industry")
    tags = [f"industry:{industry}"] if isinstance(industry, str) and industry else []
    tool_risk, usage = None, None
    tool_name = (body.tool or "").strip().lower()
    if body.tool:
        tags.append("tool_call")
        tool_risk = risk_policy.score_tool(body.tool, body.args or {})
        usage = tool_risk["usage"]
        # free text sent alongside a tool call is still scored (fail-safe union)
        if body.action or body.context:
            t = risk_policy.classify(" ".join(x for x in (body.action, body.context) if x), tags)
            tool_risk = _merge(tool_risk, {**t, "reasons": []})
    rules_cats = (tool_risk or {}).get("categories") if body.tool else risk_policy.classify(text, tags)["categories"]
    llm = second_opinion_risk(text, tags, rules_cats)  # outside the lock; None without a key
    with p.memory_store.locked():
        p.refresh()
        extra = _merge(tool_risk, llm)
        pending_same = [r for r in p.state.requests.values()
                        if r.get("action") == action_desc and r.get("identity", who) == who
                        and _status(p.state, r) == "pending"]
        out = p._cycle_unlocked(text, source=f"api:{who}", reliability=.9, tags=tags, extra_risk=extra,
                                identity=who, tool=tool_name or None, usage=usage)
        d, v, a = out["decision"], out["verification"], out["assessment"]
        rid = str(uuid.uuid4())
        decision = _map(d["action"], v["verified"], bool(pending_same))
        if decision == "defer":
            # don't stack duplicate approvals; point the caller at the existing one
            p.state.blocked_actions = [x for x in p.state.blocked_actions if x != v["approval_key"]]
            p.state.pending_usage.pop(v["approval_key"], None)
            v["approval_key"] = pending_same[0]["approval_key"]
        cats = a.get("risk_categories", [])
        req = {
            "request_id": rid, "action": action_desc, "context": body.context,
            "tool": tool_name or None, "args": copy.deepcopy(body.args) if body.tool else None,
            "args_hash": args_hash(tool_name, body.args) if body.tool else None,
            "usage": usage, "identity": who, "requester": who, "metadata": body.metadata or {},
            "decision": decision, "engine_action": d["action"], "reason": d["reason"],
            "risk_categories": cats, "irreversible": not d["reversible"],
            "flags": sorted(set(cats) & {"injection", "budget_exceeded", "llm_disagreement"}),
            "details": extra["reasons"] + v.get("budget_reasons", [])[len(extra["reasons"]):] + (
                [f"LLM error: {llm['second_opinion']['error']}"]
                if llm and llm.get("second_opinion", {}).get("error") else []),
            "confidence": d["confidence"], "approval_key": v["approval_key"],
            "preview": previews.preview(tool_name or None, body.args if body.tool else None,
                                        " ".join(x for x in (body.action,) if x) or None, cats),
            "requires_authorization": d["requires_authorization"] or not v["verified"],
            "created_at": now_iso(),
        }
        if decision == "clarify":
            req["requires_authorization"] = True
            req["approval_key"] = p.governance.approval_key(
                type("D", (), {"action": "clarify"})(), action_desc, out["observation"]["id"])
        if decision == "defer":
            req["reason"] = f"Same action already awaiting approval (request {pending_same[0]['request_id']})."
        # L0: tag unforeseen org decisions; persist episode + options (advisory only).
        opts = org_learning.normalize_options(body.options)
        domain = (body.domain or (body.metadata or {}).get("domain") or None)
        if isinstance(domain, str):
            domain = domain.strip()[:80] or None
        else:
            domain = None
        cons = float(a.get("consequence", 0) or 0)
        if org_learning.should_tag(situation_kind=body.situation_kind, options=opts, consequence=cons):
            novelty = org_learning.novelty_for_domain(p.state.episodes, domain)
            ep = org_learning.build_episode(
                request_id=rid, action=action_desc, domain=domain, options=opts,
                consequence=cons, risk_categories=cats, decision=decision,
                approval_key=req["approval_key"], identity=who, novelty=novelty,
                votes=out.get("model_votes"), assessment=a)
            p.state.episodes.append(ep)
            req["situation_kind"] = org_learning.ORG_KIND
            req["domain"] = domain
            req["options"] = opts
            req["episode_id"] = ep["id"]
            req["novelty"] = ep["novelty"]
            audit.append("org_decision.tagged", who, request_id=rid, episode_id=ep["id"],
                         domain=domain, novelty=ep["novelty"], n_options=len(opts),
                         consequence=cons, gate_decision=decision)
        else:
            req["situation_kind"] = org_learning.ROUTINE_KIND
        p.state.requests[rid] = req
        p.memory_store.save(p.state)
    if decision in ("needs_approval", "clarify"):
        req["alerts"] = notify.alert(req, request_hash(req))  # network I/O outside the state lock
    audit.append("check", who, request_id=rid, decision=decision, tool=req["tool"], args_hash=req["args_hash"],
                 action=action_desc[:300], risk_categories=cats, flags=req["flags"])
    return req


@app.post("/v1/check")
def check(body: CheckIn, caller: dict = Depends(require_caller)):
    req = _check_impl(body, caller)
    keys = ["decision", "reason", "risk_categories", "irreversible", "flags", "details",
            "confidence", "request_id", "approval_key", "preview", "situation_kind"]
    if req.get("situation_kind") == org_learning.ORG_KIND:
        keys += ["domain", "options", "episode_id", "novelty"]
    return {k: req[k] for k in keys if k in req}


def _get(p: Patience, rid: str, caller: Optional[dict] = None):
    req = p.state.requests.get(rid)
    # agents only see their own requests (no probing other agents' ids)
    if not req or (caller and caller["mode"] == "agent" and req.get("identity") != caller["id"]):
        raise HTTPException(404, "Unknown request_id.")
    return req


@app.get("/v1/requests/{rid}")
def status(rid: str, caller: dict = Depends(require_caller)):
    p = _engine()
    req = _get(p, rid, caller)
    return {"request_id": rid, "status": _status(p.state, req), "decision": req["decision"],
            "action": req["action"], "approval_key": req["approval_key"], "reason": req["reason"],
            "args_hash": req.get("args_hash"), "execution": req.get("execution"), "preview": req.get("preview"),
            "decided": req.get("decided"),
            "situation_kind": req.get("situation_kind"), "domain": req.get("domain"),
            "options": req.get("options"), "episode_id": req.get("episode_id"),
            "novelty": req.get("novelty")}


class DecideIn(BaseModel):
    reason: Optional[str] = Field(None, max_length=1000)


def decide_request(rid: str, approve: bool, who: dict, reason: str = "", via: str = "api",
                   expect_hash: Optional[str] = None) -> dict:
    p = _engine()
    req = _get(p, rid)
    if not req["requires_authorization"]:
        raise HTTPException(409, "This request was allowed and needs no approval.")
    if _status(p.state, req) != "pending":
        raise HTTPException(409, "Request already decided.")
    if expect_hash is not None and not hmac.compare_digest(expect_hash, request_hash(req)):
        raise HTTPException(409, "Request changed since the link was issued.")
    decisions.decide(p, req["approval_key"], approve, who, reason, via, request_id=rid)
    p.refresh()
    return {"request_id": rid, "status": _status(p.state, p.state.requests[rid]), "approver": who["user"]}


# Approvals are a human action: only an approver account (or the explicit legacy token), never an agent key.
@app.post("/v1/requests/{rid}/approve")
def approve(rid: str, body: Optional[DecideIn] = Body(None), who: dict = Depends(require_approver)):
    return decide_request(rid, True, who, (body.reason if body else "") or "")


@app.post("/v1/requests/{rid}/deny")
def deny(rid: str, body: Optional[DecideIn] = Body(None), who: dict = Depends(require_approver)):
    return decide_request(rid, False, who, (body.reason if body else "") or "")


# --------------------------------------------------------------------------
# Gateway mode: PATIENCE runs the tool itself with credentials agents never see.
class ExecuteIn(BaseModel):
    tool: str = Field(..., min_length=1, max_length=100)
    args: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(..., min_length=8, max_length=200)
    request_id: Optional[str] = None
    context: Optional[str] = Field(None, max_length=8000)


def _public_exec(rec: dict) -> dict:
    return {k: rec.get(k) for k in ("status", "request_id", "idempotency_key", "result", "error", "executed_at")}


@app.post("/v1/execute")
def execute(body: ExecuteIn, caller: dict = Depends(require_caller)):
    """Allowed calls run immediately. Otherwise returns 202 + request_id; after a human approves,
    call again with that request_id and the SAME tool+args (hash-bound) and a new or the same key.
    Each approval executes at most once; an idempotency key never runs twice."""
    if caller["mode"] != "agent":
        raise HTTPException(403, "Gateway execution requires per-agent API keys (agents.yaml).")
    tool = body.tool.strip().lower()
    h = args_hash(tool, body.args)
    ex = executors.get_executor(tool)
    if ex is None:
        raise HTTPException(501, f"No executor configured for '{tool}'. Executors are disabled until configured.")
    p = _engine()
    with p.memory_store.locked():
        p.refresh()
        prior = p.state.executions.get(body.idempotency_key)
        if prior:
            if prior["identity"] != caller["id"] or prior["args_hash"] != h:
                raise HTTPException(409, "Idempotency key already used for a different call.")
            if prior["status"] == "executing":
                raise HTTPException(409, "This call is already executing.")
            if prior["status"] == "needs_review":
                raise HTTPException(409, "This call was interrupted and needs human review; it will not be retried.")
            return {**_public_exec(prior), "replayed": True}  # same answer, NOT re-run
        if body.request_id:
            req = _get(p, body.request_id, caller)
            if not req.get("tool"):
                raise HTTPException(409, "That request was a text check; execute needs a tool request.")
            if req.get("args_hash") != h:
                raise HTTPException(409, "tool/args differ from the approved request; a new approval is required.")
            st = _status(p.state, req)
            if st == "executed" or (req.get("execution") or {}).get("status") in ("executing", "failed", "needs_review"):
                raise HTTPException(409, "This approval was already used (executed once). Submit a new request.")
            if st == "denied":
                raise HTTPException(403, "Request was denied.")
            if st not in ("allowed", "approved"):
                return JSONResponse(status_code=202, content={
                    "status": "pending_approval", "request_id": req["request_id"], "approval_key": req["approval_key"]})
    if not body.request_id:
        req = _check_impl(CheckIn(tool=tool, args=body.args, context=body.context), caller)
        if req["decision"] != "allow":
            return JSONResponse(status_code=202, content={
                "status": "pending_approval", "decision": req["decision"], "request_id": req["request_id"],
                "approval_key": req["approval_key"], "reason": req["reason"], "flags": req["flags"]})
    rid = req["request_id"]
    # claim (exactly once): mark executing under the lock before running anything
    with p.memory_store.locked():
        p.refresh()
        req = p.state.requests[rid]
        if body.idempotency_key in p.state.executions or (req.get("execution") or {}).get("status"):
            raise HTTPException(409, "Concurrent execution detected; not running twice.")
        approved_args = copy.deepcopy(req["args"])  # run exactly what was approved
        rec = {"status": "executing", "request_id": rid, "identity": caller["id"], "args_hash": h,
               "idempotency_key": body.idempotency_key, "tool": tool}
        rec["claimed_at"] = now_iso()
        p.state.executions[body.idempotency_key] = rec
        req["execution"] = {"status": "executing", "idempotency_key": body.idempotency_key,
                            "claimed_at": rec["claimed_at"]}
        p.memory_store.save(p.state)
    audit.append("execute.claimed", caller["id"], request_id=rid, tool=tool, args_hash=h,
                 idempotency_key=body.idempotency_key)
    try:
        result, error = ex.run(tool, approved_args, {"request_id": rid, "idempotency_key": body.idempotency_key,
                                                      "identity": caller["id"]}), None
    except executors.ExecutionError as e:
        result, error = None, str(e)
    except Exception as e:  # never echo arbitrary exception text (could carry secrets)
        result, error = None, f"executor error ({type(e).__name__})"
    with p.memory_store.locked():
        p.refresh()
        req = p.state.requests[rid]
        rec = p.state.executions[body.idempotency_key]
        if result is not None and result.get("dry_run"):
            # dry run consumes nothing: release the claim so the same approval can run live later
            del p.state.executions[body.idempotency_key]
            req.pop("execution", None)
            req["last_dry_run"] = {"at": now_iso(), "result": result}
            p.memory_store.save(p.state)
            return {"status": "dry_run", "request_id": rid, "result": result,
                    "note": "Set PATIENCE_EXECUTE_LIVE=1 to really run it."}
        rec.update({"status": "executed" if error is None else "failed", "result": result, "error": error,
                    "executed_at": now_iso()})
        req["execution"] = {"status": rec["status"], "idempotency_key": body.idempotency_key,
                            "executed_at": rec["executed_at"]}
        p.memory_store.save(p.state)
    audit.append("execute." + rec["status"], caller["id"], request_id=rid, tool=tool, args_hash=h,
                 idempotency_key=body.idempotency_key, error=error)
    if error:
        # at-most-once: a failed attempt is not retried automatically; submit a new request
        raise HTTPException(502, f"Execution failed: {error}")
    return _public_exec(rec)


# --------------------------------------------------------------------------
# Crash recovery (admin). Assumes ONE API process owns the state file (see README).
import reconcile as _reconcile


def _startup_reconcile():
    if os.environ.get("PATIENCE_RECONCILE_ON_STARTUP", "1") == "1":
        _reconcile.reconcile(_engine(), "startup")


class ReconcileIn(BaseModel):
    min_age_seconds: float = Field(300, ge=0)


@app.post("/v1/admin/reconcile")
def admin_reconcile(body: Optional[ReconcileIn] = Body(None), who: dict = Depends(require_admin)):
    """Flag executions stuck in 'executing' longer than min_age_seconds as needs_review. Never retries."""
    flagged = _reconcile.reconcile(_engine(), who["user"], (body or ReconcileIn()).min_age_seconds)
    return {"flagged": flagged}


class ResolveIn(BaseModel):
    outcome: str = Field(..., pattern="^(executed|failed)$")
    note: str = Field("", max_length=1000)


@app.post("/v1/admin/requests/{rid}/resolve")
def admin_resolve(rid: str, body: ResolveIn, who: dict = Depends(require_admin)):
    try:
        return _reconcile.resolve(_engine(), rid, body.outcome, who, body.note)
    except LookupError as e:
        raise HTTPException(409, str(e))


@app.get("/v1/admin/needs_review")
def admin_needs_review(who: dict = Depends(require_admin)):
    p = _engine()
    return {"requests": [{"request_id": r["request_id"], "tool": r.get("tool"), "execution": r.get("execution")}
                         for r in p.state.requests.values()
                         if (r.get("execution") or {}).get("status") == "needs_review"]}


# --------------------------------------------------------------------------
# One-tap approval landing page. GET only shows the preview (link scanners can't approve);
# POST needs the signed link AND an approver login (password) or approver PIN.
_SEC_HEADERS = {"Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
                "X-Content-Type-Options": "nosniff"}


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' "
                        f"content='width=device-width,initial-scale=1'><title>{_html.escape(title)}</title>"
                        "<style>body{font-family:system-ui;max-width:560px;margin:2em auto;padding:0 1em}"
                        "pre{white-space:pre-wrap;background:#f4f4f4;padding:1em}input,button{font-size:1.1em;"
                        "margin:.3em 0;width:100%;padding:.5em}</style></head><body>"
                        f"<h2>{_html.escape(title)}</h2>{body}</body></html>", status_code=status, headers=_SEC_HEADERS)


def _link_ctx(token: str):
    try:
        payload = links.parse(token)
    except links.LinkError as e:
        audit.append("link.rejected", None, reason=str(e))
        raise HTTPException(403, str(e))
    p = _engine()
    req = p.state.requests.get(payload["r"])
    if not req:
        raise HTTPException(404, "Unknown request.")
    if links.is_used(p.state, payload):
        audit.append("link.rejected", None, request_id=req["request_id"], reason="replayed")
        raise HTTPException(409, "This link was already used.")
    if not hmac.compare_digest(payload["h"], request_hash(req)):
        raise HTTPException(409, "The request changed after this link was sent; review it on the dashboard.")
    return payload, p, req


def _err_page(e: HTTPException) -> HTMLResponse:
    return _page("Link not usable", f"<p>{_html.escape(str(e.detail))}</p>", e.status_code)


@app.get("/l/{token}", response_class=HTMLResponse)
def link_landing(token: str):
    try:
        payload, p, req = _link_ctx(token)
    except HTTPException as e:
        return _err_page(e)
    st = _status(p.state, req)
    pv = previews.as_text(req.get("preview") or {})
    verb = "Approve" if payload["a"] == "approve" else "Deny"
    if st != "pending":
        return _page("Already decided", f"<p>This request is <b>{_html.escape(st)}</b>.</p><pre>{_html.escape(pv)}</pre>")
    return _page(f"{verb} this action?", f"""
<p>Requested by <b>{_html.escape(str(req.get('identity')))}</b> at {_html.escape(req.get('created_at', ''))}</p>
<pre>{_html.escape(pv)}</pre>
<p>Why it needs you: {_html.escape(req.get('reason') or '')}</p>
<form method="post">
<input name="user" placeholder="Approver username" autocomplete="username" required>
<input name="password" type="password" placeholder="Password" autocomplete="current-password">
<input name="pin" type="password" inputmode="numeric" placeholder="...or your approver PIN">
<input name="reason" placeholder="Reason (optional)" maxlength="500">
<button type="submit">{verb}</button>
</form>""")


@app.post("/l/{token}", response_class=HTMLResponse)
async def link_submit(token: str, request: Request):
    raw = await request.body()
    if len(raw) > 4096:
        return _page("Too large", "", 413)
    form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
    try:
        payload, p, req = _link_ctx(token)
    except HTTPException as e:
        return _err_page(e)
    user = form.get("user", "")[:100]
    who = approvers.verify_password(user, form["password"]) if form.get("password") else (
        approvers.verify_pin(user, form["pin"]) if form.get("pin") else None)
    if not who:
        audit.append("auth.failed", user, channel="link", request_id=req["request_id"])
        return _page("Not authorized", "<p>Wrong username, password or PIN.</p>", 403)
    with p.memory_store.locked():  # consume first: a link works once even if the decision then fails
        p.refresh()
        try:
            links.consume(p, payload)
        except links.LinkError as e:
            return _page("Link not usable", f"<p>{_html.escape(str(e))}</p>", 409)
        p.memory_store.save(p.state)
    try:
        out = decide_request(req["request_id"], payload["a"] == "approve", who, form.get("reason", ""),
                             via="link", expect_hash=payload["h"])
    except HTTPException as e:
        return _err_page(e)
    return _page("Done", f"<p>Request <b>{_html.escape(out['status'])}</b> by {_html.escape(who['user'])}.</p>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("PATIENCE_API_HOST", "127.0.0.1"),
                port=int(os.environ.get("PATIENCE_API_PORT", "8765")))
