# PATIENCE v0.6 — ask before acting

PATIENCE is a gate between AI agents and risky actions. Agents ask `/v1/check` (or use the MCP tools). Safe actions pass. Risky ones wait for a named human, who gets an alert with a plain-English preview and one-tap approve/deny links. Every decision goes into a tamper-evident audit log.

## 5-minute quickstart

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
make install                                           # pip install -r requirements.txt
make init        # = python patience_cli.py init --pin --agent my-agent
                 #   creates the admin approver (asks for a password), a PIN for one-tap links,
                 #   an agent API key (shown once), policy.yaml and a .env with a fresh link secret
make run         # API :8765, worker, dashboard :8501 (all on 127.0.0.1)
```

Open http://127.0.0.1:8501 and log in as your admin. Then ask PATIENCE as the agent:

```bash
curl -s localhost:8765/v1/check -H "Authorization: Bearer $AGENT_KEY" -H 'Content-Type: application/json' \
  -d '{"tool":"refund","args":{"amount":5000,"order":"A1"}}'
# -> {"decision":"needs_approval","preview":{"summary":"Refund $5,000.00 (A1)",...},"request_id":"..."}
```

The request appears in **Pending queue**. Approve or deny it there with a reason, from the API (HTTP Basic as an approver) or from the alert link.

Docker: `cp .env.example .env` (set `PATIENCE_LINK_SECRET`), then `docker compose run --rm api python patience_cli.py init --generate-password --pin --agent my-agent` and `docker compose up --build`. This runs three services: api, dashboard and worker, sharing the `/data` volume and bound to 127.0.0.1.

Nothing real is sent, refunded or charged unless `PATIENCE_EXECUTE_LIVE=1`.

## What's new in v0.6

| Feature | How |
|---|---|
| **Per-approver accounts** | `approvers.yaml` (scrypt-hashed passwords and PINs, role `approver` or `admin`, chmod 600). Manage it with `patience add-approver NAME [--role admin] [--pin]` or `python approvers.py add/set-pin/disable/list`. The API uses HTTP Basic and the dashboard has per-user login. Every approve or deny records approver, time (UTC), reason and channel (`api`/`dashboard`/`link`). Five bad logins lock the account for 5 minutes. The old shared secrets only work with `PATIENCE_LEGACY_APPROVER_TOKEN=1` / `PATIENCE_LEGACY_DASHBOARD_PASSWORD=1` and are recorded as `legacy-token`/`legacy-dashboard`. |
| **Tamper-evident audit log** | `patience_audit.jsonl` is append-only. Each record carries the SHA-256 of the previous one, and the newest hash is also kept in `.head`, so edits, deletions, reordering and truncation are all detected. Check it with `python audit.py verify` (exit 1 if tampered), `python audit.py tail`, or `patience verify-audit`. The dashboard sidebar shows the status. |
| **Alerts + one-tap approval** | When a check needs approval, PATIENCE alerts through every configured channel: SMTP (`PATIENCE_NOTIFY_EMAIL_TO` + `PATIENCE_SMTP_*`), a Slack incoming webhook (`PATIENCE_NOTIFY_SLACK_WEBHOOK`) or a generic HTTPS webhook (`PATIENCE_NOTIFY_WEBHOOK_URL`, HMAC-signed with `PATIENCE_WEBHOOK_SECRET`). Alerts include the preview and approve/deny links that are HMAC-signed (`PATIENCE_LINK_SECRET`), expire after 15 minutes (`PATIENCE_LINK_TTL_SECONDS`), work once, and are bound to the request hash. Opening a link only shows the preview. Acting on it also needs the approver's username plus password or PIN. Alerts are dry-run unless live. Link tokens are never written to the audit log. |
| **Action previews** | Every check returns `preview`: summary, recipient count and sample, message sample, amount total, records affected. The same preview appears in alerts, on the landing page and in the dashboard queue. |
| **Stripe executor** | `refund` / `charge` via the Stripe API with `PATIENCE_STRIPE_API_KEY`. Test keys only: `sk_live_`/`rk_live_` keys are refused unless `PATIENCE_STRIPE_ALLOW_LIVE=1`. The gateway idempotency key is sent as Stripe's `Idempotency-Key`. Dry-run unless live. |
| **MCP server** | `patience_mcp.py` (official `mcp` SDK, stdio) exposes `check_action`, `execute_action` and `request_status`. It is a client of the HTTP API, so keys, budgets, approvals and audit all apply. |
| **Dashboard** | Tabs: Overview (metrics and charts over time, holds by risk category), Pending queue (previews, approve or deny with a reason), Audit log (search and filter), Policy (admins only; YAML is validated and sanity-checked before saving, saved atomically with a `.bak`, and audited with a diff), and Command (the original view). |
| **Crash recovery** | Requests stuck in `executing` become `needs_review` on API startup (and via the worker after `PATIENCE_STUCK_SECONDS`). They are never retried automatically. Admins use `POST /v1/admin/reconcile`, `GET /v1/admin/needs_review` and `POST /v1/admin/requests/{id}/resolve {"outcome":"executed"\|"failed"}`. |
| **Packaging** | `Dockerfile` (non-root), `docker-compose.yml` (api + dashboard + worker), `.env.example`, `Makefile`, `pyproject.toml` (`patience`, `patience-mcp` entry points), `scripts/patience`. |

### MCP config (Claude Desktop / Cursor / any MCP client)

```json
{
  "mcpServers": {
    "patience": {
      "command": "python",
      "args": ["/path/to/patience_integrated/patience_mcp.py"],
      "env": {"PATIENCE_URL": "http://127.0.0.1:8765", "PATIENCE_AGENT_KEY": "pk_..."}
    }
  }
}
```

The API must be running. Tell the agent: "Call `check_action` before any action with side effects. Proceed only on `allow`, or after `request_status` says `approved`."

### Approver API

```bash
curl -u alice:PASSWORD -X POST localhost:8765/v1/requests/$RID/approve -H 'Content-Type: application/json' -d '{"reason":"verified"}'
curl -u alice:PASSWORD -X POST localhost:8765/v1/requests/$RID/deny    -d '{"reason":"not authorised"}' -H 'Content-Type: application/json'
```

### Operational notes and limits

- Run **one API process** (`--workers 1`). Startup reconcile assumes no other process is mid-execution on the same state file. The worker only flags claims older than `PATIENCE_STUCK_SECONDS`.
- Login throttling is per process, in memory. Use a reverse proxy rate limit as well if you expose the API.
- Alerts are sent synchronously during `/v1/check` with a 5 s timeout per channel. A failing channel never blocks the check.
- One-tap links need `PATIENCE_PUBLIC_URL` to be reachable by the approver's phone. Serve it over TLS.
- The audit chain detects tampering but can't prevent someone with file access from deleting the whole log together with its `.head`. Ship it off-box (or keep a copy of `.head`) for stronger guarantees.

---

# History

## v0.3 — Command Dashboard

This version adds a live local control interface to the PATIENCE decision engine.

## What changed

PATIENCE now exposes:

- mission
- end state
- current objective
- priority
- observation count
- current confidence
- model-council votes
- Red Team findings
- blocked actions
- human authorization controls
- active tasks
- decision history
- assumptions and unknowns
- raw persistent state

The interface makes the decision path visible:

Observe → Assess → Challenge → Council → Decide → Authorize → Verify → Remember

## Start it on Windows

Open PowerShell in this folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_dashboard.ps1
```

Or manually:

```powershell
python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
```

Streamlit will open the dashboard in your browser.

## Important architecture rule

Models do not directly receive unrestricted tool authority.

External models such as Grok, Claude, or another LLM should be implemented as advisory adapters that return:

- recommendation
- confidence
- reasoning summary
- dissent

The Governance Gate decides whether an action is allowed.

## v0.4 target

The next version should add:

1. Real LLM adapters.
2. Real tool registry.
3. Event ingestion.
4. Outcome scoring.
5. Model disagreement visualization.
6. Decision replay.
7. Optional notifications and scheduled checks.


# v0.4 — Trigger Agent

v0.4 adds a persistent local agent that continuously inspects PATIENCE state.

It can trigger on:

- due tasks
- blocked actions
- high uncertainty
- checkpoints
- idle reassessment

The agent writes structured trigger events to:

`trigger_queue.jsonl`

Each trigger also contains a ready-to-send PATIENCE prompt.

To inspect the latest trigger manually:

```powershell
python .\trigger_bridge.py
```

To launch the dashboard and trigger agent together:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_patience.ps1
```

## Important boundary

This local agent can continuously generate triggers, but it cannot directly wake a ChatGPT conversation by itself unless it is connected to an external API, webhook, automation system, or another supported messaging channel.

That separation is intentional:
the Trigger Agent decides WHEN the system needs attention;
the Governance Gate decides WHAT is allowed;
the model decides HOW to reason about the trigger.


# v0.5 — Integrated build (optional LLM in the loop)

## Install
```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Run (no API key needed)
Without `PATIENCE_LLM_API_KEY` the council is the rule-based Oracle, Skeptic and Opportunity adapters, exactly like v0.4, and nothing leaves your machine. `.streamlit/config.toml` turns off Streamlit usage stats.
```powershell
.\run_patience.ps1        # dashboard + trigger agent + trigger worker
```
Or manually: `python -m streamlit run dashboard.py`, `python agent_daemon.py`, `python trigger_worker.py`.

## Optional: turn on the LLM council member
```powershell
$env:PATIENCE_LLM_API_KEY  = "your-key"
$env:PATIENCE_LLM_BASE_URL = "https://api.x.ai/v1"   # any OpenAI-compatible API
$env:PATIENCE_LLM_MODEL    = "<model name>"
```
- `LLMAdapter` joins the council as an advisory vote only when the second opinion is off (`PATIENCE_LLM_SECOND_OPINION=0`). With the second opinion on (the default with a key), that is the single LLM call per check. If the API fails, the council voter votes `human_review`.
- `trigger_worker.py` reads `trigger_queue.jsonl` (written by `agent_daemon.py`), asks the model about each trigger, and records the result. Any action the model proposes goes through the full check under the identity `trigger_worker` (risk policy and budgets). Risky ones go into **Blocked actions** and need **Authorize** on the dashboard. The worker never executes anything itself. Without a key the worker stays idle.
- With a key set, observations and state ARE sent to that provider.

## Tests
```bash
python -m pytest -q tests
```

## Ask PATIENCE before acting: the HTTP API

`api.py` lets any app, script or agent ask PATIENCE "may I do this?" before it does anything. It uses the same engine, rules and state file as the dashboard, so every request shows up on the dashboard too.

Start it with `python api.py` (`run_patience.ps1` also starts it). By default it listens on **http://127.0.0.1:8765**, which only your own computer can reach.

| Endpoint | What it does |
|---|---|
| `GET /health` | Shows whether it's running. |
| `POST /v1/check` | Send `{"action": "...", "context": "...", "metadata": {...}}` (or `tool` + `args`). Who is asking comes from your API key, not from the body. You get back a `decision` plus `reason`, `risk_categories`, `irreversible`, `confidence`, `request_id` and `approval_key`. |
| `GET /v1/requests/{id}` | Shows the request's `status`: `allowed`, `pending`, `approved`, `denied` or `executed`. Agents only see their own requests. |
| `POST /v1/execute` | Gateway mode: PATIENCE runs the tool itself (see below). |
| `POST /v1/requests/{id}/approve` / `deny` | A human approves or denies. Send the header `X-Approver-Token`. |

What each decision means:
- **allow**: go ahead.
- **needs_approval**: stop. A human has to approve this exact request, on the dashboard or through `/approve`. Keep checking the status.
- **clarify**: there's too little information. Add context, or wait for a human.
- **defer**: the same action is already waiting for approval, so this request doesn't create a second approval.

Security:
- With an `agents.yaml` (see **Agent identity**), every caller needs its own key. Without one, `PATIENCE_API_TOKEN` is a single shared key (identity `default`). With neither, the API is open to localhost as `local-dev`, which is for development only.
- `/approve` and `/deny` only work when `PATIENCE_APPROVER_TOKEN` is set. If it isn't, you can only approve on the dashboard.
- Each approval covers one request only. "Approve everything" isn't possible.
- The state file is protected by a lock file and is written atomically, so the dashboard, the trigger worker and the API can all run at the same time.

Examples: `examples/check.sh "Issue refunds totaling $1,800"` and `examples/client.py`. In `client.py`, `ask_patience(action)` returns True only when the decision is allow or a human approved the request. If anything goes wrong, it returns False and nothing happens.

## Risk policy (`policies/default.yaml`)

Risk scoring is driven by a policy file that is loaded at startup. To use a different file, set `PATIENCE_POLICY=/path/to/policy.yaml`. Restart the API or dashboard after you edit it.

| Section | What it controls |
|---|---|
| `thresholds` | `mass_recipients`, the number of recipients that counts as mass communication (default 10). Also sets the default and unknown-side-effect consequence. |
| `read_only_verbs`, `negations`, `fillers`, `action_joiners`, `side_effect_verbs` | How clauses are read. A clause that leads with a read-only verb or draft (summarize, list, draft, check) is safe unless it chains into an action ("check X **and send** it"). Negated actions ("don't send") are skipped. "Don't forget to delete X" is still scored. A side-effect verb that matches no category falls back to `unknown_side_effect`, which needs approval (fail safe). |
| `injection_patterns` | Regexes for prompt injection ("ignore previous instructions", "no approval needed"). A match adds the `injection` category or flag and requires approval. |
| `communication` | The communication verbs, plus the broad words and audience nouns that make a message mass communication. |
| `categories` | `money`, `public_publishing`, `deploy`, `deletion`, `account_permissions`, `security`, `pii_sensitive`, `legal`, `injection`. Each category has a `consequence`, an `irreversible` setting, `keywords` (stem-matched) and `patterns` (regex, for example `$1.8k`). |
| `industries` | Extra keywords for healthcare, finance, retail, hr, studio and legal. A section activates when its detect words appear in the text, or when the API caller sends `metadata.industry`. |
| `tools`, `read_only_tool_prefixes` | Scoring for structured calls (see below). |
| `limits` | Rolling budgets for each agent identity (from the API key). |
| `second_opinion` | An optional LLM check. |

Text is normalized before it is scored:

- Case and accents are folded.
- Number words become digits ("two thousand" becomes 2000).
- Amounts such as `1.8k` and `1,200` are parsed.
- Small typos are fuzzy-corrected against policy words with rapidfuzz ("sned" becomes "send").
- Words are stemmed.

### Structured checks (`tool` + `args`)

```json
POST /v1/check {"tool": "refund", "args": {"amount": 50, "count": 3}}   # identity comes from the bearer key
```

`send_email` and `send_message` read the `recipients` list or count. `refund`, `charge` and `transfer` read the amount × count. `delete_records`, `publish`, `deploy`, `grant_access` and `export_data` always need approval. Unknown tools need approval. Tools whose names start with `get_`, `list_`, `search_`, `draft_` and similar are allowed. String args are also scanned for injection, PII, security and legal terms. Free-text `action` remains supported as a fallback, and sending both scores the union of the two.

### Rolling budgets

Allowed and approved calls, both structured and free-text, are logged for each **agent identity** (taken from the API key). The trigger worker uses the identity `trigger_worker`, and the dashboard uses `dashboard`. The defaults are:

- Refunds above $2,000 per day.
- More than 50 messages per hour.
- Any delete.

When a call would cross one of these, it returns `needs_approval` with the `budget_exceeded` flag. This stops an agent from evading approval by splitting one large action into many small ones.

### LLM second opinion (optional)

If `PATIENCE_LLM_API_KEY` is set, each check is also sent to the LLM through `llm_adapter.chat`. This adds latency, and the action text goes to your LLM provider. To turn it off, set `PATIENCE_LLM_SECOND_OPINION=0`.

The LLM can only escalate a decision:

- If the LLM says an action needs approval but the rules allowed it, the result is `needs_approval` with the `llm_disagreement` flag.
- If the rules block an action, the LLM cannot downgrade that.
- If the LLM call fails, the rules decision stands and the error is listed in `details`.

The `/v1/check` response now includes `flags` (`injection`, `budget_exceeded`, `llm_disagreement`) and `details`, which lists the reasons.

### Evaluation

To evaluate, run `python tests/eval_governance.py --misses`. It runs the labeled cases in `tests/cases/governance_cases.yaml` through both the engine and the API. `tests/test_governance_cases.py` enforces 100% recall on risky cases and requires at least 90% of benign cases to be allowed.


## Agent identity (per-agent API keys)

```bash
python identity.py add support-bot --industry retail   # prints the key ONCE
python identity.py revoke support-bot
```
- Keys are stored in `agents.yaml` (or the path in `PATIENCE_AGENTS`) only as sha256 hashes and are compared in constant time. `agents.yaml` is gitignored; `agents.example.yaml` shows the format.
- Once any agent exists, every call needs `Authorization: Bearer <agent key>`. An unknown, missing or revoked key gets **401**.
- The requester **is** the key's identity. If you send a `requester` field that differs from it, you get **400**. Budgets, request visibility and execution are all keyed to the identity.
- Approving is a human action. `/approve` and `/deny` accept only `X-Approver-Token`. An agent key gets 403.

## Gateway mode: agents get no direct tool keys

Asking `/v1/check` is advisory: an agent that holds the SMTP password could skip the check. Gateway mode closes that gap. **PATIENCE holds the tool credentials and makes the call itself.** It does so only after the call is allowed, or after a human approves that exact call.

Deployment pattern:
1. Put tool credentials **only** in PATIENCE's environment (the `PATIENCE_SMTP_*` and `PATIENCE_WEBHOOK_*` variables). The API never returns them.
2. Give each agent only its PATIENCE agent key. Remove SMTP passwords, Zapier/Make hook URLs and payment keys from the agent's environment, secrets and prompt.
3. Agents call `POST /v1/execute {"tool", "args", "idempotency_key"}`:
   - **200** `executed`: it ran.
   - **202** `pending_approval`: a human must approve. Poll `GET /v1/requests/{id}`, then call `/v1/execute` again with `request_id` and the **same** tool and args.
   - **409**: the args differ from what was approved, or the approval was already used, or the idempotency key was reused for a different call.
   - **403**: denied.
   - **501**: no executor is configured for that tool.
   - **502**: the executor failed. It is not retried, so submit a new request.
4. For real enforcement, block agents' network access to the tool hosts (firewall or egress rules), so PATIENCE is the only route.

Guarantees:
- **Approval is bound to the call.** The approval covers the sha256 of the canonical `{tool, args}`. Changing any argument after approval needs a new approval, and PATIENCE always executes its stored copy of the approved args.
- **Exactly once.** The execution is claimed under the state lock before it runs. Each approval runs at most once. Replaying the same `idempotency_key` returns the stored result and doesn't run again. A failure counts as used (at-most-once).
- `/v1/execute` requires agent-key mode.

Executors (`executors/`) are disabled until configured, and **dry-run by default**:

| Env | Effect |
|---|---|
| `PATIENCE_EXECUTE_LIVE=1` | Actually send. Without it, executors return what they *would* do. A dry run doesn't use up the approval. |
| `PATIENCE_SMTP_HOST`, `_PORT` (587), `_USER`, `_PASSWORD`, `_FROM`, `_SSL=1` | SMTP email for `send_email` and `send_message`. Uses STARTTLS and rejects header injection. Args: `recipients`, `subject`, `body`. |
| `PATIENCE_WEBHOOK_URL_<TOOL>` or `PATIENCE_WEBHOOK_URL` | Generic HTTPS POST for any other tool (Zapier, Make, n8n). Sends `Idempotency-Key`, plus an `X-Patience-Signature` HMAC when `PATIENCE_WEBHOOK_SECRET` is set. |
| `PATIENCE_EXECUTOR_MOCK=1` | In-memory mock for tests. |

`examples/client.py` has `execute_via_patience(tool, args)`.

## Dashboard lock

- Set `PATIENCE_DASHBOARD_PASSWORD`, or better `PATIENCE_DASHBOARD_PASSWORD_SHA256` (hex sha256, so no plaintext is kept in the environment). Nothing renders until you log in.
- The check compares hashes in constant time. A login lasts for the session, 8 hours by default (`PATIENCE_DASHBOARD_SESSION_HOURS`). Five failed tries lock the session out for 5 minutes.
- **No password set** means the dashboard is **read-only**: it shows a warning, has no Authorize buttons and has no forms that change anything.
- It binds to `127.0.0.1` (`.streamlit/config.toml` and `run_dashboard.ps1`). To reach it from other machines, use a TLS reverse proxy and keep the password set.
