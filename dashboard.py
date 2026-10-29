import json
import os
from datetime import datetime, timezone
import streamlit as st
import envfile
envfile.load()
from engine import Patience
import dashboard_auth as auth
import audit

st.set_page_config(
    page_title="PATIENCE Command",
    page_icon="*)",
    layout="wide"
)

st.markdown("""
<style>
html, body, [data-testid="stAppViewContainer"] {
    background: #0b0d10;
    color: #e8eaed;
}
.block-container { padding-top: 1.3rem; max-width: 1500px; }
.p-card {
    border: 1px solid #2a2f36;
    background: rgba(19,22,27,.82);
    border-radius: 14px;
    padding: 14px 16px;
    margin-bottom: 10px;
}
.p-kicker {
    font-size: 0.72rem;
    letter-spacing: .16em;
    color: #9aa0a6;
    text-transform: uppercase;
}
.p-value { font-size: 1.05rem; font-weight: 600; }
.flow {
    display:flex; gap:8px; flex-wrap:wrap; margin: 10px 0 16px 0;
}
.node {
    border:1px solid #31363d;
    border-radius:999px;
    padding:7px 11px;
    font-size:.78rem;
    background:#15181d;
}
.logo { font-size: 2.2rem; font-weight:700; letter-spacing:-.08em; }
.small { color:#9aa0a6; font-size:.78rem; }
</style>
""", unsafe_allow_html=True)

# ---- lock: nothing below renders until the password check passes ----------
if auth.password_configured():
    if not auth.is_authed(st.session_state):
        st.title("PATIENCE Command")
        with st.form("login"):
            user = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            if st.form_submit_button("Unlock"):
                if auth.login(st.session_state, user, pw):
                    st.rerun()
                else:
                    st.error("Wrong password (or too many tries; wait 5 minutes).")
        st.stop()
    CAN_WRITE = True
    _who = auth.current(st.session_state)
    st.sidebar.caption(f"Signed in as **{_who['user']}** ({_who['role']})")
    if st.sidebar.button("Lock dashboard"):
        auth.logout(st.session_state)
        st.rerun()
else:
    CAN_WRITE = False
    st.warning("READ-ONLY: no approver accounts exist, so approvals and edits are disabled. "
               "Create one with `python approvers.py add <you> --role admin` (or `patience init`).")

p = Patience(os.environ.get("PATIENCE_STATE_PATH", "patience_state.json"))

_av = audit.verify()
if _av["ok"]:
    st.sidebar.success(f"Audit log verified: {_av['records']} records, chain intact")
else:
    st.sidebar.error(f"AUDIT LOG TAMPERED: {_av['error']}")

if CAN_WRITE and not p.state.mission:
    p.set_mission(
        "Build PATIENCE into a governed proactive decision system.",
        "A persistent, time-aware system that observes, challenges, decides, verifies, and remembers.",
        "Validate the PATIENCE v0.3 control architecture.",
        "Decision integrity before autonomous reach."
    )

import pandas as pd
import altair as alt
import dashboard_ops as ops
import previews as _pv

WHO = auth.current(st.session_state)
tab_over, tab_queue, tab_audit, tab_policy, tab_cmd = st.tabs(
    ["Overview", "Pending queue", "Audit log", "Policy", "Command"])

with tab_over:
    m = ops.metrics(p.state)
    k = st.columns(5)
    k[0].metric("Checks", m["checks"])
    k[1].metric("Pending", m["status"].get("pending", 0))
    k[2].metric("Approvals", m["approvals"])
    k[3].metric("Denials", m["denials"])
    k[4].metric("Needs review", m["status"].get("needs_review", 0))
    if m["series"]:
        st.markdown("**Activity over time**")
        st.altair_chart(alt.Chart(pd.DataFrame(m["series"])).mark_line(point=True).encode(
            x="day:T", y="count:Q", color="metric:N"), use_container_width=True)
    if m["blocks_by_category"]:
        st.markdown("**Held / blocked by risk category**")
        st.altair_chart(alt.Chart(pd.DataFrame([{"category": c, "count": n} for c, n in m["blocks_by_category"].items()]))
                        .mark_bar().encode(x="count:Q", y=alt.Y("category:N", sort="-x")), use_container_width=True)
    if not m["checks"]:
        st.caption("No checks yet. Point an agent at /v1/check to see metrics here.")

with tab_queue:
    queue = ops.pending_queue(p.state)
    if not queue:
        st.success("Nothing waiting for a human.")
    for r in queue:
        pv = r.get("preview") or {}
        stt = ops.status(p.state, r)
        with st.container(border=True):
            st.markdown(f"**{pv.get('summary') or r.get('action')}**  ·  `{stt}`  ·  {r.get('identity')}  ·  {r.get('created_at', '')[:19]}")
            st.code(_pv.as_text(pv) if pv else (r.get("action") or ""), language=None)
            st.caption(f"Why: {r.get('reason')}  ·  risk: {', '.join(r.get('risk_categories') or []) or 'n/a'}")
            if stt == "needs_review":
                st.warning("Interrupted mid-execution; outcome unknown. Resolve via POST /v1/admin/requests/{id}/resolve.")
            elif WHO:
                reason = st.text_input("Reason", key=f"why-{r['request_id']}", placeholder="Why (recorded in the audit log)")
                b1, b2 = st.columns(2)
                if b1.button("Approve", key=f"qa-{r['request_id']}"):
                    try:
                        ops.decide_pending(p, r["request_id"], True, auth.current(st.session_state), reason)
                    except (ValueError, PermissionError) as e:
                        st.error(str(e))
                    st.rerun()
                if b2.button("Deny", key=f"qd-{r['request_id']}"):
                    try:
                        ops.decide_pending(p, r["request_id"], False, auth.current(st.session_state), reason)
                    except (ValueError, PermissionError) as e:
                        st.error(str(e))
                    st.rerun()

with tab_audit:
    if not WHO:
        st.info("Log in to view the audit log.")
    else:
        a1, a2 = st.columns([3, 1])
        q = a1.text_input("Search the audit log", key="audit_q", placeholder="request id, approver, tool, word...")
        ev = a2.selectbox("Event", ["", "check", "approval", "execute", "notify", "link", "auth", "policy"],
                          key="audit_ev")
        rows = ops.search_audit(q, ev, limit=300)
        st.caption(f"{len(rows)} record(s), newest first")
        if rows:
            st.dataframe(pd.DataFrame([{"seq": e["seq"], "time (UTC)": e["ts"][:19], "event": e["event"],
                                        "actor": e.get("actor"), "data": str(e["data"])[:300]} for e in rows]),
                         use_container_width=True, hide_index=True)

with tab_policy:
    if not auth.is_admin(st.session_state):
        st.info("Only admins can view and edit the policy.")
    else:
        st.caption(f"Editing {ops.policy_path()}. Validated before saving; every change is audited with a diff.")
        txt = st.text_area("Policy YAML", ops.read_policy(), height=420, key="policy_txt")
        note = st.text_input("Change note", key="policy_note")
        c_v, c_s = st.columns(2)
        if c_v.button("Validate"):
            errs = ops.validate_policy(txt)
            if not errs:
                st.success("Valid.")
            for x in errs:
                st.error(x)
        if c_s.button("Save policy"):
            try:
                res = ops.save_policy(txt, auth.current(st.session_state), note)
                st.success("Saved and reloaded." if res["changed"] else "No changes.")
            except (ValueError, PermissionError) as e:
                st.error(str(e))

with tab_cmd:
  top1, top2 = st.columns([1,4])
  with top1:
      st.markdown('<div class="logo">*)</div>', unsafe_allow_html=True)
  with top2:
      st.title("PATIENCE Command")
      st.caption("Governed decision intelligence / v0.6")

  st.markdown("""
  <div class="flow">
  <span class="node">OBSERVE</span>
  <span class="node">ASSESS</span>
  <span class="node">CHALLENGE</span>
  <span class="node">COUNCIL</span>
  <span class="node">DECIDE</span>
  <span class="node">AUTHORIZE</span>
  <span class="node">VERIFY</span>
  <span class="node">REMEMBER</span>
  </div>
  """, unsafe_allow_html=True)

  c1, c2, c3, c4 = st.columns(4)
  with c1:
      st.metric("Observations", len(p.state.observations))
  with c2:
      latest_conf = p.state.assessments[-1]["confidence"] if p.state.assessments else 0
      st.metric("Confidence", f"{latest_conf:.0%}")
  with c3:
      st.metric("Blocked actions", len(p.state.blocked_actions))
  with c4:
      st.metric("Active tasks", len([t for t in p.state.tasks if t.get("status")=="active"]))

  st.subheader("Command State")
  a,b = st.columns(2)
  with a:
      st.markdown(f'<div class="p-card"><div class="p-kicker">Mission</div><div class="p-value">{p.state.mission}</div></div>', unsafe_allow_html=True)
      st.markdown(f'<div class="p-card"><div class="p-kicker">Current Objective</div><div class="p-value">{p.state.current_objective}</div></div>', unsafe_allow_html=True)
  with b:
      st.markdown(f'<div class="p-card"><div class="p-kicker">End State</div><div class="p-value">{p.state.end_state}</div></div>', unsafe_allow_html=True)
      st.markdown(f'<div class="p-card"><div class="p-kicker">Priority</div><div class="p-value">{p.state.priority}</div></div>', unsafe_allow_html=True)

  st.subheader("Inject Observation")
  submitted, content = False, ""
  if CAN_WRITE:
    with st.form("observation_form"):
        content = st.text_area("Observation / event / request", height=100, placeholder="Enter a new event for PATIENCE to evaluate...")
        colx, coly = st.columns([3,1])
        with colx:
            source = st.text_input("Source", value="user")
        with coly:
            reliability = st.slider("Reliability", 0.0, 1.0, 0.9, 0.05)
        submitted = st.form_submit_button("Run Decision Cycle", use_container_width=True)

  if CAN_WRITE and submitted and content.strip():
      result = p.cycle(content.strip(), source=source.strip() or "user", reliability=reliability,
                       identity="dashboard")
      st.session_state["latest_result"] = result
      st.rerun()

  result = st.session_state.get("latest_result")
  if result:
      st.subheader("Live Decision Trace")
      cols = st.columns(4)
      trace = [
          ("Assessment", result["assessment"]),
          ("Red Team", result["red_team"]),
          ("Consensus", {"recommendation": result["consensus"]}),
          ("Decision", result["decision"]),
      ]
      for col, (title, data) in zip(cols, trace):
          with col:
              st.markdown(f"**{title}**")
              st.json(data)

      st.markdown("**Verification**")
      st.json(result["verification"])

  st.subheader("Model Council")
  votes = p.state.model_votes[-6:]
  if votes:
      for v in reversed(votes):
          with st.expander(f'{v["model"]} → {v["recommendation"]} ({v["confidence"]:.0%})'):
              st.write(v["reasoning_summary"])
              if v.get("dissent"):
                  st.caption("Dissent: " + v["dissent"])
  else:
      st.caption("No model votes yet.")

  left, right = st.columns(2)

  with left:
      st.subheader("Oversight")
      if p.state.blocked_actions:
          for action in sorted(set(p.state.blocked_actions)):
              st.warning(f"Blocked: {action}")
              if auth.can_approve(st.session_state):
                  if st.button(f"Authorize {action}", key=f"auth-{action}"):
                      auth.approve(p, action, st.session_state)
                      st.rerun()
      else:
          st.success("No blocked actions.")

      st.markdown("**Assumptions**")
      if p.state.assumptions:
          for item in p.state.assumptions:
              st.write("•", item)
      else:
          st.caption("No active assumptions.")

      st.markdown("**Unknowns**")
      if p.state.unknowns:
          for item in p.state.unknowns:
              st.write("•", item)
      else:
          st.caption("No material unknowns.")

  with right:
      st.subheader("Temporal Layer")
      add_task = False
      if CAN_WRITE:
          with st.form("task_form"):
              task_title = st.text_input("Task title")
              due_at = st.text_input("Due timestamp (ISO, optional)", placeholder="2026-10-05T12:00:00+00:00")
              priority = st.selectbox("Priority", [1,2,3,4,5], index=2)
              add_task = st.form_submit_button("Add Task")
      if add_task and task_title.strip():
          p.add_task(task_title.strip(), due_at.strip() or None, priority)
          st.rerun()

      if p.state.tasks:
          for t in sorted(p.state.tasks, key=lambda x: x.get("priority", 3)):
              st.markdown(f"**P{t.get('priority',3)} — {t['title']}**")
              st.caption(f"status={t.get('status')} · due={t.get('due_at') or 'unscheduled'}")
      else:
          st.caption("No tasks registered.")

  st.subheader("Decision Log")
  if p.state.decisions:
      for i, d in enumerate(reversed(p.state.decisions[-10:]), start=1):
          st.markdown(f"**{d['action']}** · confidence {d['confidence']:.0%}")
          st.caption(d["reason"])
  else:
      st.caption("No decisions recorded.")

  with st.expander("Raw PATIENCE state"):
      st.json(p.state.__dict__)
