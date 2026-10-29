# PATIENCE v0.4 Agent Loop

STATE
  ↓
TRIGGER AGENT
  ↓
Trigger classification
  ├─ task_due
  ├─ blocked_action
  ├─ high_uncertainty
  ├─ checkpoint
  └─ idle_reassessment
  ↓
TRIGGER QUEUE
  ↓
MODEL / CHATGPT / ORACLE
  ↓
ASSESSMENT
  ↓
RED TEAM
  ↓
GOVERNANCE GATE
  ↓
ACTION OR HUMAN AUTHORIZATION
  ↓
VERIFICATION
  ↓
MEMORY UPDATE
  ↓
STATE
  ↺

The loop is deliberately event-driven.

The trigger layer is not an authority layer.
It may request cognition, but it may not silently elevate its permissions.
