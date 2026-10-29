"""Pluggable executors for gateway mode (POST /v1/execute).

PATIENCE holds the real credentials (env vars) and performs the action itself,
only after the check allowed it or a human approved it. Agents never see keys.

Safety defaults:
  * Every executor is DISABLED until its env vars are set (see each class).
  * DRY-RUN unless PATIENCE_EXECUTE_LIVE=1: the executor validates and describes
    what it would do, but sends nothing.
  * Results never include credentials.

Routing (first match wins):
  1. PATIENCE_EXECUTOR_MOCK=1          -> MockExecutor (tests / demos, records calls in memory)
  2. tool in StripeExecutor.TOOLS and a Stripe key is set -> Stripe (test keys only unless allowed)
  3. tool in SmtpEmailExecutor.TOOLS and SMTP configured -> SMTP
  4. PATIENCE_WEBHOOK_URL_<TOOL> or PATIENCE_WEBHOOK_URL -> WebhookExecutor (Zapier / Make / n8n catch hook)
  5. otherwise -> None (API returns 501: no executor configured)
"""
from __future__ import annotations
import os
from typing import Optional
from .base import Executor, ExecutionError, live_mode
from .mock import MockExecutor
from .smtp_email import SmtpEmailExecutor
from .webhook import WebhookExecutor
from .stripe_exec import StripeExecutor

__all__ = ["Executor", "ExecutionError", "live_mode", "get_executor",
           "MockExecutor", "SmtpEmailExecutor", "WebhookExecutor", "StripeExecutor"]


def get_executor(tool: str) -> Optional[Executor]:
    tool = (tool or "").lower()
    if os.environ.get("PATIENCE_EXECUTOR_MOCK") == "1":
        return MockExecutor.shared()
    if tool in StripeExecutor.TOOLS and StripeExecutor.configured():
        return StripeExecutor()
    if tool in SmtpEmailExecutor.TOOLS and SmtpEmailExecutor.configured():
        return SmtpEmailExecutor()
    if WebhookExecutor.url_for(tool):
        return WebhookExecutor()
    return None
