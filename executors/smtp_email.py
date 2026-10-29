from __future__ import annotations
import os
import smtplib
import ssl
from email.message import EmailMessage
from .base import Executor, ExecutionError, live_mode


class SmtpEmailExecutor(Executor):
    """send_email / send_message over SMTP.

    Env (kept server-side, never returned): PATIENCE_SMTP_HOST, PATIENCE_SMTP_PORT (587),
    PATIENCE_SMTP_USER, PATIENCE_SMTP_PASSWORD, PATIENCE_SMTP_FROM, PATIENCE_SMTP_SSL=1 for
    implicit TLS (465). STARTTLS is required otherwise.
    args: recipients (list or comma string), subject, body.
    """
    name = "smtp"
    TOOLS = {"send_email", "send_message"}

    @staticmethod
    def configured() -> bool:
        return bool(os.environ.get("PATIENCE_SMTP_HOST") and os.environ.get("PATIENCE_SMTP_FROM"))

    @staticmethod
    def _recipients(args) -> list:
        r = args.get("recipients") or []
        if isinstance(r, str):
            r = [x.strip() for x in r.replace(";", ",").split(",")]
        r = [str(x).strip() for x in r if str(x).strip()]
        if not r or any("@" not in x or "\n" in x or "\r" in x for x in r):
            raise ExecutionError("recipients must be a non-empty list of email addresses")
        return r

    def build(self, args) -> EmailMessage:
        msg = EmailMessage()
        msg["From"] = os.environ["PATIENCE_SMTP_FROM"]
        msg["To"] = ", ".join(self._recipients(args))
        subject = str(args.get("subject", ""))
        if "\n" in subject or "\r" in subject:
            raise ExecutionError("subject must be one line")
        msg["Subject"] = subject
        msg.set_content(str(args.get("body", "")))
        return msg

    def run(self, tool, args, meta):
        msg = self.build(args)
        n = len(self._recipients(args))
        if not live_mode():
            return {"executor": self.name, "live": False, "dry_run": True,
                    "would_send": {"to_count": n, "subject": msg["Subject"]}}
        host = os.environ["PATIENCE_SMTP_HOST"]
        port = int(os.environ.get("PATIENCE_SMTP_PORT", "587"))
        user, pw = os.environ.get("PATIENCE_SMTP_USER"), os.environ.get("PATIENCE_SMTP_PASSWORD")
        ctx = ssl.create_default_context()
        try:
            if os.environ.get("PATIENCE_SMTP_SSL") == "1":
                s = smtplib.SMTP_SSL(host, port, context=ctx, timeout=30)
            else:
                s = smtplib.SMTP(host, port, timeout=30)
                s.starttls(context=ctx)
            with s:
                if user:
                    s.login(user, pw or "")
                s.send_message(msg)
        except Exception as e:  # never echo server banners or credentials
            raise ExecutionError(f"SMTP send failed ({type(e).__name__})") from None
        return {"executor": self.name, "live": True, "sent_to_count": n}
