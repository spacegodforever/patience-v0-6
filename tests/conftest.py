import os
os.environ["PATIENCE_NO_DOTENV"] = "1"
import os, sys
import pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Every test gets its own audit log / approvers file; no test touches repo-local files.
    Pre-v0.6 tests use the shared approver token, which now needs the explicit legacy flag."""
    monkeypatch.setenv("PATIENCE_AUDIT_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PATIENCE_APPROVERS", str(tmp_path / "approvers.yaml"))
    monkeypatch.setenv("PATIENCE_LEGACY_APPROVER_TOKEN", "1")
    monkeypatch.setenv("PATIENCE_LINK_SECRET", "test-link-secret-0123456789abcdef")
    for v in ("PATIENCE_EXECUTE_LIVE", "PATIENCE_NOTIFY_SLACK_WEBHOOK", "PATIENCE_NOTIFY_WEBHOOK_URL",
              "PATIENCE_NOTIFY_EMAIL_TO", "STRIPE_API_KEY", "PATIENCE_STRIPE_API_KEY", "PATIENCE_STRIPE_ALLOW_LIVE"):
        monkeypatch.delenv(v, raising=False)
    import approvers
    approvers._FAILS.clear()
    yield
