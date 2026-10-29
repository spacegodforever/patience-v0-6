"""v0.6 step 5: Stripe executor (mocked transport; no network)."""
import pytest
import executors
from executors.stripe_exec import StripeExecutor
from executors.base import ExecutionError

META = {"request_id": "r1", "idempotency_key": "idem-12345678", "identity": "agent1"}


@pytest.fixture
def calls(monkeypatch):
    out = []

    def fake(path, form, headers):
        out.append((path, form, headers))
        return {"id": "re_123", "status": "succeeded", "amount": form.get("amount"), "currency": "usd"}
    monkeypatch.setattr(StripeExecutor, "_request", staticmethod(fake))
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    return out


def test_routing(monkeypatch):
    assert executors.get_executor("refund") is None or not isinstance(executors.get_executor("refund"), StripeExecutor)
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_test_abc")
    assert isinstance(executors.get_executor("refund"), StripeExecutor)
    assert isinstance(executors.get_executor("charge"), StripeExecutor)


def test_live_key_refused(monkeypatch, calls):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_live_abc")
    monkeypatch.setenv("PATIENCE_EXECUTE_LIVE", "1")
    with pytest.raises(ExecutionError, match="live Stripe key"):
        StripeExecutor().run("refund", {"payment_intent": "pi_1", "amount": 10}, META)
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "rk_live_abc")
    with pytest.raises(ExecutionError, match="live Stripe key"):
        StripeExecutor().run("refund", {"payment_intent": "pi_1"}, META)
    assert calls == []
    monkeypatch.setenv("PATIENCE_STRIPE_ALLOW_LIVE", "1")
    assert StripeExecutor().run("refund", {"payment_intent": "pi_1"}, META)["stripe_mode"] == "live"


def test_unknown_key_refused(monkeypatch, calls):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "pk_test_publishable")
    with pytest.raises(ExecutionError):
        StripeExecutor().run("refund", {"payment_intent": "pi_1"}, META)


def test_dry_run_sends_nothing(monkeypatch, calls):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_test_abc")
    r = StripeExecutor().run("refund", {"payment_intent": "pi_1", "amount": "12.50"}, META)
    assert r["dry_run"] and "$12.50" in r["would"] and calls == []


def test_refund_live_passes_idempotency_key(monkeypatch, calls):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_test_abc")
    monkeypatch.setenv("PATIENCE_EXECUTE_LIVE", "1")
    r = StripeExecutor().run("refund", {"charge": "ch_1", "amount": 12.5, "reason": "duplicate"}, META)
    path, form, h = calls[0]
    assert path == "/v1/refunds" and form["amount"] == 1250 and form["charge"] == "ch_1"
    assert h["Idempotency-Key"] == "patience-idem-12345678" and h["Authorization"] == "Bearer sk_test_abc"
    assert r["stripe_id"] == "re_123" and "sk_test" not in str(r)


def test_charge_live(monkeypatch, calls):
    monkeypatch.setenv("STRIPE_API_KEY", "sk_test_abc")
    monkeypatch.setenv("PATIENCE_EXECUTE_LIVE", "1")
    StripeExecutor().run("charge", {"amount_cents": 999, "currency": "EUR", "customer": "cus_1",
                                    "payment_method": "pm_1"}, META)
    path, form, _ = calls[0]
    assert path == "/v1/payment_intents" and form["currency"] == "eur" and form["confirm"] == "true"


@pytest.mark.parametrize("args", [{"amount": 5}, {"payment_intent": "pi", "amount": -1},
                                  {"payment_intent": "pi", "amount": "1.234"},
                                  {"payment_intent": "pi", "reason": "because"}])
def test_bad_refund_args(monkeypatch, calls, args):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_test_abc")
    with pytest.raises(ExecutionError):
        StripeExecutor().run("refund", args, META)


def test_charge_requires_customer(monkeypatch, calls):
    monkeypatch.setenv("PATIENCE_STRIPE_API_KEY", "sk_test_abc")
    with pytest.raises(ExecutionError):
        StripeExecutor().run("charge", {"amount": 5}, META)
