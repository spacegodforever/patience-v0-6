from __future__ import annotations
import os


class ExecutionError(Exception):
    """Raised with a credential-free message."""


def live_mode() -> bool:
    return os.environ.get("PATIENCE_EXECUTE_LIVE") == "1"


class Executor:
    name = "base"

    def run(self, tool: str, args: dict, meta: dict) -> dict:
        """meta: {request_id, idempotency_key, identity}. Return a JSON-able, secret-free result.
        Must honour live_mode(): when False, describe the action and send nothing."""
        raise NotImplementedError
