from __future__ import annotations
import copy
import threading
from .base import Executor, live_mode


class MockExecutor(Executor):
    """In-memory executor for tests. Records every call; `fail_next` simulates an error."""
    name = "mock"
    _shared = None

    def __init__(self):
        self.calls = []
        self.fail_next = False
        self._lock = threading.Lock()

    @classmethod
    def shared(cls) -> "MockExecutor":
        if cls._shared is None:
            cls._shared = cls()
        return cls._shared

    @classmethod
    def reset(cls):
        cls._shared = cls()
        return cls._shared

    def run(self, tool, args, meta):
        with self._lock:
            if self.fail_next:
                self.fail_next = False
                raise RuntimeError("mock failure")
            self.calls.append({"tool": tool, "args": copy.deepcopy(args), "meta": dict(meta), "live": live_mode()})
            return {"executor": self.name, "live": live_mode(), "ok": True, "call_number": len(self.calls)}
