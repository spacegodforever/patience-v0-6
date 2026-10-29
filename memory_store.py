import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from dataclasses import asdict
from filelock import FileLock
from models import PatienceState, now_iso

class MemoryStore:
    """JSON state with a cross-process file lock and atomic writes, so the
    dashboard, trigger worker and HTTP API can run at the same time."""

    def __init__(self, path="patience_state.json"):
        self.path = Path(path)
        self._lock = FileLock(str(self.path) + ".lock", timeout=30)

    @contextmanager
    def locked(self):
        with self._lock:  # re-entrant within a process
            yield

    def save(self, state: PatienceState) -> None:
        state.last_updated = now_iso()
        data = json.dumps(asdict(state), indent=2)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent) or ".", prefix=".patience_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)

    def load(self) -> PatienceState:
        with self._lock:
            if not self.path.exists():
                return PatienceState()
            data = json.loads(self.path.read_text(encoding="utf-8"))
        allowed = PatienceState.__dataclass_fields__.keys()
        return PatienceState(**{k:v for k,v in data.items() if k in allowed})

    def record_memory(self, state, kind, content, confidence):
        state.memory.append({
            "kind": kind,
            "content": content,
            "confidence": confidence,
            "timestamp": now_iso()
        })
