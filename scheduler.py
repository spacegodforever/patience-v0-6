from datetime import datetime, timezone
from models import Task, PatienceState

class TemporalLayer:
    def add_task(self, state: PatienceState, task: Task) -> None:
        state.tasks.append(task.__dict__)

    def due_tasks(self, state: PatienceState, now=None):
        now = now or datetime.now(timezone.utc)
        due = []
        for task in state.tasks:
            if task.get("status") != "active" or not task.get("due_at"):
                continue
            try:
                t = datetime.fromisoformat(task["due_at"].replace("Z", "+00:00"))
                if t <= now:
                    due.append(task)
            except ValueError:
                pass
        return due

    def next_checkpoint(self, state: PatienceState) -> str:
        active = [t for t in state.tasks if t.get("status") == "active" and t.get("due_at")]
        return min(active, key=lambda x: x["due_at"])["due_at"] if active else "No scheduled checkpoint"
