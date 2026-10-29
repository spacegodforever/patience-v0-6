from __future__ import annotations
import json
from pathlib import Path

QUEUE = Path("trigger_queue.jsonl")
OUT = Path("latest_trigger_prompt.txt")

def consume_latest():
    if not QUEUE.exists():
        print("No trigger queue yet.")
        return

    lines = [line.strip() for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        print("Trigger queue is empty.")
        return

    event = json.loads(lines[-1])
    OUT.write_text(event["prompt"], encoding="utf-8")

    print("Latest trigger:")
    print("type:", event["trigger_type"])
    print("time:", event["timestamp"])
    print()
    print(event["prompt"])
    print()
    print(f"Saved prompt to {OUT}")

if __name__ == "__main__":
    consume_latest()
