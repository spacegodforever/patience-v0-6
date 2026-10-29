"""Tamper-evident audit log (append-only JSONL, SHA-256 hash chain).

Each line: {"seq", "ts", "event", "actor", "data", "prev", "hash"} where
hash = sha256(canonical JSON of the record without "hash") and prev = hash of the
previous line ("0"*64 for the first). Editing, deleting, inserting or reordering any
line breaks the chain. The newest hash is also written to <log>.head, so cutting
lines off the end is detected too (unless the attacker rewrites both files; ship the
log off-box for that, see README).

    python audit.py verify        exit 0 if intact, 1 if not
    python audit.py tail [N]

Env: PATIENCE_AUDIT_PATH (default patience_audit.jsonl)
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional
from filelock import FileLock
from models import now_iso

GENESIS = "0" * 64


def path() -> Path:
    return Path(os.environ.get("PATIENCE_AUDIT_PATH", "patience_audit.jsonl"))


def _head(p: Path) -> Path:
    return p.with_name(p.name + ".head")


def _digest(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _last(p: Path):
    if not p.exists() or p.stat().st_size == 0:
        return 0, GENESIS
    with open(p, "rb") as f:  # read the last line without loading the whole file
        f.seek(0, 2)
        end = f.tell()
        pos = max(0, end - 65536)
        f.seek(pos)
        lines = f.read().splitlines()
    last = json.loads(lines[-1])
    return int(last["seq"]), last["hash"]


def append(event: str, actor: Optional[str] = None, **data: Any) -> dict:
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(str(p) + ".lock", timeout=30):
        seq, prev = _last(p)
        rec = {"seq": seq + 1, "ts": now_iso(), "event": event, "actor": actor, "data": data, "prev": prev}
        rec["hash"] = _digest(rec)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str) + "\n"
        with open(p, "a", encoding="utf-8") as f:  # append-only
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        _head(p).write_text(rec["hash"], encoding="utf-8")
    return rec


def read(limit: Optional[int] = None) -> list:
    p = path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"event": "<unparseable line>", "raw": line[:200]})
    return out[-limit:] if limit else out


def verify() -> dict:
    """{"ok": bool, "records": n, "error": str|None, "bad_seq": int|None}"""
    p = path()
    if not p.exists():
        ok = not _head(p).exists()
        return {"ok": ok, "records": 0, "error": None if ok else "log missing but head exists", "bad_seq": None}
    prev, n = GENESIS, 0
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        try:
            rec = json.loads(line)
        except ValueError:
            return {"ok": False, "records": n, "error": f"line {i} is not valid JSON", "bad_seq": i}
        if rec.get("seq") != i:
            return {"ok": False, "records": n, "error": f"line {i}: sequence gap/reorder", "bad_seq": i}
        if rec.get("prev") != prev:
            return {"ok": False, "records": n, "error": f"line {i}: chain broken (prev hash mismatch)", "bad_seq": i}
        if _digest(rec) != rec.get("hash"):
            return {"ok": False, "records": n, "error": f"line {i}: record modified (hash mismatch)", "bad_seq": i}
        prev, n = rec["hash"], i
    h = _head(p)
    if h.exists() and h.read_text(encoding="utf-8").strip() != prev:
        return {"ok": False, "records": n, "error": "log truncated or head file altered", "bad_seq": None}
    return {"ok": True, "records": n, "error": None, "bad_seq": None}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    cmd = argv[0] if argv else "verify"
    if cmd == "verify":
        r = verify()
        print(("OK" if r["ok"] else "TAMPERED") + f": {r['records']} records verified ({path()})"
              + ("" if r["ok"] else f" - {r['error']}"))
        return 0 if r["ok"] else 1
    if cmd == "tail":
        for rec in read(int(argv[1]) if len(argv) > 1 else 20):
            print(json.dumps(rec, default=str))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
