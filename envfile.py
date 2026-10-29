"""Minimal .env loader (no dependency). Existing environment variables always win.
File: PATIENCE_DOTENV (default ./.env). Disabled with PATIENCE_NO_DOTENV=1 (tests)."""
import os


def load(path=None):
    if os.environ.get("PATIENCE_NO_DOTENV") == "1":
        return
    path = path or os.environ.get("PATIENCE_DOTENV", ".env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass
