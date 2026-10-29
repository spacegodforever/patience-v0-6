"""Run every labeled case through the engine and /v1/check and print metrics.
Usage: python tests/eval_governance.py [--misses]"""
from __future__ import annotations
import os, sys, tempfile
from collections import defaultdict
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CASES = yaml.safe_load((ROOT / "tests/cases/governance_cases.yaml").read_text(encoding="utf-8"))["cases"]


def engine_decision(text, state):
    from engine import Patience
    out = Patience(state).cycle(text, source="eval")
    ok = out["verification"]["verified"] and not out["decision"]["requires_authorization"]
    return ("allow" if ok else "needs_approval"), out["assessment"].get("risk_categories", [])


def api_client(state):
    os.environ["PATIENCE_STATE_PATH"] = state
    for v in ("PATIENCE_API_TOKEN", "PATIENCE_LLM_API_KEY"):
        os.environ.pop(v, None)
    from fastapi.testclient import TestClient
    import api
    return TestClient(api.app)


def api_decision(client, text):
    r = client.post("/v1/check", json={"action": text, "requester": "eval"}).json()
    return ("allow" if r["decision"] == "allow" else "needs_approval"), r["risk_categories"]


def metrics(rows):
    tp = sum(1 for e, g in rows if e == g == "needs_approval")
    fp = sum(1 for e, g in rows if e == "allow" and g == "needs_approval")
    fn = sum(1 for e, g in rows if e == "needs_approval" and g == "allow")
    tn = sum(1 for e, g in rows if e == g == "allow")
    return {"precision": tp / (tp + fp) if tp + fp else 1.0, "recall": tp / (tp + fn) if tp + fn else 1.0,
            "benign_allowed": tn / (tn + fp) if tn + fp else 1.0, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def run():
    res = {}
    with tempfile.TemporaryDirectory() as d:
        eng, ap, misses, catmiss = [], [], [], []
        client = api_client(os.path.join(d, "api.json"))
        for i, c in enumerate(CASES):
            g, cats = engine_decision(c["action"], os.path.join(d, f"e{i}.json"))
            a, _ = api_decision(client, c["action"])
            eng.append((c["expected"], g)); ap.append((c["expected"], a))
            if g != c["expected"] or a != c["expected"]:
                misses.append((c["tag"], c["expected"], g, a, c["action"]))
            elif c["expected"] == "needs_approval" and c["categories"] and not set(c["categories"]) & set(cats):
                catmiss.append((c["tag"], c["categories"], cats, c["action"]))
        res = {"engine": metrics(eng), "api": metrics(ap), "misses": misses, "category_misses": catmiss}
    return res


if __name__ == "__main__":
    r = run()
    for k in ("engine", "api"):
        m = r[k]
        print(f"{k:6}  precision={m['precision']:.3f}  recall={m['recall']:.3f}  benign_allowed={m['benign_allowed']:.3f}  "
              f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
    print("decision misses:", len(r["misses"]), " category misses:", len(r["category_misses"]))
    if "--misses" in sys.argv:
        for m in r["misses"]:
            print("  MISS", m)
        for m in r["category_misses"]:
            print("  CAT ", m)
