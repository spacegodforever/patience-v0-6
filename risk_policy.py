"""Policy-driven risk classifier for PATIENCE (v0.5).

Pipeline: normalize (lowercase, strip accents, number words, 1.8k) -> injection
scan -> split into clauses -> per clause: drop fillers, skip negated clauses,
read the lead verb (typo-corrected, stemmed). Read-only clauses are safe unless
they chain into an action verb. Other clauses are scored against the policy
categories. Unknown side-effect verbs fail safe to needs approval.
"""
from __future__ import annotations
import os
import re
import time
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
import yaml
try:
    from rapidfuzz.distance import OSA
except ImportError:  # dependency-light fallback
    OSA = None

DEFAULT_POLICY = Path(__file__).resolve().parent / "policies" / "default.yaml"


def stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s", "e"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


def strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


_UNITS = {w: i for i, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve "
          "thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split())}
_TENS = {w: 10 * i for i, w in enumerate("_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()) if w != "_"}
_SCALES = {"hundred": 100, "thousand": 1000, "million": 1_000_000}


def words_to_numbers(text: str) -> str:
    out, cur, total, active = [], 0, 0, False
    def flush():
        nonlocal cur, total, active
        if active:
            out.append(str(total + cur))
        cur, total, active = 0, 0, False
    for tok in text.split():
        t = tok.lower()
        if t in _UNITS: cur += _UNITS[t]; active = True
        elif t in _TENS: cur += _TENS[t]; active = True
        elif t in _SCALES and active:
            if _SCALES[t] == 100: cur *= 100
            else: total += cur * _SCALES[t]; cur = 0
        elif t in ("thousand", "million") and not active:
            total, active = _SCALES[t], True
        else:
            flush(); out.append(tok)
    flush()
    s = " ".join(out)
    s = re.sub(r"\b(\d+(?:\.\d+)?)\s?k\b", lambda m: f"{m.group(0)} {int(float(m.group(1)) * 1000)}", s)
    return re.sub(r"(\d),(\d{3})", r"\1\2", s)


class Policy:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or os.environ.get("PATIENCE_POLICY") or DEFAULT_POLICY)
        self.raw = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        r = self.raw
        th = r.get("thresholds", {})
        self.mass = int(th.get("mass_recipients", 10))
        self.default_consequence = float(th.get("default_consequence", .25))
        self.unknown_consequence = float(th.get("unknown_side_effect", .7))
        S = lambda xs: {stem(x) for x in xs}
        self.readonly = S(r.get("read_only_verbs", []))
        self.fillers = S(r.get("fillers", []))
        self.joiners = set(r.get("action_joiners", []))
        self.negations = [n.split() for n in r.get("negations", [])]
        self.side_effect = S(r.get("side_effect_verbs", []))
        self.injection = [re.compile(p, re.I) for p in r.get("injection_patterns", [])]
        c = r.get("communication", {})
        self.comm = S(c.get("verbs", []))
        self.broad = S(c.get("broad_words", []))
        self.audience = S(c.get("audience_nouns", []))
        self.categories: Dict[str, dict] = {}
        for name, spec in r.get("categories", {}).items():
            self.categories[name] = {
                "consequence": float(spec.get("consequence", .8)),
                "irreversible": bool(spec.get("irreversible", True)),
                "phrases": [tuple(stem(w) for w in tokens(k)) for k in spec.get("keywords", [])],
                "patterns": [re.compile(p) for p in spec.get("patterns", [])],
            }
        self.categories.setdefault("mass_communication", {"consequence": .85, "irreversible": True, "phrases": [], "patterns": []})
        self.categories.setdefault("communication", {"consequence": .75, "irreversible": True, "phrases": [], "patterns": []})
        self.categories.setdefault("unknown_side_effect", {"consequence": self.unknown_consequence, "irreversible": False, "phrases": [], "patterns": []})
        for extra_cat, cons, irr in (("budget_exceeded", .85, True), ("llm_disagreement", .75, False)):
            self.categories.setdefault(extra_cat, {"consequence": cons, "irreversible": irr, "phrases": [], "patterns": []})
        self.industries = {}
        for name, spec in (r.get("industries") or {}).items():
            self.industries[name] = {
                "detect": [tuple(stem(w) for w in tokens(k)) for k in spec.get("detect", [])],
                "extra": {cat: [tuple(stem(w) for w in tokens(k)) for k in kws] for cat, kws in (spec.get("extra") or {}).items()},
            }
        self.limits = r.get("limits", {}) or {}
        self.tools = r.get("tools", {}) or {}
        # Vocabulary for typo correction: every single policy word.
        vocab = set()
        for lst in (r.get("read_only_verbs", []), r.get("side_effect_verbs", []), c.get("verbs", []),
                    c.get("audience_nouns", []), c.get("broad_words", [])):
            vocab |= {w for w in lst if " " not in w}
        for spec in r.get("categories", {}).values():
            vocab |= {w for w in spec.get("keywords", []) if " " not in w}
        self.vocab = {w for w in vocab if len(w) >= 4}
        self.vocab_stems = {stem(w) for w in self.vocab}


def tokens(s: str) -> List[str]:
    s = strip_accents(s.lower()).replace("'", "").replace("’", "")
    return re.findall(r"[a-z0-9%$€£]+|[,;:.!?]", re.sub(r"(?<=[a-z])-(?=[a-z])", " ", s))


@lru_cache(maxsize=1)
def get_policy() -> Policy:
    return Policy()


def reload_policy():
    get_policy.cache_clear()
    return get_policy()


def _fix_typo(tok: str, p: Policy) -> str:
    if OSA is None or len(tok) < 4 or not tok.isalpha() or tok in p.vocab or stem(tok) in p.vocab_stems:
        return tok
    if any(tok.startswith(w) for w in p.vocab):  # inflected form of a known word
        return tok
    best, bd = tok, 99
    for w in p.vocab:
        if abs(len(w) - len(tok)) > 2:
            continue
        d = OSA.distance(tok, w)
        if d < bd:
            best, bd = w, d
    if len(tok) == 4:  # only transpositions for short words (sned->send, not lost->post)
        return best if bd == 1 and sorted(best) == sorted(tok) else tok
    limit = 1 if len(tok) <= 6 else 2
    return best if bd <= limit else tok


def _contains(seq: Tuple[str, ...], phrase: Tuple[str, ...]) -> bool:
    n = len(phrase)
    return n > 0 and any(seq[i:i + n] == phrase for i in range(len(seq) - n + 1))


CLAUSE_SPLIT = re.compile(r"[,;:.!?]|\b(?:and then|then|but|after that|and|plus|also)\b")


class Classification(dict):
    pass


def classify(text: str, tags: Iterable[str] = (), policy: Optional[Policy] = None) -> dict:
    p = policy or get_policy()
    raw = strip_accents(text.lower())
    flags: List[str] = []
    cats: Set[str] = set()
    injected = any(rx.search(raw) for rx in p.injection)
    if injected:
        cats.add("injection"); flags.append("injection")
    norm = words_to_numbers(raw.replace("[demo]", " "))
    toks_all = [_fix_typo(t, p) for t in tokens(norm)]
    corrected = [(a, b) for a, b in zip(tokens(norm), toks_all) if a != b]
    stems_all = tuple(stem(t) for t in toks_all)
    # active industries
    active = {t.split(":", 1)[1] for t in tags if isinstance(t, str) and t.startswith("industry:")}
    for name, spec in p.industries.items():
        if any(_contains(stems_all, ph) for ph in spec["detect"]):
            active.add(name)
    extra: Dict[str, list] = {}
    for name in active:
        for cat, phs in p.industries.get(name, {}).get("extra", {}).items():
            extra.setdefault(cat, []).extend(phs)
    # clauses
    text_fixed = " ".join(toks_all)
    clauses = [c.strip() for c in CLAUSE_SPLIT.split(text_fixed) if c and c.strip()]
    readonly_clauses = 0
    for cl in clauses:
        tk = cl.split()
        # negation check before stripping fillers
        while tk and stem(tk[0]) in p.fillers and tk[0] not in ("not", "no"):
            tk = tk[1:]
        neg = next((n for n in p.negations if tk[:len(n)] == n), None)
        if neg is not None:
            rest = tk[len(neg):]
            # "don't send X" is safe; "don't forget to delete X" chains into a real action.
            def act(i):
                w = stem(rest[i])
                return w in p.side_effect or w in p.comm or bool(
                    _score_clause(tuple(stem(x) for x in rest[i:]), " ".join(rest[i:]), p, extra))
            idx = next((i for i in range(1, len(rest)) if rest[i - 1] in p.joiners and act(i)), None)
            if idx is None:
                continue
            tk = rest[idx:]
        tk = [t for t in tk if not t.isdigit()] if tk and tk[0] == "step" else tk
        while tk and (stem(tk[0]) in p.fillers or tk[0].isdigit()):
            tk = tk[1:]
        if not tk:
            continue
        st = tuple(stem(t) for t in tk)
        lead = st[0]
        if lead in p.readonly and lead not in p.side_effect:
            readonly_clauses += 1
            # chained action inside a read-only clause: "... to send it"
            for i in range(1, len(st)):
                if tk[i - 1] in p.joiners and (st[i] in p.side_effect or st[i] in p.comm):
                    # treat the rest as its own clause
                    sub = _score_clause(st[i:], raw, p, extra)
                    cats |= sub or {"unknown_side_effect"}
                    break
            continue
        sub = _score_clause(st, cl, p, extra)
        if sub:
            cats |= sub
        elif lead in p.side_effect or lead in p.comm:
            cats.add("unknown_side_effect")
    if "unknown_side_effect" in cats:
        # "summarize refunds, then issue the missing ones": the object lives in another clause
        cats |= _score_clause(stems_all, norm, p, extra) - {"communication", "mass_communication"}
    if len(cats) > 1:
        cats.discard("unknown_side_effect")
    if "mass_communication" in cats:
        cats.discard("communication")
    consequence = max([p.categories[c]["consequence"] for c in cats] or [p.default_consequence])
    irreversible = any(p.categories[c]["irreversible"] for c in cats)
    order = list(p.categories)
    return {"categories": sorted(cats, key=lambda c: order.index(c) if c in order else 99),
            "consequence": consequence, "irreversible": irreversible, "flags": flags,
            "industries": sorted(active), "typos_corrected": corrected,
            "read_only": bool(clauses) and readonly_clauses == len(clauses) and not cats}


def _score_clause(st: Tuple[str, ...], text: str, p: Policy, extra: Dict[str, list]) -> Set[str]:
    cats = set()
    joined = " ".join(st)
    for name, spec in p.categories.items():
        if any(_contains(st, ph) for ph in spec["phrases"]) or any(_contains(st, ph) for ph in extra.get(name, [])):
            cats.add(name)
        elif any(rx.search(text) for rx in spec["patterns"]):
            cats.add(name)
    if any(s in p.comm for s in st):
        nums = [int(x) for x in re.findall(r"\b\d+\b", joined)]
        broad = any(s in p.broad for s in st)
        big = any(n >= p.mass for n in nums) and any(s in p.audience for s in st)
        cats.add("mass_communication" if broad or big else "communication")
    elif any(s in p.broad for s in ("every", "everyone", "everybody")) and False:
        pass
    return cats


# ---------------------------------------------------------------------------
# Phase 2a: structured tool calls scored from their real arguments.
def _num(v, default=0.0) -> float:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        m = re.search(r"\d+(?:\.\d+)?", words_to_numbers(v.lower()).replace("$", ""))
        if m:
            n = float(m.group(0))
            return n * 1000 if re.search(r"\d\s?k\b", v.lower()) else n
    return default


def tool_usage(tool: str, args: dict, policy: Optional[Policy] = None) -> dict:
    """Quantities a call consumes, for the rolling budgets."""
    p = policy or get_policy()
    spec = p.tools.get(tool, {}) or {}
    args = args or {}
    out = {}
    if spec.get("recipients_arg"):
        r = args.get(spec["recipients_arg"])
        out["recipients"] = len(r) if isinstance(r, (list, tuple, set)) else (
            len([x for x in re.split(r"[,;\s]+", r) if x]) if isinstance(r, str) and "@" in r else _num(r, 1))
    count = _num(args.get(spec.get("count_arg", "count")), 1) if spec.get("count_arg") else 1
    out["count"] = count
    if spec.get("amount_arg"):
        out["amount_total"] = _num(args.get(spec["amount_arg"])) * count
    return out


def score_tool(tool: str, args: dict, policy: Optional[Policy] = None) -> dict:
    p = policy or get_policy()
    tool = (tool or "").strip().lower()
    args = args or {}
    spec = p.tools.get(tool)
    reasons: List[str] = []
    if spec is None:
        if any(tool.startswith(x) for x in p.raw.get("read_only_tool_prefixes", [])):
            return {"categories": [], "consequence": p.default_consequence, "irreversible": False,
                    "reasons": [f"{tool} is read-only"], "usage": {}}
        return {"categories": ["unknown_side_effect"], "consequence": p.unknown_consequence, "irreversible": False,
                "reasons": [f"unknown tool '{tool}' (fail-safe)"], "usage": {}}
    usage = tool_usage(tool, args, p)
    cat = spec.get("category", "unknown_side_effect")
    if cat == "communication" and usage.get("recipients", 0) >= p.mass:
        cat = "mass_communication"
    auto = spec.get("auto_allow") or {}
    ok = bool(auto)
    if "max_recipients" in auto:
        ok &= usage.get("recipients", 0) <= auto["max_recipients"]
        if not ok: reasons.append(f"{usage.get('recipients')} recipients > {auto['max_recipients']}")
    if "max_total" in auto:
        if usage.get("amount_total", 0) > auto["max_total"]:
            ok = False; reasons.append(f"total ${usage['amount_total']:,.0f} > ${auto['max_total']:,}")
    # args can smuggle risk too (body text, channel names, SQL)
    text_args = " ".join(str(v) for v in args.values() if isinstance(v, str))
    text_risk = classify(text_args) if text_args else {"categories": [], "flags": []}
    extra = [c for c in text_risk["categories"] if c in ("injection", "pii_sensitive", "security", "legal")]
    cats = sorted(set(([] if ok else [cat]) + extra))
    if ok and not extra:
        reasons.append(f"{tool} within auto-allow limits")
    if extra:
        reasons.append("arguments contain " + ", ".join(extra))
    c = p.categories.get(cat, {"consequence": .8, "irreversible": True})
    return {"categories": cats, "consequence": max([p.categories[x]["consequence"] for x in cats if x in p.categories] or [p.default_consequence]),
            "irreversible": any(p.categories.get(x, c)["irreversible"] for x in cats),
            "reasons": reasons, "usage": usage}


# Phase 2b: rolling per-requester budgets.
def check_budgets(usage_log: List[dict], requester: str, tool: str, usage: dict,
                  now: float, policy: Optional[Policy] = None) -> List[str]:
    """Return the names of limits this call would cross. usage_log entries:
    {requester, tool, ts, usage:{...}}."""
    p = policy or get_policy()
    crossed = []
    for name, lim in p.limits.items():
        tools = lim.get("tools", [])
        if tool not in tools and "*" not in tools:
            continue
        metric, mx, win = lim["metric"], float(lim["max"]), float(lim["window_seconds"])
        used = sum(e["usage"].get(metric, 0) for e in usage_log
                   if e.get("requester") == requester and ("*" in tools or e.get("tool") in tools) and now - e["ts"] < win)
        if used + usage.get(metric, 0) > mx:
            crossed.append(f"{name}: {used:g} used + {usage.get(metric, 0):g} > {mx:g}")
    return crossed


def prune_usage(usage_log: List[dict], now: float, policy: Optional[Policy] = None) -> List[dict]:
    p = policy or get_policy()
    longest = max([float(l["window_seconds"]) for l in p.limits.values()] or [0])
    return [e for e in usage_log if now - e["ts"] < longest]


def now() -> float:
    """Clock used for budgets (patched in tests)."""
    return time.time()


def text_usage(text: str, categories: Iterable[str]) -> dict:
    """Best-effort quantities for a free-text check so text calls count toward budgets too."""
    cats = set(categories)
    norm = words_to_numbers(strip_accents(text.lower()))
    out = {"count": 1}
    if "money" in cats:
        amts = [float(x.replace(",", "")) for x in re.findall(r"[$€£]\s?(\d[\d,]*(?:\.\d+)?)", norm)]
        amts += [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s?(?:dollars|usd|eur|euros)", norm)]
        if amts:
            out["amount_total"] = max(amts)
    if cats & {"communication", "mass_communication"}:
        nums = [int(x) for x in re.findall(r"\b\d+\b", norm)]
        out["recipients"] = max(nums) if nums else (get_policy().mass if "mass_communication" in cats else 1)
    return out
