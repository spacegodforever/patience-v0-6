"""PATIENCE LLM adapter (v0.5).

Sends a structured assessment or trigger prompt to any OpenAI-compatible
chat API (xAI Grok, OpenAI, OpenRouter, a local LM Studio/Ollama server).
The model is ADVISORY ONLY: it returns a vote; the Governance Gate decides.

Config (environment variables, never commit keys):
  PATIENCE_LLM_API_KEY   required
  PATIENCE_LLM_BASE_URL  default https://api.x.ai/v1
  PATIENCE_LLM_MODEL     default grok-4-fast  (set to your provider's model)
"""
from __future__ import annotations
import json
import os
import urllib.request
from dataclasses import asdict
from models import Assessment, ModelVote
from adapters import BaseModelAdapter

ALLOWED = {"respond", "research", "prototype", "human_review"}

SYSTEM = (
    "You are an advisory member of the PATIENCE model council. "
    "You never execute actions and never bypass authorization gates. "
    "Reply ONLY with JSON: {\"recommendation\": one of "
    "[respond, research, prototype, human_review], \"confidence\": 0-1, "
    "\"reasoning_summary\": short string, \"dissent\": string or null}."
)


def chat(messages, temperature=0.2, timeout=60):
    key = os.environ.get("PATIENCE_LLM_API_KEY")
    if not key:
        raise RuntimeError("PATIENCE_LLM_API_KEY is not set")
    base = os.environ.get("PATIENCE_LLM_BASE_URL", "https://api.x.ai/v1").rstrip("/")
    model = os.environ.get("PATIENCE_LLM_MODEL", "grok-4-fast")
    body = json.dumps({"model": model, "messages": messages,
                       "temperature": temperature}).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions", data=body,
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    return data["choices"][0]["message"]["content"]


def _parse_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").split("\n", 1)[-1]
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])


class LLMAdapter(BaseModelAdapter):
    name = "llm"

    def __init__(self):
        self.name = "llm:" + os.environ.get("PATIENCE_LLM_MODEL", "grok-4-fast")

    def vote(self, a: Assessment) -> ModelVote:
        try:
            out = _parse_json(chat([
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": "Assessment:\n" + json.dumps(asdict(a), indent=2)},
            ]))
            rec = out.get("recommendation")
            if rec not in ALLOWED:
                rec = "human_review"  # fail safe
            conf = max(0.0, min(1.0, float(out.get("confidence", 0.5))))
            return ModelVote(self.name, rec, conf,
                             str(out.get("reasoning_summary", ""))[:500],
                             out.get("dissent"))
        except Exception as e:  # network/parse failure never grants authority
            return ModelVote(self.name, "human_review", 0.2,
                             f"LLM unavailable, defaulting to human review: {e}")


def llm_enabled():
    return bool(os.environ.get("PATIENCE_LLM_API_KEY"))
