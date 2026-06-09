"""
sentinel/llm/provider.py
Unified LLM interface — Ollama / Anthropic / OpenAI behind one call.
"""
from __future__ import annotations

import json
from typing import List, Optional

import httpx
from pydantic import BaseModel, ValidationError, field_validator

from sentinel.core.config import config

_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_RISK_LEVELS = {"low", "medium", "high", "critical"}

ANALYSIS_SYSTEM = """You are SENTINEL, an expert penetration tester and security analyst.
You analyze recon scan data and produce structured vulnerability findings.
Respond ONLY with valid JSON — no markdown fences, no preamble, no commentary.

Your JSON must follow this exact schema:
{
  "executive_summary": "2-3 sentence summary of the target's security posture",
  "risk_level": "low|medium|high|critical",
  "findings": [
    {
      "title": "short descriptive title",
      "description": "detailed explanation",
      "severity": "info|low|medium|high|critical",
      "module": "which scan module found this",
      "evidence": "raw evidence from scan data",
      "remediation": "specific actionable fix",
      "cvss_score": "numeric 0.0-10.0 or null"
    }
  ],
  "attack_surface": ["list", "of", "notable", "exposed", "services"],
  "recommendations": ["prioritized", "remediation", "steps"]
}"""

CHAT_SYSTEM = """You are SENTINEL, an expert AI penetration testing assistant.
You help security professionals understand scan results, plan attacks, and remediate vulnerabilities.
Be precise, technical, and actionable. Format code blocks with triple backticks."""


def _analysis_prompt(scan_data: dict) -> str:
    return (
        "Analyze this recon scan data and return structured findings:\n\n"
        + json.dumps(scan_data, indent=2)
    )


def _parse_json(raw: str) -> dict:
    """Parse a model's JSON reply, tolerating stray markdown fences."""
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1].removeprefix("json").strip()
    return json.loads(text)


class FindingSchema(BaseModel):
    """One vulnerability finding, coerced into the shape the app expects."""
    title: str = "Untitled Finding"
    description: Optional[str] = None
    severity: str = "info"
    module: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[str] = None

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_severity(cls, v: object) -> str:
        s = str(v).strip().lower()
        return s if s in _SEVERITIES else "info"

    @field_validator("cvss_score", mode="before")
    @classmethod
    def _str_cvss(cls, v: object) -> Optional[str]:
        return None if v is None else str(v)


class AnalysisSchema(BaseModel):
    """Full analysis payload returned by analyze(); fills/repairs missing fields."""
    executive_summary: str = ""
    risk_level: str = "low"
    findings: List[FindingSchema] = []
    attack_surface: List[str] = []
    recommendations: List[str] = []

    @field_validator("risk_level", mode="before")
    @classmethod
    def _norm_risk(cls, v: object) -> str:
        r = str(v).strip().lower()
        return r if r in _RISK_LEVELS else "low"


def _parse_analysis(raw: str) -> dict:
    """Parse and validate a model's analysis reply against the expected schema.

    The model is asked for a fixed schema but isn't guaranteed to honour it, so
    we coerce/repair the payload (defaulting missing fields, normalising bad
    severities) instead of trusting the raw JSON downstream.
    """
    data = _parse_json(raw)
    if not isinstance(data, dict):
        data = {}
    try:
        return AnalysisSchema.model_validate(data).model_dump()
    except ValidationError:
        # Last resort: return a valid-but-empty analysis that notes the problem.
        return AnalysisSchema(
            executive_summary="Model returned data that did not match the expected schema."
        ).model_dump()


class OllamaProvider:
    def __init__(self) -> None:
        self._base = config.ollama_base_url
        self._model = config.ollama_model

    def analyze(self, scan_data: dict) -> dict:
        r = httpx.post(f"{self._base}/api/chat", json={
            "model": self._model,
            "messages": [
                {"role": "system", "content": ANALYSIS_SYSTEM},
                {"role": "user",   "content": _analysis_prompt(scan_data)},
            ],
            "stream": False,
        }, timeout=120)
        return _parse_analysis(r.json()["message"]["content"])

    def chat(self, messages: list[dict]) -> str:
        full = [{"role": "system", "content": CHAT_SYSTEM}] + messages
        r = httpx.post(f"{self._base}/api/chat", json={
            "model": self._model, "messages": full, "stream": False,
        }, timeout=60)
        return r.json()["message"]["content"]


class AnthropicProvider:
    def __init__(self) -> None:
        import anthropic
        self._client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self._model  = config.anthropic_model

    def analyze(self, scan_data: dict) -> dict:
        r = self._client.messages.create(
            model=self._model, max_tokens=4096,
            system=ANALYSIS_SYSTEM,
            messages=[{"role": "user", "content": _analysis_prompt(scan_data)}],
        )
        return _parse_analysis(r.content[0].text)

    def chat(self, messages: list[dict]) -> str:
        r = self._client.messages.create(
            model=self._model, max_tokens=2048,
            system=CHAT_SYSTEM, messages=messages,
        )
        return r.content[0].text


class OpenAIProvider:
    def __init__(self) -> None:
        from openai import OpenAI
        self._client = OpenAI(api_key=config.openai_api_key)
        self._model  = config.openai_model

    def analyze(self, scan_data: dict) -> dict:
        r = self._client.chat.completions.create(
            model=self._model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": ANALYSIS_SYSTEM},
                {"role": "user",   "content": _analysis_prompt(scan_data)},
            ],
        )
        return _parse_analysis(r.choices[0].message.content)

    def chat(self, messages: list[dict]) -> str:
        full = [{"role": "system", "content": CHAT_SYSTEM}] + messages
        r = self._client.chat.completions.create(model=self._model, messages=full)
        return r.choices[0].message.content


_PROVIDERS = {
    "ollama":    OllamaProvider,
    "anthropic": AnthropicProvider,
    "openai":    OpenAIProvider,
}


def get_provider(backend: str | None = None):
    key = (backend or config.llm_backend).lower()
    cls = _PROVIDERS.get(key)
    if cls is None:
        raise ValueError(f"Unknown LLM backend '{key}'. Choose: {list(_PROVIDERS)}")
    return cls()
