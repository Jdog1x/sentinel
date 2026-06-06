"""
sentinel/llm/provider.py
Unified LLM interface — Ollama / Anthropic / OpenAI behind one call.
"""
from __future__ import annotations

import json
from sentinel.core.config import config

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


class OllamaProvider:
    def __init__(self) -> None:
        import httpx
        self._base = config.ollama_base_url
        self._model = config.ollama_model

    def analyze(self, scan_data: dict) -> dict:
        import httpx
        prompt = f"Analyze this recon scan data and return structured findings:\n\n{json.dumps(scan_data, indent=2)}"
        r = httpx.post(f"{self._base}/api/chat", json={
            "model": self._model,
            "messages": [
                {"role": "system", "content": ANALYSIS_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            "stream": False,
        }, timeout=120)
        raw = r.json()["message"]["content"]
        return json.loads(raw)

    def chat(self, messages: list[dict]) -> str:
        import httpx
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
        prompt = f"Analyze this recon scan data and return structured findings:\n\n{json.dumps(scan_data, indent=2)}"
        r = self._client.messages.create(
            model=self._model, max_tokens=4096,
            system=ANALYSIS_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return json.loads(r.content[0].text)

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
        prompt = f"Analyze this recon scan data and return structured findings:\n\n{json.dumps(scan_data, indent=2)}"
        r = self._client.chat.completions.create(
            model=self._model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": ANALYSIS_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
        )
        return json.loads(r.choices[0].message.content)

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
