"""
sentinel/core/config.py
Centralised configuration — reads .env, validates, exposes typed settings.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_ROOT / ".env", override=False)


class SentinelConfig(BaseModel):
    llm_backend: Literal["ollama", "anthropic", "openai"] = Field(
        default_factory=lambda: os.getenv("LLM_BACKEND", "ollama")
    )
    ollama_base_url: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    ollama_model: str = Field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.2")
    )
    anthropic_api_key: str = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    anthropic_model: str = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    )
    openai_api_key: str = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    openai_model: str = Field(
        default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o")
    )
    flask_secret_key: str = Field(
        default_factory=lambda: os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
    )
    flask_debug: bool = Field(
        default_factory=lambda: os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )
    database_url: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///sentinel.db")
    )
    redis_url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    report_output_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("REPORT_OUTPUT_DIR", "./reports"))
    )

    @field_validator("report_output_dir", mode="before")
    @classmethod
    def _ensure_dir(cls, v: str | Path) -> Path:
        p = Path(v)
        p.mkdir(parents=True, exist_ok=True)
        return p


config = SentinelConfig()
