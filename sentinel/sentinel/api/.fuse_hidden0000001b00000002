"""
sentinel/api/security.py
API authentication and rate limiting helpers.

Authentication is optional and off by default: when SENTINEL_API_KEY is unset,
the API behaves exactly as before (frictionless local dev). When it is set,
every /api/* request except the health check must present the key. Keys are
compared with secrets.compare_digest to avoid timing leaks.

The rate limiter is a small in-process fixed-window counter keyed by client IP —
enough to blunt scan-spamming on a single-node deployment. (A multi-node setup
would back this with Redis.)
"""
from __future__ import annotations

import secrets
import threading
import time

from sentinel.core.config import config


def extract_api_key(headers) -> str | None:
    """Pull the key from 'X-API-Key' or 'Authorization: Bearer <key>'."""
    key = headers.get("X-API-Key")
    if key:
        return key.strip()
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def api_key_valid(provided: str | None) -> bool:
    """True if auth is disabled, or the provided key matches the configured one."""
    expected = config.api_key
    if not expected:
        return True  # auth disabled
    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


class RateLimiter:
    """Thread-safe fixed-window rate limiter (requests per 60s per client)."""

    def __init__(self, limit_per_minute: int) -> None:
        self._limit = max(0, limit_per_minute)
        self._lock = threading.Lock()
        self._hits: dict[str, tuple[int, int]] = {}  # client -> (window_start, count)

    def allow(self, client_id: str, *, now: float | None = None) -> bool:
        if self._limit <= 0:
            return True  # 0 or negative == unlimited
        window = int((now if now is not None else time.time()) // 60)
        with self._lock:
            start, count = self._hits.get(client_id, (window, 0))
            if start != window:
                start, count = window, 0
            if count >= self._limit:
                self._hits[client_id] = (start, count)
                return False
            self._hits[client_id] = (start, count + 1)
            return True
