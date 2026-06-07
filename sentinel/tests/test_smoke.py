"""Smoke tests covering the pure-logic pieces of SENTINEL (no network required)."""
from __future__ import annotations

import pytest

from sentinel.core.scanner import _map_severity
from sentinel.core.models import Severity
from sentinel.llm.provider import _parse_json, get_provider
from sentinel.modules import nmap_scanner


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("info", Severity.INFO),
        ("LOW", Severity.LOW),
        ("Medium", Severity.MEDIUM),
        ("high", Severity.HIGH),
        ("critical", Severity.CRITICAL),
        ("nonsense", Severity.INFO),  # unknown values fall back to INFO
    ],
)
def test_map_severity(raw, expected):
    assert _map_severity(raw) is expected


def test_parse_json_strips_markdown_fences():
    assert _parse_json('```json\n{"ok": true}\n```') == {"ok": True}
    assert _parse_json('{"ok": true}') == {"ok": True}


def test_get_provider_rejects_unknown_backend():
    with pytest.raises(ValueError):
        get_provider("does-not-exist")


def test_nmap_parser_extracts_open_ports():
    sample = "22/tcp open ssh OpenSSH 8.9p1\n80/tcp open http nginx 1.18.0\n"
    result = nmap_scanner._parse("example.com", sample)
    ports = {p["port"]: p["service"] for p in result.open_ports}
    assert ports == {22: "ssh", 80: "http"}
