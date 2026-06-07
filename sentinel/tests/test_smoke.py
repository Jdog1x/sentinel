"""Smoke tests covering the pure-logic pieces of SENTINEL (no network required)."""
from __future__ import annotations

import pytest

from sentinel.core.scanner import _map_severity
from sentinel.core.models import Severity
from sentinel.llm.provider import _parse_analysis, _parse_json, get_provider
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


def test_parse_analysis_coerces_malformed_output():
    # Missing fields are filled, bad severity/risk normalised, cvss stringified.
    raw = '{"risk_level": "SEVERE", "findings": [{"severity": "boom", "cvss_score": 7.5}]}'
    out = _parse_analysis(raw)
    assert out["risk_level"] == "low"            # unknown risk -> default
    assert out["executive_summary"] == ""        # missing -> default
    assert out["attack_surface"] == []           # missing list -> default
    finding = out["findings"][0]
    assert finding["severity"] == "info"         # unknown severity -> info
    assert finding["cvss_score"] == "7.5"        # number -> string
    assert finding["title"] == "Untitled Finding"


def test_parse_analysis_handles_non_dict_json():
    # A bare JSON array (not the expected object) must not crash the scan.
    out = _parse_analysis("[1, 2, 3]")
    assert out["findings"] == []
    assert out["risk_level"] in {"low", "medium", "high", "critical"}


def test_nmap_parser_extracts_open_ports():
    sample = "22/tcp open ssh OpenSSH 8.9p1\n80/tcp open http nginx 1.18.0\n"
    result = nmap_scanner._parse("example.com", sample)
    ports = {p["port"]: p["service"] for p in result.open_ports}
    assert ports == {22: "ssh", 80: "http"}
