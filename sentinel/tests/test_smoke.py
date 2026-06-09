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


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
  </host>
</nmaprun>"""


def test_nmap_xml_parser_extracts_open_ports():
    result = nmap_scanner._parse_xml("example.com", _NMAP_XML)
    ports = {p["port"]: p["service"] for p in result.open_ports}
    assert ports == {22: "ssh", 80: "http"}        # closed 443 excluded
    assert result.os_guess == "Linux 5.X"
    by_port = {p["port"]: p["version"] for p in result.open_ports}
    assert by_port[22] == "OpenSSH 8.9p1"


def test_nmap_xml_parser_handles_garbage():
    # Non-XML output must surface an error, not crash the scan.
    result = nmap_scanner._parse_xml("example.com", "not xml at all")
    assert result.error is not None
    assert result.open_ports == []


# --- target authorization (SSRF guard) -------------------------------------

def test_authorize_rejects_private_and_loopback():
    from sentinel.core.authorization import TargetNotAuthorized, authorize_target
    for bad in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254"]:
        with pytest.raises(TargetNotAuthorized):
            authorize_target(bad)


def test_authorize_allows_public_ip_literal():
    from sentinel.core.authorization import authorize_target
    # A public IP literal needs no DNS and should pass the address check.
    assert authorize_target("1.1.1.1") == "1.1.1.1"


def test_authorize_cleans_host_from_url():
    from sentinel.core.authorization import clean_host
    assert clean_host("https://Example.com:8443/path?x=1") == "example.com"


def test_authorize_respects_allowlist(monkeypatch):
    from sentinel.core import authorization
    from sentinel.core.config import config
    monkeypatch.setattr(config, "target_allowlist", "example.com")
    with pytest.raises(authorization.TargetNotAuthorized):
        authorization.authorize_target("evil.com")
    # subdomains of an allowlisted domain are permitted
    assert authorization._allowed_by_list("api.example.com") is True
    assert authorization._allowed_by_list("evil.com") is False


# --- API auth + rate limiting ----------------------------------------------

def test_api_key_validation():
    from sentinel.api import security
    from sentinel.core.config import config
    # Auth disabled when no key configured.
    config.api_key = ""
    assert security.api_key_valid(None) is True
    # Auth enforced when configured.
    config.api_key = "s3cret"
    assert security.api_key_valid("s3cret") is True
    assert security.api_key_valid("wrong") is False
    assert security.api_key_valid(None) is False
    config.api_key = ""


def test_extract_api_key_from_headers():
    from sentinel.api.security import extract_api_key
    assert extract_api_key({"X-API-Key": "abc"}) == "abc"
    assert extract_api_key({"Authorization": "Bearer xyz"}) == "xyz"
    assert extract_api_key({}) is None


def test_rate_limiter_blocks_after_limit():
    from sentinel.api.security import RateLimiter
    rl = RateLimiter(limit_per_minute=2)
    assert rl.allow("ip", now=0) is True
    assert rl.allow("ip", now=0) is True
    assert rl.allow("ip", now=0) is False      # third in same window blocked
    assert rl.allow("ip", now=61) is True       # next window resets
