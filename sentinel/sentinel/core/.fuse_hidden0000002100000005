"""
sentinel/core/authorization.py
Target authorization / SSRF guard.

A scanner that will probe any host it's handed is an abuse vector: left open it
can be driven to attack arbitrary third parties or to reach internal-only
services (cloud metadata endpoints, intranet hosts, localhost daemons). Every
scan target is run through authorize_target() first, which:

  1. enforces an optional allowlist (only approved hosts/domains may be scanned);
  2. resolves the host and rejects private / loopback / link-local / reserved /
     multicast address space unless explicitly permitted via ALLOW_PRIVATE_TARGETS.
"""
from __future__ import annotations

import ipaddress
import socket

from sentinel.core.config import config


class TargetNotAuthorized(ValueError):
    """Raised when a scan target is not permitted by policy."""


def clean_host(target: str) -> str:
    """Reduce a user-supplied target to a bare host (no scheme, port or path)."""
    host = target.strip()
    host = host.removeprefix("https://").removeprefix("http://")
    host = host.split("/", 1)[0]           # drop any path
    host = host.split("@", 1)[-1]          # drop any userinfo
    # Strip a trailing :port, but leave bracketed IPv6 literals intact.
    if not host.startswith("[") and host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.strip("[]").lower()


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> treat as blocked
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local      # includes 169.254.169.254 cloud metadata
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _allowed_by_list(host: str) -> bool:
    """True if host equals, or is a subdomain of, an allowlisted entry."""
    allow = config.allowlist
    if not allow:
        return True  # empty allowlist == no restriction
    return any(host == a or host.endswith("." + a) for a in allow)


def _resolve(host: str) -> list[str]:
    """Resolve host to a list of IP strings. Empty list means resolution failed."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return list({info[4][0] for info in infos})


def authorize_target(target: str) -> str:
    """Validate a scan target against policy.

    Returns the cleaned host on success; raises TargetNotAuthorized otherwise.
    """
    host = clean_host(target)
    if not host:
        raise TargetNotAuthorized("Empty target.")

    if not _allowed_by_list(host):
        raise TargetNotAuthorized(
            f"Target '{host}' is not in TARGET_ALLOWLIST."
        )

    if config.allow_private_targets:
        return host  # operator has explicitly opted into internal scanning

    # Resolve and ensure no associated address is in disallowed space. If the
    # target is itself an IP literal, getaddrinfo returns it unchanged.
    ips = _resolve(host)
    if not ips:
        raise TargetNotAuthorized(f"Could not resolve target '{host}'.")

    for ip in ips:
        if _is_blocked_ip(ip):
            raise TargetNotAuthorized(
                f"Target '{host}' resolves to non-public address {ip}. "
                "Set ALLOW_PRIVATE_TARGETS=true to scan internal hosts."
            )
    return host
