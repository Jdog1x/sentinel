"""
sentinel/modules/whois_lookup.py
WHOIS registration data.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import whois


@dataclass
class WhoisResult:
    target:        str
    registrar:     Optional[str]  = None
    creation_date: Optional[str]  = None
    expiry_date:   Optional[str]  = None
    name_servers:  list[str]      = field(default_factory=list)
    emails:        list[str]      = field(default_factory=list)
    org:           Optional[str]  = None
    country:       Optional[str]  = None
    error:         Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "target":        self.target,
            "registrar":     self.registrar,
            "creation_date": self.creation_date,
            "expiry_date":   self.expiry_date,
            "name_servers":  self.name_servers,
            "emails":        self.emails,
            "org":           self.org,
            "country":       self.country,
            "error":         self.error,
        }


def _str(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0]
    return str(val)


def run(target: str) -> WhoisResult:
    domain = target.removeprefix("https://").removeprefix("http://").split("/")[0]
    try:
        w = whois.whois(domain)
        return WhoisResult(
            target=target,
            registrar=_str(w.registrar),
            creation_date=_str(w.creation_date),
            expiry_date=_str(w.expiration_date),
            name_servers=[ns.lower() for ns in (w.name_servers or []) if isinstance(ns, str)],
            emails=list(w.emails) if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
            org=_str(w.org),
            country=_str(w.country),
        )
    except Exception as exc:
        return WhoisResult(target=target, error=str(exc))
