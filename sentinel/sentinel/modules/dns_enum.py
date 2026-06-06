"""
sentinel/modules/dns_enum.py
DNS enumeration — A, MX, NS, TXT, SOA, CNAME + subdomain brute-force.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.reversename

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote",
    "api", "dev", "staging", "test", "admin", "portal", "dashboard",
    "ns1", "ns2", "mx", "mx1", "mx2", "autodiscover", "webmail",
    "cpanel", "git", "gitlab", "jenkins", "jira", "cdn", "static",
]


@dataclass
class DNSResult:
    domain:     str
    records:    dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str]            = field(default_factory=list)
    ip_address: Optional[str]        = None
    error:      Optional[str]        = None

    def to_dict(self) -> dict:
        return {
            "domain":     self.domain,
            "records":    self.records,
            "subdomains": self.subdomains,
            "ip_address": self.ip_address,
            "error":      self.error,
        }


def run(domain: str, brute_force: bool = True) -> DNSResult:
    result = DNSResult(domain=domain)
    try:
        result.ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        pass

    resolver          = dns.resolver.Resolver()
    resolver.timeout  = 3
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            result.records[rtype] = [str(r) for r in answers]
        except Exception:
            pass

    if brute_force:
        found = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                resolver.resolve(fqdn, "A")
                found.append(fqdn)
            except Exception:
                pass
        result.subdomains = found

    return result
