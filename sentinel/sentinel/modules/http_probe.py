"""
sentinel/modules/http_probe.py
HTTP/HTTPS fingerprinting — headers, security audit, tech detection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from sentinel.core.config import config

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

INTERESTING_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin", "/login", "/wp-login.php", "/phpmyadmin",
    "/api", "/api/v1", "/swagger", "/swagger-ui.html",
    "/.git/HEAD", "/.env", "/server-status",
]

TECH_SIGNATURES = [
    (r"WordPress",     "WordPress"),
    (r"Drupal",        "Drupal"),
    (r"Joomla",        "Joomla"),
    (r"Django",        "Django"),
    (r"Laravel",       "Laravel"),
    (r"nginx",         "nginx"),
    (r"Apache",        "Apache"),
    (r"Microsoft-IIS", "IIS"),
    (r"Cloudflare",    "Cloudflare"),
]


@dataclass
class HTTPResult:
    target:                   str
    url:                      str           = ""
    status_code:              Optional[int] = None
    server:                   Optional[str] = None
    headers:                  dict          = field(default_factory=dict)
    missing_security_headers: list[str]     = field(default_factory=list)
    detected_technologies:    list[str]     = field(default_factory=list)
    interesting_paths:        list[dict]    = field(default_factory=list)
    redirect_chain:           list[str]     = field(default_factory=list)
    error:                    Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target":                   self.target,
            "url":                      self.url,
            "status_code":              self.status_code,
            "server":                   self.server,
            "headers":                  self.headers,
            "missing_security_headers": self.missing_security_headers,
            "detected_technologies":    self.detected_technologies,
            "interesting_paths":        self.interesting_paths,
            "redirect_chain":           self.redirect_chain,
            "error":                    self.error,
        }


def run(target: str) -> HTTPResult:
    if not target.startswith(("http://", "https://")):
        target_url = f"https://{target}"
    else:
        target_url = target

    result = HTTPResult(target=target, url=target_url)

    try:
        # TLS verification is off by default (HTTP_VERIFY_TLS): recon often
        # targets hosts with self-signed or expired certs that we still want
        # to fingerprint. Enable verification via the env var when appropriate.
        with httpx.Client(timeout=10, follow_redirects=True,
                          verify=config.http_verify_tls,
                          headers={"User-Agent": "Sentinel/1.0 Security Scanner"}) as client:
            resp = client.get(target_url)
            result.status_code  = resp.status_code
            result.headers      = dict(resp.headers)
            result.server       = resp.headers.get("server")
            result.redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

            body = resp.text[:4096]
            combined = " ".join(resp.headers.values()) + " " + body

            for hdr in SECURITY_HEADERS:
                if hdr.lower() not in {k.lower() for k in resp.headers}:
                    result.missing_security_headers.append(hdr)

            for pattern, label in TECH_SIGNATURES:
                if re.search(pattern, combined, re.IGNORECASE):
                    result.detected_technologies.append(label)

            for path in INTERESTING_PATHS:
                base = f"{resp.url.scheme}://{resp.url.host}"
                try:
                    pr = client.get(base + path)
                    if pr.status_code not in (404, 403, 410):
                        result.interesting_paths.append({
                            "path": path, "status": pr.status_code, "size": len(pr.content)
                        })
                except Exception:
                    pass
    except Exception as exc:
        result.error = str(exc)

    return result
