"""
sentinel/modules/nmap_scanner.py
Wrapper around nmap — port scan, service/version detection.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NmapResult:
    target:     str
    open_ports: list[dict]    = field(default_factory=list)
    os_guess:   Optional[str] = None
    raw_output: str           = ""
    error:      Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target":     self.target,
            "open_ports": self.open_ports,
            "os_guess":   self.os_guess,
            "raw_output": self.raw_output,
            "error":      self.error,
        }


def run(target: str, fast: bool = False) -> NmapResult:
    if not shutil.which("nmap"):
        return NmapResult(target=target, error="nmap not found — install from https://nmap.org")
    args = ["nmap", "-T4", "--open"]
    if fast:
        args += ["-F"]
    else:
        args += ["-sV", "--version-intensity", "5", "-O", "--osscan-guess"]
    args.append(target)
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
        return _parse(target, proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired:
        return NmapResult(target=target, error="nmap timed out after 5 minutes")
    except Exception as exc:
        return NmapResult(target=target, error=str(exc))


_PORT_RE = re.compile(r"^(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?$", re.MULTILINE)
_OS_RE   = re.compile(r"OS details?:\s*(.+)", re.IGNORECASE)


def _parse(target: str, raw: str) -> NmapResult:
    ports = []
    for m in _PORT_RE.finditer(raw):
        ports.append({
            "port":     int(m.group(1)),
            "protocol": m.group(2),
            "service":  m.group(3),
            "version":  (m.group(4) or "").strip(),
        })
    os_match = _OS_RE.search(raw)
    return NmapResult(
        target=target,
        open_ports=ports,
        os_guess=os_match.group(1).strip() if os_match else None,
        raw_output=raw,
    )
