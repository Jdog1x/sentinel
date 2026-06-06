"""
sentinel/core/scanner.py
Scan orchestrator — chains modules, stores results, calls LLM analysis.
"""
from __future__ import annotations

import traceback
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from sentinel.core.models import Finding, Scan, ScanStatus, Severity, SessionLocal, init_db
from sentinel.llm.provider import get_provider
from sentinel.modules import dns_enum, http_probe, nmap_scanner, whois_lookup

console = Console()


class ScanOrchestrator:
    def __init__(self, llm_backend: Optional[str] = None):
        self.llm_backend = llm_backend
        init_db()

    def run_scan(self, target: str, fast: bool = False) -> Scan:
        db   = SessionLocal()
        scan = Scan(target=target, status=ScanStatus.RUNNING, llm_backend=self.llm_backend)
        db.add(scan)
        db.commit()
        db.refresh(scan)

        raw: dict = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:

            t = progress.add_task("WHOIS lookup...", total=None)
            try:
                raw["whois"] = whois_lookup.run(target).to_dict()
            except Exception:
                raw["whois"] = {"error": traceback.format_exc()}
            progress.update(t, description="[green]WHOIS done")

            t = progress.add_task("DNS enumeration...", total=None)
            try:
                raw["dns"] = dns_enum.run(target).to_dict()
            except Exception:
                raw["dns"] = {"error": traceback.format_exc()}
            progress.update(t, description="[green]DNS done")

            t = progress.add_task("Port scanning (nmap)...", total=None)
            try:
                raw["nmap"] = nmap_scanner.run(target, fast=fast).to_dict()
            except Exception:
                raw["nmap"] = {"error": traceback.format_exc()}
            progress.update(t, description="[green]Nmap done")

            t = progress.add_task("HTTP fingerprinting...", total=None)
            try:
                raw["http"] = http_probe.run(target).to_dict()
            except Exception:
                raw["http"] = {"error": traceback.format_exc()}
            progress.update(t, description="[green]HTTP done")

            t = progress.add_task("AI analysis...", total=None)
            scan.status      = ScanStatus.ANALYZING
            scan.raw_results = raw
            db.commit()

            try:
                provider = get_provider(self.llm_backend)
                analysis = provider.analyze(raw)
                for f in analysis.get("findings", []):
                    finding = Finding(
                        scan_id=scan.id,
                        title=f.get("title", "Untitled Finding"),
                        description=f.get("description"),
                        severity=_map_severity(f.get("severity", "info")),
                        module=f.get("module"),
                        evidence=f.get("evidence"),
                        remediation=f.get("remediation"),
                        cvss_score=str(f.get("cvss_score")) if f.get("cvss_score") else None,
                    )
                    db.add(finding)
                raw["analysis"] = analysis
            except Exception:
                raw["analysis"] = {"error": traceback.format_exc()}

            progress.update(t, description="[green]AI analysis done")

        scan.status      = ScanStatus.COMPLETE
        scan.raw_results = raw
        scan.updated_at  = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        db.close()
        return scan

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        db   = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        db.close()
        return scan

    def list_scans(self) -> list[Scan]:
        db   = SessionLocal()
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        db.close()
        return scans


def _map_severity(s: str) -> Severity:
    return {
        "info":     Severity.INFO,
        "low":      Severity.LOW,
        "medium":   Severity.MEDIUM,
        "high":     Severity.HIGH,
        "critical": Severity.CRITICAL,
    }.get(s.lower(), Severity.INFO)
