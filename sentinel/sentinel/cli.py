"""
sentinel/cli.py
SENTINEL command-line interface.
"""
from __future__ import annotations

import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """
[bold cyan]
  SENTINEL - AI-Powered Pentest Recon & Report Platform
[/bold cyan]
"""


@click.group()
@click.version_option("1.0.0", prog_name="sentinel")
def cli():
    """SENTINEL -- AI-Powered Pentest Recon & Report Platform"""
    pass


@cli.command()
@click.argument("target")
@click.option("--fast",    is_flag=True, help="Quick scan -- top-100 ports")
@click.option("--backend", type=click.Choice(["ollama", "anthropic", "openai"]), default=None)
@click.option("--report",  is_flag=True, help="Auto-generate PDF after scan")
def scan(target: str, fast: bool, backend: str | None, report: bool):
    """Run a full recon scan against TARGET (domain or IP)."""
    console.print(BANNER)
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]   "
        f"[bold]Mode:[/bold] {'fast' if fast else 'full'}   "
        f"[bold]LLM:[/bold] {backend or 'from .env'}",
        title="[bold cyan]New Scan", border_style="cyan",
    ))
    from sentinel.core.scanner import ScanOrchestrator
    try:
        completed = ScanOrchestrator(llm_backend=backend).run_scan(target, fast=fast)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[red]Scan failed:[/red] {exc}")
        sys.exit(1)
    _print_summary(completed)
    if report:
        _gen_report(completed.id)


@cli.command("scans")
def list_scans():
    """List all past scans."""
    from sentinel.core.scanner import ScanOrchestrator
    scans = ScanOrchestrator().list_scans()
    if not scans:
        console.print("[dim]No scans yet. Run: sentinel scan <target>[/dim]")
        return
    table = Table(title="Past Scans", border_style="cyan")
    table.add_column("ID",       style="dim",  width=10)
    table.add_column("Target",   style="cyan")
    table.add_column("Status",   style="bold")
    table.add_column("Findings", justify="right")
    table.add_column("Created",  style="dim")
    status_colors = {
        "complete": "green", "running": "yellow",
        "analyzing": "blue", "failed": "red", "pending": "dim",
    }
    for s in scans:
        st  = s.status.value if s.status else "pending"
        col = status_colors.get(st, "white")
        table.add_row(
            s.id[:8],
            s.target,
            f"[{col}]{st.upper()}[/{col}]",
            str(len(s.findings)),
            s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "-",
        )
    console.print(table)


@cli.command("report")
@click.argument("scan_id")
def report_cmd(scan_id: str):
    """Generate a PDF report for a completed scan."""
    _gen_report(scan_id)


@cli.command("show")
@click.argument("scan_id")
def show_scan(scan_id: str):
    """Show detailed results for a scan."""
    from sentinel.core.models import SessionLocal, Scan
    db   = SessionLocal()
    scan = db.query(Scan).filter(Scan.id.startswith(scan_id)).first()
    db.close()
    if not scan:
        console.print(f"[red]Scan not found:[/red] {scan_id}")
        return
    _print_summary(scan)


@cli.command("serve")
@click.option("--port", default=5000)
@click.option("--host", default="0.0.0.0")
def serve(port: int, host: str):
    """Start the SENTINEL web API."""
    from sentinel.api.app import create_app
    console.print(BANNER)
    console.print(f"[bold cyan]API running at http://{host}:{port}[/bold cyan]")
    create_app().run(host=host, port=port, debug=False)


def _print_summary(scan):
    from sentinel.core.models import SessionLocal, Scan as ScanModel
    db = SessionLocal()
    s = db.query(ScanModel).filter(ScanModel.id == scan.id).first()
    findings = list(s.findings) if s else []
    raw = s.raw_results or {} if s else {}
    db.close()
    analysis = raw.get("analysis", {})
    console.print(Panel(
        f"[bold]Target:[/bold] {s.target}\n"
        f"[bold]Status:[/bold] [green]{s.status.value.upper()}[/green]\n"
        f"[bold]Risk:[/bold]   [yellow]{analysis.get('risk_level', 'N/A').upper()}[/yellow]\n\n"
        f"{analysis.get('executive_summary', 'No summary available.')}",
        title="[bold cyan]Scan Complete", border_style="cyan",
    ))
    if findings:
        table = Table(title="Findings", border_style="cyan", show_lines=True)
        table.add_column("#",        width=4)
        table.add_column("Severity", width=10)
        table.add_column("Title",    style="bold")
        table.add_column("Module",   style="dim", width=12)
        table.add_column("CVSS",     width=6, justify="right")
        sev_colors = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "blue", "info": "dim",
        }
        for i, f in enumerate(findings, 1):
            sev = f.severity.value if f.severity else "info"
            table.add_row(
                str(i),
                f"[{sev_colors.get(sev,'white')}]{sev.upper()}[/{sev_colors.get(sev,'white')}]",
                f.title, f.module or "-", f.cvss_score or "-",
            )
        console.print(table)
    else:
        console.print("[dim]No findings recorded.[/dim]")

def _gen_report(scan_id: str):
    from sentinel.core.models import SessionLocal, Scan
    from sentinel.reports.pdf_generator import generate as gen_pdf
    db   = SessionLocal()
    scan = db.query(Scan).filter(Scan.id.startswith(scan_id)).first()
    db.close()
    if not scan:
        console.print(f"[red]Scan not found:[/red] {scan_id}")
        return
    console.print(f"[cyan]Generating report for[/cyan] {scan.target}...")
    try:
        path = gen_pdf(scan)
        console.print(Panel(f"[bold green]Saved:[/bold green] {path}", title="PDF Report", border_style="green"))
    except Exception as exc:
        console.print(f"[red]Failed:[/red] {exc}")


if __name__ == "__main__":
    cli()
