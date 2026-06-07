"""
sentinel/reports/pdf_generator.py
Professional pentest-style PDF report generator using ReportLab.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

from sentinel.core.config import config
from sentinel.core.models import Scan, Severity

ACCENT  = colors.HexColor("#00d4aa")
SUBTLE  = colors.HexColor("#30363d")
WHITE   = colors.white
SEV_COLORS = {
    Severity.CRITICAL: colors.HexColor("#ff4444"),
    Severity.HIGH:     colors.HexColor("#ff8800"),
    Severity.MEDIUM:   colors.HexColor("#ffcc00"),
    Severity.LOW:      colors.HexColor("#44aaff"),
    Severity.INFO:     colors.HexColor("#888888"),
}


def _styles():
    return {
        "title": ParagraphStyle("T", fontName="Helvetica-Bold", fontSize=28, textColor=ACCENT, spaceAfter=6),
        "subtitle": ParagraphStyle("ST", fontName="Helvetica", fontSize=12, textColor=colors.HexColor("#c9d1d9"), spaceAfter=4),
        "section": ParagraphStyle("S", fontName="Helvetica-Bold", fontSize=14, textColor=ACCENT, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("B", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#333333"), spaceAfter=4, leading=14),
        "mono": ParagraphStyle("M", fontName="Courier", fontSize=8, textColor=colors.HexColor("#1a1a1a"), backColor=colors.HexColor("#f0f0f0"), spaceAfter=4, leading=12),
    }


def generate(scan: Scan, output_path: Optional[Path] = None) -> Path:
    if output_path is None:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = scan.target.replace(".", "_").replace("/", "_")
        output_path = config.report_output_dir / f"sentinel_{safe}_{ts}.pdf"

    styles = _styles()
    doc    = SimpleDocTemplate(str(output_path), pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm, bottomMargin=2*cm)
    analysis = scan.raw_results.get("analysis", {}) if scan.raw_results else {}
    story = [
        Paragraph("SENTINEL", styles["title"]),
        Paragraph("AI-Powered Security Assessment Report", styles["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=8),
        Spacer(1, 0.5*cm),
        Paragraph("Executive Summary", styles["section"]),
        Paragraph(analysis.get("executive_summary", "Analysis not available."), styles["body"]),
        Spacer(1, 0.5*cm),
    ]

    ports = (scan.raw_results or {}).get("nmap", {}).get("open_ports", [])
    if ports:
        story.append(Paragraph("Open Ports & Services", styles["section"]))
        rows = [["Port", "Protocol", "Service", "Version"]] + [
            [str(p["port"]), p["protocol"], p["service"], p.get("version", "")] for p in ports
        ]
        t = Table(rows, colWidths=[2*cm, 3*cm, 4*cm, 8*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",     (0,0), (-1,0), ACCENT),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f5f5f5")]),
            ("BOX",           (0,0), (-1,-1), 0.5, SUBTLE),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, colors.HexColor("#eeeeee")),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story += [t, Spacer(1, 0.3*cm)]

    story.append(PageBreak())
    story.append(Paragraph("Vulnerability Findings", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=SUBTLE, spaceAfter=6))

    if scan.findings:
        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for idx, f in enumerate(sorted(scan.findings, key=lambda x: sev_order.index(x.severity) if x.severity in sev_order else 99), 1):
            sev_color = SEV_COLORS.get(f.severity, colors.grey)
            sev_label = f.severity.value.upper() if f.severity else "INFO"
            header = Table([[
                Paragraph(f"{idx}. {f.title}", ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#1a1a1a"))),
                Paragraph(sev_label, ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=9, textColor=WHITE, alignment=TA_CENTER)),
            ]], colWidths=[14*cm, 3*cm])
            header.setStyle(TableStyle([
                ("BACKGROUND",    (1,0), (1,0), sev_color),
                ("BACKGROUND",    (0,0), (0,0), colors.HexColor("#f0f0f0")),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (0,-1), 8),
                ("BOX",           (0,0), (-1,-1), 0.5, SUBTLE),
                ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ]))
            block = [header]
            if f.description:
                block.append(Paragraph(f.description, styles["body"]))
            if f.evidence:
                block.append(Paragraph(f.evidence[:500], styles["mono"]))
            if f.remediation:
                block.append(Paragraph(f"Fix: {f.remediation}", styles["body"]))
            block.append(Spacer(1, 0.4*cm))
            story.append(KeepTogether(block))
    else:
        story.append(Paragraph("No findings recorded.", styles["body"]))

    recs = analysis.get("recommendations", [])
    if recs:
        story += [PageBreak(), Paragraph("Recommendations", styles["section"])]
        for i, r in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {r}", styles["body"]))

    doc.build(story)
    return output_path
