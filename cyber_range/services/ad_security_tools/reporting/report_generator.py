"""
AD Security Tools — Enterprise PDF Report Generator
=====================================================
Generates a premium, concise (≤7 page) penetration test report with:
  - Executive Summary
  - Scope & Methodology
  - Finding Severity Breakdown (chart)
  - Detailed Findings with TTPs, PoCs, Evidence Chains
  - Attack Path Visualization
  - Remediation Roadmap
  - Appendix: Evidence Log

Uses ReportLab for PDF generation.
"""

import os
import io
import logging
from datetime import datetime, timezone
from typing import Callable

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether, Image
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

logger = logging.getLogger(__name__)

# ── Color Palette ────────────────────────────────────────────────────
BRAND_DARK = colors.HexColor("#0a0e1a")
BRAND_GOLD = colors.HexColor("#c9a84c")
BRAND_RED = colors.HexColor("#e74c3c")
BRAND_ORANGE = colors.HexColor("#f39c12")
BRAND_YELLOW = colors.HexColor("#f1c40f")
BRAND_GREEN = colors.HexColor("#2ecc71")
BRAND_BLUE = colors.HexColor("#3498db")
BRAND_WHITE = colors.HexColor("#ffffff")
BRAND_GRAY = colors.HexColor("#95a5a6")
BRAND_LIGHT_BG = colors.HexColor("#f8f9fa")

SEV_COLORS = {
    "Critical": BRAND_RED,
    "High": BRAND_ORANGE,
    "Medium": BRAND_YELLOW,
    "Low": BRAND_GREEN,
}


def _build_styles():
    """Create custom paragraph styles for the report."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=26, textColor=BRAND_DARK, spaceAfter=4*mm,
        fontName="Helvetica-Bold", alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"],
        fontSize=12, textColor=BRAND_GRAY, spaceAfter=8*mm,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        "SectionHead", parent=styles["Heading1"],
        fontSize=16, textColor=BRAND_DARK, spaceBefore=8*mm,
        spaceAfter=4*mm, fontName="Helvetica-Bold",
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "SubSection", parent=styles["Heading2"],
        fontSize=12, textColor=BRAND_DARK, spaceBefore=4*mm,
        spaceAfter=2*mm, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontSize=9.5, textColor=BRAND_DARK, spaceAfter=2*mm,
        fontName="Helvetica", leading=13, alignment=TA_JUSTIFY,
    ))
    styles.add(ParagraphStyle(
        "FindingTitle", parent=styles["Normal"],
        fontSize=11, textColor=BRAND_DARK, spaceBefore=3*mm,
        spaceAfter=1*mm, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "Evidence", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#444444"),
        fontName="Courier", leftIndent=8*mm, spaceAfter=1*mm,
    ))
    styles.add(ParagraphStyle(
        "Footer", parent=styles["Normal"],
        fontSize=7, textColor=BRAND_GRAY, alignment=TA_CENTER,
    ))
    return styles


def _severity_badge(severity: str) -> str:
    """Return HTML-styled severity badge."""
    color_map = {"Critical": "#e74c3c", "High": "#f39c12",
                 "Medium": "#f1c40f", "Low": "#2ecc71"}
    c = color_map.get(severity, "#95a5a6")
    return f'<font color="{c}"><b>[{severity.upper()}]</b></font>'


def _header_footer(canvas, doc):
    """Draw header and footer on each page."""
    canvas.saveState()
    # Header line
    canvas.setStrokeColor(BRAND_GOLD)
    canvas.setLineWidth(1.5)
    canvas.line(20*mm, A4[1] - 15*mm, A4[0] - 20*mm, A4[1] - 15*mm)
    # Header text
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(BRAND_DARK)
    canvas.drawString(20*mm, A4[1] - 13*mm, "AEGIS XStrike — Penetration Test Report")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(BRAND_GRAY)
    canvas.drawRightString(A4[0] - 20*mm, A4[1] - 13*mm, "CONFIDENTIAL")
    # Footer
    canvas.setStrokeColor(BRAND_GOLD)
    canvas.line(20*mm, 18*mm, A4[0] - 20*mm, 18*mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(BRAND_GRAY)
    canvas.drawString(20*mm, 13*mm, "© Expedite Consults — Enterprise Security Assessment")
    canvas.drawRightString(A4[0] - 20*mm, 13*mm, f"Page {doc.page}")
    canvas.restoreState()


# ═══════════════════════════════════════════════════════════════════════
# SEVERITY PIE CHART
# ═══════════════════════════════════════════════════════════════════════

def _severity_pie(findings: list) -> Drawing:
    """Generate a severity breakdown pie chart."""
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        s = f.get("severity", "Low")
        if s in sev:
            sev[s] += 1

    d = Drawing(260, 160)
    pie = Pie()
    pie.x = 40
    pie.y = 10
    pie.width = 120
    pie.height = 120
    pie.data = [sev["Critical"], sev["High"], sev["Medium"], sev["Low"]]
    pie.labels = [f"Critical ({sev['Critical']})", f"High ({sev['High']})",
                  f"Medium ({sev['Medium']})", f"Low ({sev['Low']})"]
    pie.slices[0].fillColor = BRAND_RED
    pie.slices[1].fillColor = BRAND_ORANGE
    pie.slices[2].fillColor = BRAND_YELLOW
    pie.slices[3].fillColor = BRAND_GREEN
    pie.slices.strokeColor = BRAND_WHITE
    pie.slices.strokeWidth = 1.5
    pie.sideLabels = True
    pie.simpleLabels = False
    pie.slices.fontName = "Helvetica"
    pie.slices.fontSize = 8
    d.add(pie)
    return d


# ═══════════════════════════════════════════════════════════════════════
# MAIN REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

def generate_report(assessment_data: dict, output_path: str = None,
                    log_fn: Callable = None) -> str:
    """
    Generate a premium enterprise PDF report from assessment results.

    Args:
        assessment_data: Full assessment result dict from the orchestrator.
        output_path: Optional output file path. Auto-generated if not provided.
        log_fn: Optional logging callback.

    Returns:
        Path to the generated PDF file.
    """
    if not output_path:
        aid = assessment_data.get("assessment_id", "report")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "reports")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"AEGIS_Report_{aid}_{ts}.pdf")

    styles = _build_styles()
    elements = []

    findings = assessment_data.get("findings", [])
    attack_paths = assessment_data.get("attack_paths", [])
    correlations = assessment_data.get("correlations", [])
    exposure = assessment_data.get("exposure_score", {})
    discovery = assessment_data.get("discovery", {})
    tools = assessment_data.get("tools_invoked", [])
    target = assessment_data.get("target", "Unknown")
    domain = assessment_data.get("domain", "")
    duration = assessment_data.get("duration_seconds", 0)

    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        s = f.get("severity", "Low")
        if s in sev:
            sev[s] += 1

    score = exposure.get("total_score", 0) if isinstance(exposure, dict) else 0
    risk_label = exposure.get("risk_label", "UNKNOWN") if isinstance(exposure, dict) else "UNKNOWN"

    # ═════════════════════════════════════════════════════════════════
    # PAGE 1: COVER
    # ═════════════════════════════════════════════════════════════════
    elements.append(Spacer(1, 40*mm))
    elements.append(Paragraph("PENETRATION TEST REPORT", styles["ReportTitle"]))
    elements.append(Paragraph(
        f"Active Directory Security Assessment<br/>"
        f"Target: {target} {f'({domain})' if domain else ''}<br/>"
        f"Date: {datetime.now().strftime('%B %d, %Y')}<br/>"
        f"Assessment ID: {assessment_data.get('assessment_id', 'N/A')}",
        styles["ReportSubtitle"]
    ))
    elements.append(Spacer(1, 10*mm))
    elements.append(HRFlowable(width="100%", thickness=2, color=BRAND_GOLD))
    elements.append(Spacer(1, 8*mm))

    # Risk score summary box
    score_color = "#e74c3c" if score >= 75 else "#f39c12" if score >= 50 else "#f1c40f" if score >= 25 else "#2ecc71"
    elements.append(Paragraph(
        f'<font size="14"><b>Exposure Score: </b></font>'
        f'<font size="20" color="{score_color}"><b>{score}/100 ({risk_label})</b></font>',
        styles["BodyText2"]
    ))
    elements.append(Spacer(1, 4*mm))

    # Quick stats table
    stats_data = [
        ["METRIC", "VALUE"],
        ["Total Findings", str(len(findings))],
        ["Critical", str(sev["Critical"])],
        ["High", str(sev["High"])],
        ["Medium", str(sev["Medium"])],
        ["Low", str(sev["Low"])],
        ["Attack Paths", str(len(attack_paths))],
        ["Compound Risks", str(len(correlations))],
        ["Tools Executed", str(len(tools))],
        ["Duration", f"{duration:.1f}s"],
    ]
    stats_table = Table(stats_data, colWidths=[55*mm, 35*mm])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_GOLD),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_WHITE, BRAND_LIGHT_BG]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(stats_table)
    elements.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # PAGE 2: EXECUTIVE SUMMARY
    # ═════════════════════════════════════════════════════════════════
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GOLD))
    elements.append(Spacer(1, 3*mm))

    # Auto-generate narrative
    if sev["Critical"] > 0:
        risk_narrative = (
            f"This assessment identified <b>{sev['Critical']} critical</b> and "
            f"<b>{sev['High']} high</b> severity findings across the target "
            f"Active Directory environment ({target}). "
            f"<b>{len(attack_paths)} viable attack paths</b> were identified that "
            f"could lead to full domain compromise. "
            f"The overall exposure score is <b>{score}/100 ({risk_label})</b>, "
            f"indicating {'an immediate threat requiring urgent remediation' if score >= 75 else 'significant risk requiring prompt action'}. "
        )
    elif sev["High"] > 0:
        risk_narrative = (
            f"The assessment of {target} identified <b>{sev['High']} high</b> and "
            f"<b>{sev['Medium']} medium</b> severity findings. "
            f"While no critical vulnerabilities enabling immediate domain compromise were found, "
            f"the high-severity findings present significant risk if left unaddressed. "
            f"Exposure score: <b>{score}/100 ({risk_label})</b>."
        )
    else:
        risk_narrative = (
            f"The assessment of {target} identified <b>{len(findings)} findings</b> "
            f"({sev['Medium']} medium, {sev['Low']} low). "
            f"No critical or high-severity vulnerabilities were discovered. "
            f"Exposure score: <b>{score}/100 ({risk_label})</b>."
        )

    # Add AI narrative if available
    ai_narrative = assessment_data.get("ai_narrative", "")
    if ai_narrative:
        risk_narrative += f"<br/><br/><i>AI Analysis: {ai_narrative[:500]}</i>"

    elements.append(Paragraph(risk_narrative, styles["BodyText2"]))
    elements.append(Spacer(1, 4*mm))

    # Severity pie chart
    elements.append(Paragraph("1.1 Finding Distribution", styles["SubSection"]))
    if any(sev.values()):
        elements.append(_severity_pie(findings))
    elements.append(Spacer(1, 4*mm))

    # ═════════════════════════════════════════════════════════════════
    # SCOPE & METHODOLOGY
    # ═════════════════════════════════════════════════════════════════
    elements.append(Paragraph("2. SCOPE & METHODOLOGY", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GOLD))
    elements.append(Spacer(1, 3*mm))

    scope_text = (
        f"<b>Target:</b> {target} {f'({domain})' if domain else ''}<br/>"
        f"<b>Mode:</b> Active autonomous penetration testing<br/>"
        f"<b>Tools Executed:</b> {', '.join(tools) if isinstance(tools, list) else tools}<br/>"
        f"<b>Duration:</b> {duration:.1f} seconds<br/>"
        f"<b>Methodology:</b> PTES, OWASP, MITRE ATT&CK, NIST CSF, CIS Controls<br/>"
        f"<b>Phases:</b> Recon → Vuln Scan → Exploit → PrivEsc → OWASP → Post-Ex → Lateral → Cloud → EDR → Report"
    )
    elements.append(Paragraph(scope_text, styles["BodyText2"]))
    elements.append(Spacer(1, 3*mm))

    # Discovery summary
    elements.append(Paragraph("2.1 Discovery Summary", styles["SubSection"]))
    disc_data = [["Metric", "Count"]]
    disc_data.append(["Hosts Found", str(discovery.get("hosts_found", discovery.get("hosts", 0)))])
    disc_data.append(["Ports Found", str(discovery.get("ports_found", discovery.get("ports", 0)))])
    disc_table = Table(disc_data, colWidths=[55*mm, 25*mm])
    disc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_GOLD),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_WHITE, BRAND_LIGHT_BG]),
    ]))
    elements.append(disc_table)
    elements.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # SECTION 3: CONFIRMED EXPLOITATIONS (with full TTP + evidence)
    # ═════════════════════════════════════════════════════════════════
    confirmed = [f for f in findings if f.get("status", "").upper() == "CONFIRMED"]
    potential = [f for f in findings if f.get("status", "").upper() != "CONFIRMED"]

    elements.append(Paragraph("3. CONFIRMED EXPLOITATIONS", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_RED))
    elements.append(Spacer(1, 2*mm))

    if confirmed:
        elements.append(Paragraph(
            f'<font color="#e74c3c"><b>{len(confirmed)} vulnerabilities were successfully exploited '
            f'with evidence collected.</b></font>',
            styles["BodyText2"]
        ))
        elements.append(Spacer(1, 3*mm))

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_confirmed = sorted(confirmed, key=lambda f: sev_order.get(f.get("severity", "Low"), 3))

        for i, f in enumerate(sorted_confirmed[:20], 1):
            badge = _severity_badge(f.get("severity", "Low"))
            title = f.get("title", "Finding")
            mitre = f.get("mitre_id", "")
            evidence = f.get("evidence", "")
            cvss = f.get("cvss", 0.0)
            cve = f.get("cve", "")
            rem = f.get("remediation", "")
            scanner = f.get("scanner", f.get("source_tool", f.get("module", "")))

            # MITRE ATT&CK mapping
            mitre_tactics = {
                "T1046": ("Discovery", "Network Service Scanning"),
                "T1210": ("Lateral Movement", "Exploit Remote Services"),
                "T1190": ("Initial Access", "Exploit Public-Facing Application"),
                "T1021": ("Lateral Movement", "Remote Services"),
                "T1021.002": ("Lateral Movement", "Remote Services: SMB/Windows Admin Shares"),
                "T1110": ("Credential Access", "Brute Force"),
                "T1110.004": ("Credential Access", "Credential Stuffing"),
                "T1078": ("Initial Access", "Valid Accounts"),
                "T1078.001": ("Initial Access", "Valid Accounts: Default Accounts"),
                "T1059": ("Execution", "Command and Scripting Interpreter"),
                "T1005": ("Collection", "Data from Local System"),
                "T1083": ("Discovery", "File and Directory Discovery"),
            }
            tactic, technique = mitre_tactics.get(mitre, mitre_tactics.get(mitre.split(".")[0] if mitre else "", ("Unknown", mitre)))

            finding_block = []

            # ── Finding header ──
            finding_block.append(Paragraph(
                f'{badge} <b>E-{i:02d}: {title}</b>',
                styles["FindingTitle"]
            ))

            # ── Metadata table ──
            meta_data = []
            if f.get("host"):
                meta_data.append(["Target Host", str(f["host"])])
            if cvss:
                meta_data.append(["CVSS Score", str(cvss)])
            if cve:
                meta_data.append(["CVE ID", str(cve)])
            meta_data.append(["Tool Used", str(scanner)])
            if meta_data:
                meta_table = Table(meta_data, colWidths=[35*mm, 120*mm])
                meta_table.setStyle(TableStyle([
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("TEXTCOLOR", (0, 0), (0, -1), BRAND_DARK),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#333333")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ]))
                finding_block.append(meta_table)

            # ── TTP Section ──
            finding_block.append(Spacer(1, 2*mm))
            ttp_header = (
                f'<font color="#0a0e1a"><b>Tactics, Techniques &amp; Procedures (TTP)</b></font>'
            )
            finding_block.append(Paragraph(ttp_header, styles["BodyText2"]))

            ttp_data = [
                ["Tactic", str(tactic)],
                ["Technique", f"{mitre} — {technique}"],
                ["Procedure", f.get("description", title)],
            ]
            ttp_table = Table(ttp_data, colWidths=[30*mm, 125*mm])
            ttp_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, -1), BRAND_LIGHT_BG),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ]))
            finding_block.append(ttp_table)

            # ── Evidence Block (the actual proof) ──
            finding_block.append(Spacer(1, 2*mm))
            finding_block.append(Paragraph(
                '<font color="#e74c3c"><b>⬤ Sample Collected Evidence:</b></font>',
                styles["BodyText2"]
            ))

            if evidence:
                # Parse evidence into lines for proper rendering
                ev_text = str(evidence).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                ev_lines = ev_text.split("\n")

                # Render evidence in a styled box
                ev_table_data = []
                for line in ev_lines[:35]:  # Show up to 35 lines
                    ev_table_data.append([Paragraph(
                        f'<font face="Courier" size="6.5">{line}</font>',
                        styles["Evidence"]
                    )])

                if ev_table_data:
                    ev_table = Table(ev_table_data, colWidths=[155*mm])
                    ev_table.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#00ff88")),
                        ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 1),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#333355")),
                    ]))
                    finding_block.append(ev_table)
            else:
                finding_block.append(Paragraph(
                    '<font face="Courier" size="7" color="#999999">No evidence captured for this finding.</font>',
                    styles["Evidence"]
                ))

            # ── Remediation ──
            if rem:
                finding_block.append(Spacer(1, 2*mm))
                finding_block.append(Paragraph(
                    f'<font color="#2ecc71"><b>✓ Remediation:</b></font> {rem}',
                    styles["BodyText2"]
                ))

            finding_block.append(Spacer(1, 3*mm))
            finding_block.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
            elements.append(KeepTogether(finding_block))

        if len(sorted_confirmed) > 20:
            elements.append(Paragraph(
                f'<i>... and {len(sorted_confirmed) - 20} additional exploited findings. See appendix.</i>',
                styles["BodyText2"]
            ))
    else:
        elements.append(Paragraph(
            "No vulnerabilities were successfully exploited during this assessment.",
            styles["BodyText2"]
        ))

    elements.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # SECTION 4: UNVERIFIED VULNERABILITIES (ZAP, OpenVAS, scan-only)
    # ═════════════════════════════════════════════════════════════════
    elements.append(Paragraph("4. UNVERIFIED VULNERABILITIES", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_ORANGE))
    elements.append(Spacer(1, 2*mm))

    if potential:
        elements.append(Paragraph(
            f'<font color="#f39c12"><b>{len(potential)} potential vulnerabilities detected by scanners '
            f'but NOT exploited.</b></font> These require manual verification.',
            styles["BodyText2"]
        ))
        elements.append(Spacer(1, 3*mm))

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_potential = sorted(potential, key=lambda f: sev_order.get(f.get("severity", "Low"), 3))

        # Summary table of unverified findings
        uv_data = [["#", "Severity", "Title", "Host", "Scanner", "Status"]]
        for j, f in enumerate(sorted_potential[:30], 1):
            badge_text = f.get("severity", "Low")
            uv_data.append([
                str(j),
                badge_text,
                (f.get("title", "")[:50]),
                str(f.get("host", "")),
                str(f.get("scanner", f.get("module", "")))[:20],
                "Not Exploited",
            ])

        if len(uv_data) > 1:
            uv_table = Table(uv_data, colWidths=[8*mm, 18*mm, 55*mm, 30*mm, 25*mm, 22*mm])
            uv_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_GOLD),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.3, BRAND_GRAY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BRAND_WHITE, BRAND_LIGHT_BG]),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            elements.append(uv_table)

        if len(sorted_potential) > 30:
            elements.append(Spacer(1, 2*mm))
            elements.append(Paragraph(
                f'<i>... and {len(sorted_potential) - 30} additional unverified findings.</i>',
                styles["BodyText2"]
            ))
    else:
        elements.append(Paragraph("No unverified vulnerabilities.", styles["BodyText2"]))

    elements.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # PAGE 6: ATTACK PATHS & COMPOUND RISKS
    # ═════════════════════════════════════════════════════════════════
    elements.append(Paragraph("5. ATTACK PATHS", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GOLD))
    elements.append(Spacer(1, 3*mm))

    if attack_paths:
        for ap in attack_paths:
            name = ap.get("name", "Unknown Path")
            risk = ap.get("risk_score", 0)
            conf = ap.get("confidence", 0)
            steps = ap.get("steps", [])
            mitre_chain = ap.get("mitre_chain", [])

            risk_color = "#e74c3c" if risk >= 90 else "#f39c12" if risk >= 70 else "#f1c40f"

            path_block = []
            path_block.append(Paragraph(
                f'<font color="{risk_color}"><b>▶ {name}</b></font> '
                f'(Risk: {risk}/100, Confidence: {conf:.0%})',
                styles["FindingTitle"]
            ))

            # Steps
            step_text = " → ".join(s.get("node", "?") for s in steps)
            path_block.append(Paragraph(f"<b>Chain:</b> {step_text}", styles["BodyText2"]))

            if mitre_chain:
                path_block.append(Paragraph(
                    f"<b>MITRE:</b> {' → '.join(mitre_chain)}", styles["Evidence"]
                ))

            path_block.append(Spacer(1, 2*mm))
            elements.append(KeepTogether(path_block))
    else:
        elements.append(Paragraph("No viable attack paths identified.", styles["BodyText2"]))

    elements.append(Spacer(1, 4*mm))

    # Compound Risks
    if correlations:
        elements.append(Paragraph("5.1 Compound Risk Correlations", styles["SubSection"]))
        for corr in correlations:
            rule = corr.get("rule", "")
            sev_corr = corr.get("combined_severity", "")
            narrative = corr.get("attack_narrative", "")
            badge = _severity_badge(sev_corr)
            elements.append(Paragraph(f"{badge} <b>{rule}</b>", styles["FindingTitle"]))
            if narrative:
                elements.append(Paragraph(narrative[:300], styles["BodyText2"]))
            elements.append(Spacer(1, 1*mm))

    elements.append(PageBreak())

    # ═════════════════════════════════════════════════════════════════
    # PAGE 7: REMEDIATION ROADMAP
    # ═════════════════════════════════════════════════════════════════
    elements.append(Paragraph("6. REMEDIATION ROADMAP", styles["SectionHead"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GOLD))
    elements.append(Spacer(1, 3*mm))

    # Group by priority — use all findings sorted by severity
    all_sorted = sorted(findings, key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(f.get("severity", "Low"), 3))
    critical_rems = [f for f in all_sorted if f.get("severity") == "Critical" and f.get("remediation")]
    high_rems = [f for f in all_sorted if f.get("severity") == "High" and f.get("remediation")]
    medium_rems = [f for f in all_sorted if f.get("severity") == "Medium" and f.get("remediation")]

    if critical_rems:
        elements.append(Paragraph(
            '<font color="#e74c3c"><b>IMMEDIATE (0-48 hours)</b></font>',
            styles["SubSection"]
        ))
        for f in critical_rems[:5]:
            elements.append(Paragraph(
                f"• <b>{f['title']}:</b> {f['remediation']}", styles["BodyText2"]
            ))

    if high_rems:
        elements.append(Paragraph(
            '<font color="#f39c12"><b>SHORT-TERM (1-2 weeks)</b></font>',
            styles["SubSection"]
        ))
        for f in high_rems[:5]:
            elements.append(Paragraph(
                f"• <b>{f['title']}:</b> {f['remediation']}", styles["BodyText2"]
            ))

    if medium_rems:
        elements.append(Paragraph(
            '<font color="#f1c40f"><b>MEDIUM-TERM (1-3 months)</b></font>',
            styles["SubSection"]
        ))
        for f in medium_rems[:5]:
            elements.append(Paragraph(
                f"• <b>{f['title']}:</b> {f['remediation']}", styles["BodyText2"]
            ))

    # Exposure score breakdown
    elements.append(Spacer(1, 4*mm))
    elements.append(Paragraph("6.1 Exposure Score Breakdown", styles["SubSection"]))
    if isinstance(exposure, dict):
        cats = exposure.get("categories", {})
        if cats:
            cat_data = [["Category", "Score", "Max"]]
            for cat, sc in cats.items():
                cat_data.append([cat, str(sc), "25"])
            cat_data.append(["TOTAL", str(score), "100"])
            cat_table = Table(cat_data, colWidths=[55*mm, 20*mm, 20*mm])
            cat_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), BRAND_GOLD),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
                ("BACKGROUND", (0, -1), (-1, -1), BRAND_DARK),
                ("TEXTCOLOR", (0, -1), (-1, -1), BRAND_GOLD),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [BRAND_WHITE, BRAND_LIGHT_BG]),
            ]))
            elements.append(cat_table)

    # ═════════════════════════════════════════════════════════════════
    # BUILD PDF
    # ═════════════════════════════════════════════════════════════════
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=22*mm, bottomMargin=22*mm,
        leftMargin=20*mm, rightMargin=20*mm,
        title=f"AEGIS XStrike — Penetration Test Report",
        author="Expedite Consults",
        subject="Active Directory Security Assessment",
    )

    doc.build(elements, onFirstPage=_header_footer, onLaterPages=_header_footer)

    if log_fn:
        log_fn(f"  📄 Report generated: {output_path}")

    return output_path


# ── Convenience function ─────────────────────────────────────────────

def generate_report_from_db(assessment_id: str, output_path: str = None) -> str:
    """Generate report from evidence database by assessment ID."""
    try:
        from ..evidence.evidence_store import get_findings, get_assessment_summary
        summary = get_assessment_summary(assessment_id)
        findings = get_findings(assessment_id)
        data = {
            "assessment_id": assessment_id,
            "target": summary.get("target_domain", ""),
            "domain": summary.get("target_domain", ""),
            "findings": findings,
            "exposure_score": {"total_score": summary.get("score", 0)},
            "attack_paths": [],
            "correlations": [],
            "discovery": {},
            "tools_invoked": [],
            "duration_seconds": 0,
        }
        return generate_report(data, output_path)
    except Exception as e:
        logger.error(f"[Report] DB report error: {e}")
        return ""
