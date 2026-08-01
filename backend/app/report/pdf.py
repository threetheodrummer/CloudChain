"""
PDF export of a scan report.

Generated server-side rather than in the browser for two reasons: the same
document is then available to the CLI and to CI, and it's built from the exact
report dict the dashboard renders, so a downloaded file can never disagree with
what was on screen.

reportlab is used deliberately over an HTML-to-PDF converter. WeasyPrint and
wkhtmltopdf both need system libraries (cairo, pango, Qt) that would roughly
double the size of the backend container for a feature this small.
"""
from __future__ import annotations

import io
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#0b1220")
MUTED = colors.HexColor("#5f7086")
RULE = colors.HexColor("#d7dee8")
ACCENT = colors.HexColor("#0e7490")

SEVERITY_COLOURS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#a16207"),
    "LOW": colors.HexColor("#0369a1"),
}

GRADE_COLOURS = {
    "A": colors.HexColor("#15803d"),
    "B": colors.HexColor("#0369a1"),
    "C": colors.HexColor("#a16207"),
    "D": colors.HexColor("#c2410c"),
    "E": colors.HexColor("#b91c1c"),
    "F": colors.HexColor("#991b1b"),
}


def _hex(colour: colors.Color) -> str:
    """'#rrggbb' for use in reportlab's inline <font color=...> markup.

    Color.hexval() returns '0xrrggbb', which the paragraph parser rejects.
    """
    return "#" + colour.hexval()[2:]


def _safe(text: Any) -> str:
    """Make text safe for reportlab's built-in fonts.

    The standard Type 1 fonts cover Latin-1 only. An arrow or a curly quote
    that slipped in from a narrative would render as a solid black box, so
    anything outside that range is transliterated rather than drawn.
    """
    s = "" if text is None else str(text)
    replacements = {
        "→": "->", "←": "<-", "—": "-", "–": "-",
        "‘": "'", "’": "'", "“": '"', "”": '"',
        "•": "*", "·": "-", "…": "...",
    }
    for bad, good in replacements.items():
        s = s.replace(bad, good)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "cc-title", parent=base["Title"], fontSize=20, leading=24,
            textColor=INK, alignment=TA_LEFT, spaceAfter=2,
        ),
        "sub": ParagraphStyle(
            "cc-sub", parent=base["Normal"], fontSize=8.5, leading=12, textColor=MUTED,
        ),
        "h2": ParagraphStyle(
            "cc-h2", parent=base["Heading2"], fontSize=12, leading=15,
            textColor=INK, spaceBefore=14, spaceAfter=5,
        ),
        "body": ParagraphStyle(
            "cc-body", parent=base["Normal"], fontSize=9, leading=12.5, textColor=INK,
        ),
        "small": ParagraphStyle(
            "cc-small", parent=base["Normal"], fontSize=7.8, leading=10.5, textColor=INK,
        ),
        "muted": ParagraphStyle(
            "cc-muted", parent=base["Normal"], fontSize=8, leading=11, textColor=MUTED,
        ),
        "step": ParagraphStyle(
            "cc-step", parent=base["Normal"], fontSize=8.5, leading=12,
            textColor=INK, leftIndent=10,
        ),
    }


def _table(data: List[List[Any]], widths: List[float], header: bool = True) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ]
    t.setStyle(TableStyle(style))
    return t


def _paths_section(title: str, note: str, paths: List[Dict[str, Any]], S) -> List[Any]:
    out: List[Any] = [Paragraph(_safe(title), S["h2"])]
    if note:
        out.append(Paragraph(_safe(note), S["muted"]))
        out.append(Spacer(1, 4))

    if not paths:
        out.append(Paragraph("None found.", S["body"]))
        return out

    for path in paths:
        block: List[Any] = []
        tags = [path.get("severity", "")]
        if path.get("crosses_accounts"):
            tags.append("crosses " + ", ".join(path.get("accounts", [])))
        block.append(Paragraph("<b>%s</b>" % _safe(" | ".join(t for t in tags if t)), S["small"]))
        for i, step in enumerate(path.get("steps", []), start=1):
            block.append(Paragraph(f"{i}. {_safe(step)}", S["step"]))
        block.append(Spacer(1, 8))
        out.append(KeepTogether(block))
    return out


def build_report_pdf(report: Dict[str, Any]) -> bytes:
    """Render a report dict (from report.generator.build_report) as a PDF."""
    S = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"CloudChain report {report.get('scan_id', '')}",
        author="CloudChain",
    )

    posture = report.get("posture") or {}
    summary = report.get("summary") or {}
    story: List[Any] = []

    # --- header ----------------------------------------------------------
    story.append(Paragraph("CloudChain posture report", S["title"]))
    story.append(
        Paragraph(
            _safe(
                f"Scan {report.get('scan_id', '')} | {report.get('mode', '')} mode | "
                f"{report.get('timestamp', '')}"
            ),
            S["sub"],
        )
    )
    story.append(Spacer(1, 10))

    # --- posture ---------------------------------------------------------
    grade = posture.get("grade", "?")
    score_line = (
        f'<font size="26"><b>{posture.get("score", "?")}</b></font>'
        f'<font size="11" color="#5f7086">/100</font>   '
        f'<font size="13" color="{_hex(GRADE_COLOURS.get(grade, INK))}">'
        f"<b>GRADE {_safe(grade)}</b></font>"
    )
    story.append(Paragraph(score_line, S["body"]))
    story.append(Spacer(1, 4))
    if posture.get("explanation"):
        story.append(Paragraph(_safe(posture["explanation"]), S["body"]))

    components = posture.get("components") or []
    if components:
        story.append(Paragraph("How the score was calculated", S["h2"]))
        rows = [["Dimension", "Deducted", "What it measured"]]
        for c in components:
            rows.append(
                [
                    Paragraph(f"<b>{_safe(c['name'])}</b>", S["small"]),
                    Paragraph(f"{c['points_lost']:.2f} / {c['weight']:g}", S["small"]),
                    Paragraph(_safe(c["headline"]), S["small"]),
                ]
            )
        story.append(_table(rows, [30 * mm, 22 * mm, 122 * mm]))

    # --- accounts --------------------------------------------------------
    accounts = report.get("accounts") or []
    if len(accounts) > 1:
        story.append(Paragraph("Accounts scanned", S["h2"]))
        rows = [["Account", "Name", "Findings"]]
        for a in accounts:
            rows.append([_safe(a["id"]), _safe(a["name"]), str(a["findings"])])
        story.append(_table(rows, [40 * mm, 60 * mm, 25 * mm]))

    # --- severity --------------------------------------------------------
    by_sev = summary.get("by_severity") or {}
    story.append(Paragraph("Findings by severity", S["h2"]))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_table = _table(
        [order, [str(by_sev.get(s, 0)) for s in order]],
        [40 * mm] * 4,
        header=True,
    )
    sev_table.setStyle(
        TableStyle([("TEXTCOLOR", (i, 0), (i, 0), SEVERITY_COLOURS[s]) for i, s in enumerate(order)])
    )
    story.append(sev_table)

    # --- paths -----------------------------------------------------------
    story.extend(
        _paths_section(
            "Attack paths",
            "Routes an unauthenticated attacker can walk, from an internet entry "
            "point to AdministratorAccess.",
            report.get("attack_paths") or [],
            S,
        )
    )
    story.extend(
        _paths_section(
            "Escalation routes",
            "Routes that open once the starting identity is compromised. Latent "
            "privilege-escalation primitives, not live breach routes.",
            report.get("escalation_paths") or [],
            S,
        )
    )

    # --- findings --------------------------------------------------------
    findings = report.get("findings") or report.get("top_findings") or []
    if findings:
        story.append(PageBreak())
        story.append(Paragraph(f"All findings ({len(findings)})", S["h2"]))
        rows = [["#", "Score", "Severity", "Issue", "Resource"]]
        for f in findings:
            rows.append(
                [
                    str(f.get("rank", "")),
                    str(f.get("risk_score", "")),
                    Paragraph(
                        f'<font color="{_hex(SEVERITY_COLOURS.get(f.get("severity"), INK))}">'
                        f'<b>{_safe(f.get("severity"))}</b></font>',
                        S["small"],
                    ),
                    Paragraph(_safe(f.get("issue_code")), S["small"]),
                    Paragraph(_safe(f.get("resource_id")), S["small"]),
                ]
            )
        story.append(_table(rows, [10 * mm, 14 * mm, 20 * mm, 58 * mm, 72 * mm]))

        story.append(Paragraph("Remediation", S["h2"]))
        for f in findings:
            story.append(
                Paragraph(
                    f'<b>{_safe(f.get("issue_code"))}</b> on {_safe(f.get("resource_id"))}',
                    S["small"],
                )
            )
            story.append(Paragraph(_safe(f.get("remediation", "")), S["step"]))
            story.append(Spacer(1, 5))

    # --- drift -----------------------------------------------------------
    drift = report.get("drift")
    if drift and drift.get("previous_scan_id"):
        story.append(Paragraph("Drift since previous scan", S["h2"]))
        story.append(
            Paragraph(
                _safe(
                    f"{len(drift['new_findings'])} new | "
                    f"{len(drift['resolved_findings'])} resolved | "
                    f"{drift['unchanged_count']} unchanged"
                ),
                S["body"],
            )
        )
        for e in drift["new_findings"]:
            story.append(
                Paragraph(f"NEW  {_safe(e['issue_code'])} on {_safe(e['resource_id'])}", S["small"])
            )
        for e in drift["resolved_findings"]:
            story.append(
                Paragraph(
                    f"RESOLVED  {_safe(e['issue_code'])} on {_safe(e['resource_id'])}", S["small"]
                )
            )

    story.append(Spacer(1, 14))
    story.append(
        Paragraph(
            "Generated by CloudChain. Every number in this report is derived from the "
            "same scan result the dashboard renders.",
            S["muted"],
        )
    )

    doc.build(story)
    return buf.getvalue()
