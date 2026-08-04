"""
PDF export of a scan report.

Generated server-side rather than in the browser for two reasons: the same
document is then available to the CLI and to CI, and it's built from the exact
report dict the dashboard renders, so a downloaded file can never disagree with
what was on screen.

reportlab is used deliberately over an HTML-to-PDF converter. WeasyPrint and
wkhtmltopdf both need system libraries (cairo, pango, Qt) that would roughly
double the size of the backend container for a feature this small.

Layout note: reportlab does not grow a paragraph's leading to fit an inline
font-size change, so a 26pt number inside a 12pt style silently overlaps the
line beneath it. Anything oversized here gets its own style with matching
leading, or is drawn as a graphic.
"""
from __future__ import annotations

import io
from typing import Any, Dict, List

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Dark palette, matched to the dashboard so the export and the screen read as
# the same product.
BG = colors.HexColor("#05070b")
PANEL = colors.HexColor("#0e1620")
PANEL_ALT = colors.HexColor("#131c28")
RULE = colors.HexColor("#1e2a3a")
INK = colors.HexColor("#e6edf3")
MUTED = colors.HexColor("#93a4b8")
FAINT = colors.HexColor("#5f7086")
ACCENT = colors.HexColor("#22d3ee")
TRACK = colors.HexColor("#1b2635")

SEVERITY_COLOURS = {
    "CRITICAL": colors.HexColor("#ff5d7a"),
    "HIGH": colors.HexColor("#ff9d5c"),
    "MEDIUM": colors.HexColor("#ffd166"),
    "LOW": colors.HexColor("#8ecae6"),
}

GRADE_COLOURS = {
    "A": colors.HexColor("#7ee0c3"),
    "B": colors.HexColor("#8ecae6"),
    "C": colors.HexColor("#ffd166"),
    "D": colors.HexColor("#ff9d5c"),
    "E": colors.HexColor("#ff7d6b"),
    "F": colors.HexColor("#ff5d7a"),
}

CONTENT_WIDTH = 174 * mm


def _hex(colour: colors.Color) -> str:
    """'#rrggbb' for use in reportlab's inline <font color=...> markup.

    Color.hexval() returns '0xrrggbb', which the paragraph parser rejects.
    """
    return "#" + colour.hexval()[2:]


def _plain(text: Any) -> str:
    """Transliterate to Latin-1, which is all the built-in fonts cover.

    An arrow or curly quote would otherwise render as a solid black box rather
    than fail loudly. Used for canvas/Drawing strings, which take no markup.
    """
    s = "" if text is None else str(text)
    for bad, good in {
        "→": "->", "←": "<-", "—": "-", "–": "-",
        "‘": "'", "’": "'", "“": '"', "”": '"',
        "•": "*", "·": "-", "…": "...",
    }.items():
        s = s.replace(bad, good)
    return s.encode("latin-1", "replace").decode("latin-1")


def _safe(text: Any) -> str:
    """_plain, plus escaping so resource names can't be parsed as markup."""
    return _plain(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _dark_page(canvas, doc) -> None:
    """Paint the page black before anything else lands on it."""
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], stroke=0, fill=1)

    canvas.setFillColor(FAINT)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 10 * mm, "CloudChain Posture Report")
    canvas.drawRightString(doc.pagesize[0] - 18 * mm, 10 * mm, f"page {canvas.getPageNumber()}")
    canvas.restoreState()


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    def style(name, **kw):
        kw.setdefault("textColor", INK)
        kw.setdefault("alignment", TA_LEFT)
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "title": style("cc-title", fontName="Helvetica-Bold", fontSize=21, leading=25, spaceAfter=2),
        "sub": style("cc-sub", fontSize=8.5, leading=12, textColor=FAINT),
        "h2": style("cc-h2", fontName="Helvetica-Bold", fontSize=12, leading=16,
                    spaceBefore=15, spaceAfter=5),
        "body": style("cc-body", fontSize=9, leading=13, textColor=INK),
        "small": style("cc-small", fontSize=7.8, leading=11),
        "muted": style("cc-muted", fontSize=8, leading=11.5, textColor=MUTED),
        "step": style("cc-step", fontSize=8.5, leading=12.5, leftIndent=12, textColor=INK),
        "th": style("cc-th", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED),
    }


def _table(rows: List[List[Any]], widths: List[float], header: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), PANEL),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), PANEL_ALT),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
        ]
    t.setStyle(TableStyle(style))
    return t


# --------------------------------------------------------------- graphics


def _score_graphic(score: int, grade: str, total_deducted: float) -> Drawing:
    """The headline number, drawn rather than typeset.

    Drawing it sidesteps the leading problem entirely and gives the score the
    visual weight it has on the dashboard.
    """
    tone = GRADE_COLOURS.get(grade, SEVERITY_COLOURS["CRITICAL"])
    height = 54
    d = Drawing(CONTENT_WIDTH, height)

    d.add(Rect(0, 0, CONTENT_WIDTH, height, fillColor=PANEL, strokeColor=RULE, strokeWidth=0.5))
    d.add(String(14, height - 26, str(score), fontName="Helvetica-Bold", fontSize=30, fillColor=tone))

    num_width = 20 + len(str(score)) * 17
    d.add(String(num_width, height - 26, "/ 100", fontName="Helvetica", fontSize=10, fillColor=FAINT))
    d.add(String(num_width, height - 40, _plain(f"GRADE {grade}"), fontName="Helvetica-Bold",
                 fontSize=10, fillColor=tone))

    # Progress track. The filled portion is the score, so a shorter bar is a
    # worse account -- the same direction as the gauge on screen.
    bar_x, bar_w, bar_h = 130, CONTENT_WIDTH - 130 - 14, 10
    bar_y = height - 30
    d.add(Rect(bar_x, bar_y, bar_w, bar_h, fillColor=TRACK, strokeColor=None))
    d.add(Rect(bar_x, bar_y, max(bar_w * score / 100.0, 1.5), bar_h, fillColor=tone, strokeColor=None))
    d.add(String(bar_x, bar_y - 12, _plain(f"{total_deducted:.1f} points deducted from 100"),
                 fontName="Helvetica", fontSize=7.5, fillColor=FAINT))
    return d


def _dimension_graphic(components: List[Dict[str, Any]]) -> Drawing:
    """One bar per dimension, each scaled to its own maximum.

    Scaling per dimension rather than to a shared axis is deliberate: the
    question a reader has is "how much of this dimension's budget was spent",
    and a shared axis would make the 20-point dimension look inherently safer
    than the 30-point one.
    """
    row_h, pad_top = 20, 8
    height = pad_top + row_h * len(components) + 6
    d = Drawing(CONTENT_WIDTH, height)
    d.add(Rect(0, 0, CONTENT_WIDTH, height, fillColor=PANEL, strokeColor=RULE, strokeWidth=0.5))

    label_w, value_w = 78, 62
    bar_x = label_w + 10
    bar_w = CONTENT_WIDTH - bar_x - value_w - 12

    for i, c in enumerate(components):
        y = height - pad_top - (i + 1) * row_h + 6
        share = (c["points_lost"] / c["weight"]) if c["weight"] else 0.0
        tone = (
            SEVERITY_COLOURS["CRITICAL"] if share >= 0.66
            else SEVERITY_COLOURS["MEDIUM"] if share >= 0.33
            else GRADE_COLOURS["A"]
        )

        d.add(String(12, y + 2, _plain(c["name"]), fontName="Helvetica-Bold", fontSize=8, fillColor=INK))
        d.add(Rect(bar_x, y, bar_w, 8, fillColor=TRACK, strokeColor=None))
        if share > 0:
            d.add(Rect(bar_x, y, max(bar_w * share, 1.5), 8, fillColor=tone, strokeColor=None))
        d.add(String(bar_x + bar_w + 8, y + 1,
                     _plain(f"{c['points_lost']:.1f} / {c['weight']:g}"),
                     fontName="Helvetica", fontSize=7.5, fillColor=tone))
    return d


def _severity_graphic(by_severity: Dict[str, int]) -> Drawing:
    """Severity counts as a proportional stacked bar plus a legend."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = [max(int(by_severity.get(s, 0)), 0) for s in order]
    total = sum(counts) or 1

    height = 44
    d = Drawing(CONTENT_WIDTH, height)
    d.add(Rect(0, 0, CONTENT_WIDTH, height, fillColor=PANEL, strokeColor=RULE, strokeWidth=0.5))

    bar_x, bar_w, bar_y = 12, CONTENT_WIDTH - 24, height - 20
    d.add(Rect(bar_x, bar_y, bar_w, 9, fillColor=TRACK, strokeColor=None))

    x = bar_x
    for sev, count in zip(order, counts):
        if not count:
            continue
        seg = bar_w * count / total
        d.add(Rect(x, bar_y, seg, 9, fillColor=SEVERITY_COLOURS[sev], strokeColor=None))
        x += seg

    lx = 12
    for sev, count in zip(order, counts):
        d.add(Rect(lx, 11, 7, 7, fillColor=SEVERITY_COLOURS[sev], strokeColor=None))
        d.add(String(lx + 11, 12, _plain(f"{sev} {count}"), fontName="Helvetica",
                     fontSize=7.5, fillColor=MUTED))
        lx += 108
    return d


# ----------------------------------------------------------------- sections


def _paths_section(title: str, note: str, paths: List[Dict[str, Any]], S) -> List[Any]:
    out: List[Any] = [Paragraph(_safe(title), S["h2"])]
    if note:
        out.append(Paragraph(_safe(note), S["muted"]))
        out.append(Spacer(1, 5))

    if not paths:
        out.append(Paragraph("None found.", S["body"]))
        return out

    for path in paths:
        block: List[Any] = []
        tags = [path.get("severity", "")]
        if path.get("crosses_accounts"):
            tags.append("crosses " + ", ".join(path.get("accounts", [])))
        tone = SEVERITY_COLOURS.get(path.get("severity"), SEVERITY_COLOURS["CRITICAL"])
        block.append(
            Paragraph(
                f'<font color="{_hex(tone)}"><b>{_safe(" | ".join(t for t in tags if t))}</b></font>',
                S["small"],
            )
        )
        for i, step in enumerate(path.get("steps", []), start=1):
            block.append(Paragraph(f"{i}. {_safe(step)}", S["step"]))
        block.append(Spacer(1, 9))
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
    components = posture.get("components") or []
    story: List[Any] = []

    story.append(Paragraph("CloudChain Posture Report", S["title"]))
    story.append(
        Paragraph(
            _safe(
                f"Scan {report.get('scan_id', '')} | {report.get('mode', '')} mode | "
                f"{report.get('timestamp', '')}"
            ),
            S["sub"],
        )
    )
    story.append(Spacer(1, 12))

    # --- posture ---------------------------------------------------------
    story.append(
        _score_graphic(
            int(posture.get("score", 0) or 0),
            str(posture.get("grade", "?")),
            float(posture.get("total_deducted", 0) or 0),
        )
    )
    if posture.get("explanation"):
        story.append(Spacer(1, 8))
        story.append(Paragraph(_safe(posture["explanation"]), S["body"]))

    if components:
        story.append(Paragraph("How the score was calculated", S["h2"]))
        story.append(_dimension_graphic(components))
        story.append(Spacer(1, 8))
        rows = [[Paragraph(h, S["th"]) for h in ("Dimension", "Deducted", "What it measured")]]
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
        rows = [[Paragraph(h, S["th"]) for h in ("Account", "Name", "Findings")]]
        for a in accounts:
            rows.append(
                [
                    Paragraph(_safe(a["id"]), S["small"]),
                    Paragraph(_safe(a["name"]), S["small"]),
                    Paragraph(str(a["findings"]), S["small"]),
                ]
            )
        story.append(_table(rows, [40 * mm, 60 * mm, 25 * mm]))

    # --- severity --------------------------------------------------------
    story.append(Paragraph("Findings by severity", S["h2"]))
    story.append(_severity_graphic(summary.get("by_severity") or {}))

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
        # Deliberately no page break: the paths section varies in length, and
        # forcing one left half a page blank on most reports.
        story.append(Paragraph(f"All findings ({len(findings)})", S["h2"]))
        rows = [[Paragraph(h, S["th"]) for h in ("#", "Score", "Severity", "Issue", "Resource")]]
        for f in findings:
            tone = SEVERITY_COLOURS.get(f.get("severity"), INK)
            rows.append(
                [
                    Paragraph(str(f.get("rank", "")), S["small"]),
                    Paragraph(str(f.get("risk_score", "")), S["small"]),
                    Paragraph(
                        f'<font color="{_hex(tone)}"><b>{_safe(f.get("severity"))}</b></font>',
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
            story.append(Spacer(1, 6))

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
                Paragraph(
                    f'<font color="{_hex(SEVERITY_COLOURS["HIGH"])}">NEW</font>  '
                    f"{_safe(e['issue_code'])} on {_safe(e['resource_id'])}",
                    S["small"],
                )
            )
        for e in drift["resolved_findings"]:
            story.append(
                Paragraph(
                    f'<font color="{_hex(GRADE_COLOURS["A"])}">RESOLVED</font>  '
                    f"{_safe(e['issue_code'])} on {_safe(e['resource_id'])}",
                    S["small"],
                )
            )

    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            "Generated by CloudChain. Every number in this report is derived from the "
            "same scan result the dashboard renders.",
            S["muted"],
        )
    )

    doc.build(story, onFirstPage=_dark_page, onLaterPages=_dark_page)
    return buf.getvalue()
