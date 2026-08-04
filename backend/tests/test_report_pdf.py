"""
PDF report export.

The document is generated server-side from the same report dict the dashboard
renders, so these tests mostly guard that promise: everything on screen reaches
the file, and nothing in it can render as a black box.
"""
import pytest

from app.pipeline import run_scan
from app.report.generator import build_report
from app.report.pdf import _hex, _safe, build_report_pdf

pypdf = pytest.importorskip("pypdf")


@pytest.fixture(scope="module")
def report():
    result, drift = run_scan(mode="demo", persist=False)
    return build_report(result, drift)


@pytest.fixture(scope="module")
def pdf_text(report):
    data = build_report_pdf(report)
    reader = pypdf.PdfReader(__import__("io").BytesIO(data))
    return "".join(page.extract_text() for page in reader.pages)


def test_output_is_a_real_pdf(report):
    data = build_report_pdf(report)
    assert data.startswith(b"%PDF-")
    assert len(data) > 2000


def test_every_major_section_reaches_the_document(pdf_text):
    for section in (
        "CloudChain Posture Report",
        "How the score was calculated",
        "Findings by severity",
        "Attack paths",
        "Escalation routes",
        "All findings",
        "Remediation",
    ):
        assert section in pdf_text, f"missing section: {section}"


def test_the_headline_number_matches_the_report(report, pdf_text):
    posture = report["posture"]
    assert str(posture["score"]) in pdf_text
    assert f"GRADE {posture['grade']}" in pdf_text


def test_both_kinds_of_path_are_labelled_distinctly(report, pdf_text):
    """The PDF must not blur a live breach route into a latent primitive."""
    assert "unauthenticated attacker can walk" in pdf_text
    assert "once the starting identity is compromised" in pdf_text


def test_multi_account_scans_list_their_accounts(report, pdf_text):
    if len(report.get("accounts", [])) > 1:
        assert "Accounts scanned" in pdf_text
        for account in report["accounts"]:
            assert account["name"] in pdf_text


def test_findings_and_their_remediation_are_present(report, pdf_text):
    top = report["findings"][0]
    assert top["issue_code"] in pdf_text
    assert top["resource_id"] in pdf_text


# ------------------------------------------------------------- text safety


def test_characters_outside_latin1_are_transliterated():
    """reportlab's built-in fonts are Latin-1 only; an arrow would render as a
    solid black box rather than fail loudly, so it's replaced up front."""
    assert _safe("a → b") == "a -&gt; b"
    assert _safe("don’t") == "don't"
    assert "—" not in _safe("dash — here")


def test_markup_characters_are_escaped():
    """Resource names are user data and must not be parsed as reportlab markup."""
    assert _safe("<b>not-bold</b>") == "&lt;b&gt;not-bold&lt;/b&gt;"
    assert _safe("a & b") == "a &amp; b"


def test_none_becomes_empty_not_the_string_none():
    assert _safe(None) == ""


def test_hex_helper_produces_parser_ready_colour():
    """Color.hexval() returns '0xrrggbb', which reportlab's parser rejects."""
    from reportlab.lib import colors

    assert _hex(colors.HexColor("#991b1b")) == "#991b1b"


# ------------------------------------------------------------- robustness


def test_an_empty_report_still_renders():
    """A clean account has no paths and no findings; that must not crash."""
    data = build_report_pdf(
        {"scan_id": "empty", "mode": "demo", "timestamp": "", "summary": {}, "posture": {}}
    )
    assert data.startswith(b"%PDF-")


def test_a_scan_with_no_paths_says_so(report):
    stripped = dict(report, attack_paths=[], escalation_paths=[])
    reader = pypdf.PdfReader(__import__("io").BytesIO(build_report_pdf(stripped)))
    text = "".join(p.extract_text() for p in reader.pages)
    assert "None found." in text
