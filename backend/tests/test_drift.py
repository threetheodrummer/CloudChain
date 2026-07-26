from app.models import Finding, ScanResult, Severity
from app.storage.drift import compare_scans


def _finding(resource_id, issue_code, dedupe_key=""):
    return Finding(
        resource_id=resource_id,
        resource_type="s3_bucket",
        issue_code=issue_code,
        title="t",
        description="d",
        base_severity=Severity.MEDIUM,
        remediation="fix it",
        dedupe_key=dedupe_key,
    )


def _scan(scan_id, findings):
    from app.risk import score_findings

    return ScanResult(scan_id=scan_id, mode="demo", findings=score_findings(findings, set()))


def test_first_scan_has_no_previous_everything_is_new():
    current = _scan("scan-1", [_finding("b1", "ISSUE_A")])
    drift = compare_scans(current, previous=None)
    assert drift.previous_scan_id is None
    assert len(drift.new_findings) == 1
    assert drift.resolved_findings == []
    assert drift.unchanged_count == 0


def test_identical_scans_are_fully_unchanged():
    findings = [_finding("b1", "ISSUE_A"), _finding("b2", "ISSUE_B")]
    previous = _scan("scan-1", findings)
    current = _scan("scan-2", findings)
    drift = compare_scans(current, previous)
    assert drift.new_findings == []
    assert drift.resolved_findings == []
    assert drift.unchanged_count == 2


def test_new_and_resolved_findings_detected():
    previous = _scan("scan-1", [_finding("b1", "ISSUE_A"), _finding("b2", "ISSUE_B")])
    current = _scan("scan-2", [_finding("b1", "ISSUE_A"), _finding("b3", "ISSUE_C")])
    drift = compare_scans(current, previous)

    assert len(drift.new_findings) == 1
    assert drift.new_findings[0].resource_id == "b3"

    assert len(drift.resolved_findings) == 1
    assert drift.resolved_findings[0].resource_id == "b2"

    assert drift.unchanged_count == 1


def test_dedupe_key_distinguishes_same_resource_and_issue_code():
    previous = _scan("scan-1", [_finding("sg1", "SG_OPEN", dedupe_key="22")])
    current = _scan("scan-2", [_finding("sg1", "SG_OPEN", dedupe_key="22"), _finding("sg1", "SG_OPEN", dedupe_key="3389")])
    drift = compare_scans(current, previous)
    assert len(drift.new_findings) == 1  # only the port-3389 rule is new
    assert drift.unchanged_count == 1
