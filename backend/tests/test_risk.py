from app.models import Finding, Severity
from app.risk import score_finding, score_findings


def _finding(**overrides):
    base = dict(
        resource_id="r1",
        resource_type="s3_bucket",
        issue_code="TEST_ISSUE",
        title="t",
        description="d",
        base_severity=Severity.HIGH,
        remediation="fix it",
    )
    base.update(overrides)
    return Finding(**base)


def test_base_severity_ordering_with_no_multipliers():
    low = score_finding(_finding(base_severity=Severity.LOW), in_attack_path=False)
    medium = score_finding(_finding(base_severity=Severity.MEDIUM), in_attack_path=False)
    high = score_finding(_finding(base_severity=Severity.HIGH), in_attack_path=False)
    critical = score_finding(_finding(base_severity=Severity.CRITICAL), in_attack_path=False)
    assert low < medium < high < critical


def test_attack_path_multiplier_dominates():
    # A MEDIUM finding on an attack path should be able to outrank an
    # isolated HIGH finding once internet_facing/sensitive stack up --
    # this is the whole point of contextual scoring over static severity.
    isolated_high = score_finding(
        _finding(base_severity=Severity.HIGH, internet_facing=False, sensitive=False),
        in_attack_path=False,
    )
    chained_medium = score_finding(
        _finding(base_severity=Severity.MEDIUM, internet_facing=True, sensitive=True),
        in_attack_path=True,
    )
    assert chained_medium > isolated_high


def test_score_findings_ranks_descending_and_assigns_rank():
    findings = [
        _finding(resource_id="a", base_severity=Severity.LOW),
        _finding(resource_id="b", base_severity=Severity.CRITICAL),
        _finding(resource_id="c", base_severity=Severity.MEDIUM),
    ]
    scored = score_findings(findings, finding_ids_in_path=set())
    scores = [sf.risk_score for sf in scored]
    assert scores == sorted(scores, reverse=True)
    assert [sf.rank for sf in scored] == [1, 2, 3]
    assert scored[0].resource_id == "b"  # CRITICAL should rank first
