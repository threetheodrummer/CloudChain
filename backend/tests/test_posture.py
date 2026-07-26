from app.models import AttackPath, Finding, Severity
from app.risk import compute_posture, grade_for, score_findings
from app.risk.posture import ATTACK_PATH_PENALTY, SEVERITY_PENALTY


def _scored(severities):
    findings = [
        Finding(
            resource_id=f"r{i}",
            resource_type="s3_bucket",
            issue_code=f"ISSUE_{i}",
            title="t",
            description="d",
            base_severity=sev,
            remediation="fix",
        )
        for i, sev in enumerate(severities)
    ]
    return score_findings(findings, set())


def _path():
    return AttackPath(path_id="p1", node_ids=["a", "b"], steps=["a to b"], severity=Severity.CRITICAL, narrative="n")


def test_clean_account_scores_100_and_grade_a():
    p = compute_posture([], [])
    assert p["score"] == 100
    assert p["grade"] == "A"
    assert p["deductions"] == []
    assert p["auto_failed"] is False


def test_single_low_finding_barely_dents_the_score():
    p = compute_posture(_scored([Severity.LOW]), [])
    assert p["score"] == 100 - int(SEVERITY_PENALTY[Severity.LOW]) or p["score"] == 100
    assert p["grade"] == "A"


def test_each_severity_deducts_its_documented_weight():
    p = compute_posture(_scored([Severity.CRITICAL]), [])
    assert p["total_deducted"] == SEVERITY_PENALTY[Severity.CRITICAL]

    p = compute_posture(_scored([Severity.HIGH]), [])
    assert p["total_deducted"] == SEVERITY_PENALTY[Severity.HIGH]


def test_attack_path_is_the_heaviest_single_penalty():
    worst_finding = max(SEVERITY_PENALTY.values())
    assert ATTACK_PATH_PENALTY > worst_finding

    with_path = compute_posture(_scored([Severity.LOW]), [_path()])
    assert with_path["total_deducted"] >= ATTACK_PATH_PENALTY


def test_score_floors_at_zero_never_negative():
    many = _scored([Severity.CRITICAL] * 40)
    p = compute_posture(many, [_path(), _path()])
    assert p["score"] == 0
    assert p["grade"] == "F"


def test_deductions_explain_the_whole_score():
    findings = _scored([Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.LOW])
    p = compute_posture(findings, [_path()])
    listed = sum(d["points"] for d in p["deductions"])
    assert round(listed, 1) == p["total_deducted"]
    assert p["score"] == int(round(100 - listed))


def test_grade_bands_are_ordered():
    assert grade_for(100) == "A"
    assert grade_for(80) == "B"
    assert grade_for(65) == "C"
    assert grade_for(45) == "D"
    assert grade_for(25) == "E"
    assert grade_for(5) == "F"


def test_any_attack_path_forces_grade_f_regardless_of_score():
    # One LOW finding plus a takeover path still scores high numerically, but
    # the grade must be F -- the path is an automatic fail.
    p = compute_posture(_scored([Severity.LOW]), [_path()])
    assert p["score"] > 40
    assert p["grade"] == "F"
    assert p["auto_failed"] is True


def test_demo_account_grades_f_because_of_the_takeover_path():
    from app.pipeline import run_scan

    result, _ = run_scan(mode="demo", persist=False)
    p = compute_posture(result.findings, result.attack_paths)
    assert p["grade"] == "F"
    assert any("AdministratorAccess" in d["reason"] for d in p["deductions"])
