"""
Escalation routes in live scans.

Added after CloudChain was pointed at six deliberately-vulnerable TryHackMe AWS
accounts and reported zero attack paths in all six -- including a room built
entirely around privilege escalation. The engine could already find
identity-to-admin chains, but only Terraform plan checking ever asked it to.

Most real accounts have no internet-exposed, credential-leaking entry point, so
reporting only internet-reachable chains means reporting nothing. These tests
lock in both halves of the fix: the routes are found, and they are never
presented as equivalent to a route an unauthenticated attacker can walk.
"""
import pytest

from app.graph import build_attack_graph, find_attack_paths, find_escalation_paths, to_scan_graph
from app.models import Finding, ScanResult, Severity
from app.pipeline import run_scan
from app.report.generator import build_report
from app.risk import compute_posture, score_findings


def _finding(**overrides):
    base = dict(
        account_id="785637365768",
        account_name="thm",
        resource_id="r",
        resource_type="iam_user",
        issue_code="IAM_USER_NO_MFA",
        title="t",
        description="d",
        base_severity=Severity.MEDIUM,
        remediation="fix",
    )
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def escalation_only():
    """The shape that produced zero paths: an admin role plus a user who can
    PassRole into it, and no internet entry point anywhere."""
    findings = [
        _finding(
            resource_id="LabAdminRole",
            resource_type="iam_role",
            issue_code="IAM_ROLE_ADMIN_ACCESS",
            base_severity=Severity.HIGH,
        ),
        _finding(
            resource_id="carl-the-dev",
            issue_code="IAM_PRIVILEGE_ESCALATION_RISK",
            base_severity=Severity.CRITICAL,
            evidence={"pass_role_targets": ["LabAdminRole"]},
        ),
    ]
    graph, by_resource = build_attack_graph(findings)
    return {
        "findings": score_findings(findings, set()),
        "graph": to_scan_graph(graph),
        "attack_paths": find_attack_paths(graph, by_resource),
        "escalation_paths": find_escalation_paths(graph, by_resource),
    }


# ------------------------------------------------------------- discovery


def test_escalation_route_is_found_where_no_internet_path_exists(escalation_only):
    assert escalation_only["attack_paths"] == []
    assert len(escalation_only["escalation_paths"]) == 1

    path = escalation_only["escalation_paths"][0]
    assert path.entry_kind == "identity"
    assert path.node_ids[0].endswith("iam_user:carl-the-dev")


def test_live_scans_populate_escalation_paths():
    """The regression itself: a scan must carry these, not just plan checking."""
    result, _ = run_scan(mode="demo", persist=False)
    assert hasattr(result, "escalation_paths")
    assert result.escalation_paths, "the demo org contains identity-to-admin routes"
    assert all(p.entry_kind == "identity" for p in result.escalation_paths)


def test_the_two_kinds_are_never_merged():
    result, _ = run_scan(mode="demo", persist=False)
    assert all(p.entry_kind == "internet" for p in result.attack_paths)
    internet_ids = {p.path_id for p in result.attack_paths}
    escalation_ids = {p.path_id for p in result.escalation_paths}
    assert not (internet_ids & escalation_ids)


# --------------------------------------------------------------- scoring


def test_escalation_routes_now_move_the_score(escalation_only):
    """Before the fix this scored 91/A despite a live route to admin."""
    without = compute_posture(
        escalation_only["findings"], escalation_only["attack_paths"], escalation_only["graph"]
    )
    with_escalation = compute_posture(
        escalation_only["findings"],
        escalation_only["attack_paths"],
        escalation_only["graph"],
        escalation_only["escalation_paths"],
    )

    assert with_escalation["score"] < without["score"]
    reach = next(c for c in with_escalation["components"] if c["key"] == "reachability")
    assert reach["points_lost"] > 0


def test_an_escalation_route_never_scores_as_badly_as_an_internet_route():
    """A latent primitive is not an open door, and the score must say so."""
    findings = score_findings([_finding()], set())

    internet = ScanResult(
        scan_id="a",
        mode="demo",
        attack_paths=[
            _path(["s3_bucket:b", "iam_role:r", "admin_access:AdministratorAccess"], "internet")
        ],
    )
    escalation = ScanResult(
        scan_id="b",
        mode="demo",
        escalation_paths=[
            _path(["iam_user:u", "iam_role:r", "admin_access:AdministratorAccess"], "identity")
        ],
    )

    internet_score = compute_posture(findings, internet.attack_paths, None)["score"]
    escalation_score = compute_posture(
        findings, [], None, escalation.escalation_paths
    )["score"]

    assert escalation_score > internet_score


def _path(nodes, entry_kind):
    from app.models import AttackPath

    return AttackPath(
        path_id=f"{entry_kind}-{len(nodes)}",
        node_ids=list(nodes),
        steps=["hop"] * (len(nodes) - 1),
        severity=Severity.CRITICAL,
        narrative="n",
        entry_kind=entry_kind,
    )


def test_reachability_explains_which_kind_of_route_it_scored(escalation_only):
    posture = compute_posture(
        escalation_only["findings"],
        escalation_only["attack_paths"],
        escalation_only["graph"],
        escalation_only["escalation_paths"],
    )
    reach = next(c for c in posture["components"] if c["key"] == "reachability")

    assert "No internet-reachable route" in reach["headline"]
    assert "lower floor" in reach["method"]
    assert reach["factors"], "the escalation route must be named in the evidence"


def test_a_clean_account_still_scores_zero_reachability():
    posture = compute_posture([], [], None, [])
    reach = next(c for c in posture["components"] if c["key"] == "reachability")
    assert reach["points_lost"] == 0
    assert posture["score"] == 100


# ---------------------------------------------------------------- report


def test_report_exposes_escalation_paths_separately():
    result, _ = run_scan(mode="demo", persist=False)
    report = build_report(result)

    assert "escalation_paths" in report
    assert report["escalation_paths"]
    assert all(p["entry_kind"] == "identity" for p in report["escalation_paths"])
    assert all(p["entry_kind"] == "internet" for p in report["attack_paths"])


def test_stored_scans_without_the_field_still_load():
    """Scans persisted before escalation_paths existed must deserialize."""
    old = ScanResult(scan_id="old", mode="demo")
    assert old.escalation_paths == []
    assert build_report(old)["escalation_paths"] == []
