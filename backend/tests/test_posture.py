"""
Tests for the explainable posture engine.

The point of these tests is not just "does it return a number" -- it's that the
number is *reconstructible* from the components the engine publishes. If a
reviewer can't re-derive the score by hand from the breakdown, the
explainability claim is hollow, so that invariant is asserted directly.
"""
import pytest

from app.graph.attack_graph import ADMIN_SINK
from app.models import AttackPath, Finding, GraphEdge, GraphNode, ScanGraph, Severity
from app.risk import compute_posture, grade_for, score_findings
from app.risk.posture import COMPONENT_WEIGHTS


def _scored(severities, **overrides):
    findings = [
        Finding(
            resource_id=overrides.get("resource_id", f"r{i}"),
            resource_type=overrides.get("resource_type", "s3_bucket"),
            issue_code=overrides.get("issue_code", f"ISSUE_{i}"),
            title="t",
            description="d",
            base_severity=sev,
            internet_facing=overrides.get("internet_facing", False),
            sensitive=overrides.get("sensitive", False),
            remediation="fix",
        )
        for i, sev in enumerate(severities)
    ]
    return score_findings(findings, set())


def _path(nodes=("a", "b", ADMIN_SINK)):
    nodes = list(nodes)
    return AttackPath(
        path_id="p1",
        node_ids=nodes,
        steps=["hop"] * (len(nodes) - 1),
        severity=Severity.CRITICAL,
        narrative="n",
    )


def _graph(edges):
    ids = {n for edge in edges for n in edge}
    return ScanGraph(
        nodes=[GraphNode(id=i, type="t", label=i) for i in ids],
        edges=[GraphEdge(source=s, target=t, relation="r") for s, t in edges],
    )


# --------------------------------------------------------------------- shape


def test_clean_account_scores_100_and_grade_a():
    p = compute_posture([], [])
    assert p["score"] == 100
    assert p["grade"] == "A"
    assert p["auto_failed"] is False
    assert p["total_deducted"] == 0


def test_all_four_components_are_always_present_and_sum_to_100():
    p = compute_posture([], [])
    assert [c["key"] for c in p["components"]] == [
        "exposure",
        "privilege",
        "reachability",
        "blast_radius",
    ]
    assert sum(COMPONENT_WEIGHTS.values()) == 100.0


def test_every_component_publishes_its_method_and_stays_in_range():
    findings = _scored([Severity.CRITICAL], internet_facing=True, sensitive=True)
    p = compute_posture(findings, [_path()])
    for c in p["components"]:
        assert c["method"], f"{c['key']} must explain how its raw value was derived"
        assert 0.0 <= c["raw"] <= 1.0
        assert c["points_lost"] <= c["weight"] + 0.001


# ------------------------------------------------------------ explainability


def test_score_is_reconstructible_from_components():
    """The headline number must equal 100 minus the published deductions.

    This is the whole explainability contract: if these ever diverge, the
    dashboard is lying about its own arithmetic.
    """
    findings = _scored([Severity.CRITICAL, Severity.HIGH], internet_facing=True)
    p = compute_posture(findings, [])

    listed = sum(c["points_lost"] for c in p["components"])
    assert p["score"] == int(round(100 - listed))
    assert p["total_deducted"] == pytest.approx(listed, abs=0.01)


def test_exposure_factors_name_the_findings_behind_the_number():
    exposed = _scored([Severity.HIGH], resource_id="public-bucket", internet_facing=True)
    internal = _scored([Severity.HIGH], resource_id="private-bucket", internet_facing=False)
    p = compute_posture(exposed + internal, [])

    exposure = next(c for c in p["components"] if c["key"] == "exposure")
    labels = " ".join(f["label"] for f in exposure["factors"])
    assert "public-bucket" in labels
    assert "private-bucket" not in labels  # not internet-facing, must not count


# ---------------------------------------------------------------- behaviour


def test_confirmed_attack_path_dominates_the_score():
    """A proven route to admin should cost more than a pile of unrelated
    findings -- that's the thesis of the whole tool."""
    findings = _scored([Severity.HIGH], internet_facing=True, sensitive=True)

    without = compute_posture(findings, [])
    with_path = compute_posture(findings, [_path()])

    assert with_path["score"] < without["score"]
    reach = next(c for c in with_path["components"] if c["key"] == "reachability")
    assert reach["points_lost"] >= 0.70 * COMPONENT_WEIGHTS["reachability"]


def test_shorter_chains_are_penalised_harder():
    findings = _scored([Severity.HIGH], internet_facing=True, sensitive=True)
    long_chain = compute_posture(findings, [_path(["a", "b", "c", "d", ADMIN_SINK])])
    short_chain = compute_posture(findings, [_path(["a", ADMIN_SINK])])
    assert short_chain["score"] < long_chain["score"]


def test_blast_radius_measures_downstream_reach():
    findings = _scored(
        [Severity.HIGH], resource_id="r1", internet_facing=True, sensitive=True
    )
    graph = _graph(
        [
            ("s3_bucket:r1", "iam_user:u1"),
            ("iam_user:u1", "iam_role:admin"),
            ("iam_role:admin", ADMIN_SINK),
        ]
    )
    p = compute_posture(findings, [], graph)
    blast = next(c for c in p["components"] if c["key"] == "blast_radius")

    # The entry point reaches all 3 real nodes; the synthetic sink is excluded.
    assert blast["raw"] == pytest.approx(1.0)
    assert blast["points_lost"] == pytest.approx(COMPONENT_WEIGHTS["blast_radius"])


def test_privilege_dimension_ignores_non_identity_findings():
    storage_only = _scored([Severity.CRITICAL], issue_code="S3_PUBLIC_ACCESS")
    p = compute_posture(storage_only, [])
    privilege = next(c for c in p["components"] if c["key"] == "privilege")
    assert privilege["points_lost"] == 0
    assert privilege["factors"] == []


def test_score_floors_at_zero_never_negative():
    many = _scored([Severity.CRITICAL] * 40, internet_facing=True, sensitive=True)
    p = compute_posture(many, [_path(["a", ADMIN_SINK])] * 5)
    assert p["score"] >= 0
    assert p["grade"] == "F"


# --------------------------------------------------------------- grade rules


def test_grade_bands_are_ordered():
    assert grade_for(100) == "A"
    assert grade_for(80) == "B"
    assert grade_for(65) == "C"
    assert grade_for(45) == "D"
    assert grade_for(25) == "E"
    assert grade_for(5) == "F"


def test_any_attack_path_forces_grade_f_regardless_of_score():
    # A single low-severity finding plus a takeover path still scores high
    # numerically, but the grade must be F -- the path is an automatic fail.
    p = compute_posture(_scored([Severity.LOW]), [_path()])
    assert p["score"] > 40
    assert p["grade"] == "F"
    assert p["auto_failed"] is True
    assert "capped at F" in p["explanation"]


def test_demo_account_grades_f_because_of_the_takeover_path():
    from app.pipeline import run_scan

    result, _ = run_scan(mode="demo", persist=False)
    p = compute_posture(result.findings, result.attack_paths, result.graph)

    assert p["grade"] == "F"
    reach = next(c for c in p["components"] if c["key"] == "reachability")
    assert "AdministratorAccess" in reach["headline"]
    # Blast radius must actually engage on the demo graph, not silently skip.
    blast = next(c for c in p["components"] if c["key"] == "blast_radius")
    assert blast["points_lost"] > 0
