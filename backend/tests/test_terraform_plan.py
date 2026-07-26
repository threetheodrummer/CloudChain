"""
Shift-left: analysing a Terraform plan before it is applied.

The property that makes this worth shipping is *parity*. A pre-deploy check
that uses its own rules is worse than useless, because it teaches people the
gate and the real scanner disagree. So the tests here assert that plan
scanning goes through the same scanners and the same graph engine as a live
scan, and that its silences are deliberate rather than accidental.
"""
import json
from pathlib import Path

import pytest

from app.graph import build_attack_graph, find_escalation_paths
from app.models import Finding, Severity
from app.pipeline import analyse_sources
from app.terraform import PlanDataSource, analyse_plan, parse_plan
from app.terraform.analyzer import format_pr_comment

FIXTURES = Path(__file__).parent / "fixtures"


def _plan(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def risky():
    return _plan("plan_introduces_path")


@pytest.fixture
def safe():
    return _plan("plan_safe")


# ------------------------------------------------------------------ parsing


def test_parse_plan_groups_resources_by_type(risky):
    by_type = parse_plan(risky)
    assert "aws_s3_bucket" in by_type
    assert "aws_iam_role" in by_type


def test_parse_plan_accepts_raw_json_text(risky):
    assert parse_plan(json.dumps(risky)) == parse_plan(risky)


def test_plan_source_reads_bucket_configuration(risky):
    src = PlanDataSource(risky)
    assert src.list_buckets() == ["ci-artifacts-bucket"]
    assert src.is_bucket_acl_public("ci-artifacts-bucket") is True
    assert src.is_bucket_encrypted("ci-artifacts-bucket") is False
    assert "ci/credentials.csv" in src.list_object_keys("ci-artifacts-bucket")


def test_plan_source_resolves_policies_through_attachments(risky):
    src = PlanDataSource(risky)
    assert src.list_user_policy_names("ci-deployer") == ["CiDeployPolicy"]
    actions = {a for a, _ in src.get_policy_statements("CiDeployPolicy")}
    assert "iam:PassRole" in actions
    assert "lambda:CreateFunction" in actions


def test_plan_source_understands_aws_managed_policy_arns(risky):
    """A plan references AdministratorAccess by ARN without its contents."""
    src = PlanDataSource(risky)
    assert src.list_role_policy_names("CiExecutionRole") == ["AdministratorAccess"]
    assert ("*", "*") in src.get_policy_statements("AdministratorAccess")


def test_locked_down_bucket_is_read_as_locked_down(safe):
    src = PlanDataSource(safe)
    pab = src.get_public_access_block("ci-artifacts-bucket")
    assert all(pab.values())
    assert src.is_bucket_acl_public("ci-artifacts-bucket") is False
    assert src.is_bucket_versioned("ci-artifacts-bucket") is True


# ------------------------------------------- deliberate silences, not bugs


def test_runtime_only_checks_stay_silent_on_a_plan(risky):
    """MFA enrolment and key age are not in any plan.

    Guessing would flag every pull request for something the author cannot fix
    from Terraform, which is how shift-left gates get switched off.
    """
    src = PlanDataSource(risky)
    assert src.user_has_mfa("ci-deployer") is True
    assert src.list_access_keys("ci-deployer") == []

    result = analyse_sources([src], scan_id="plan", mode="plan")
    codes = {f.issue_code for f in result.findings}
    assert "IAM_USER_NO_MFA" not in codes
    assert "IAM_STALE_ACCESS_KEY" not in codes


def test_unmanaged_password_policy_is_not_reported(safe):
    src = PlanDataSource(safe)
    result = analyse_sources([src], scan_id="plan", mode="plan")
    assert "IAM_WEAK_PASSWORD_POLICY" not in {f.issue_code for f in result.findings}


# -------------------------------------------------------------- parity


def test_plan_scanning_uses_the_same_scanners_as_a_live_scan(risky):
    """Plan and live analysis must be the same code path, not a parallel one."""
    src = PlanDataSource(risky, account_id="111111111111", account_name="prod")
    result = analyse_sources([src], scan_id="plan", mode="plan")

    codes = {f.issue_code for f in result.findings}
    assert {"S3_PUBLIC_ACCESS", "IAM_PRIVILEGE_ESCALATION_RISK", "IAM_ROLE_ADMIN_ACCESS"} <= codes
    for f in result.findings:
        assert f.account_id == "111111111111"


def test_escalation_path_is_found_in_the_planned_state(risky):
    src = PlanDataSource(risky, account_id="111111111111", account_name="prod")
    result = analyse_sources([src], scan_id="plan", mode="plan")

    graph, by_resource = build_attack_graph(result.findings)
    escalations = find_escalation_paths(graph, by_resource)
    assert escalations, "planned state should contain an identity-to-admin route"
    assert all(p.entry_kind == "identity" for p in escalations)


def test_an_identity_that_is_already_admin_is_not_an_escalation():
    """Holding admin isn't escalating to it -- a direct edge must not count."""
    finding = Finding(
        account_id="111111111111",
        resource_id="root-ish-user",
        resource_type="iam_user",
        issue_code="IAM_OVERPERMISSIVE_POLICY",
        title="t",
        description="d",
        base_severity=Severity.CRITICAL,
        remediation="fix",
    )
    graph, by_resource = build_attack_graph([finding])
    assert find_escalation_paths(graph, by_resource) == []


# -------------------------------------------------------------- verdicts


def test_plan_that_opens_a_route_to_admin_blocks(risky):
    analysis = analyse_plan(risky, account_id="111111111111", account_name="prod")
    assert analysis["verdict"] == "BLOCK"
    assert analysis["new_paths"]
    assert "Blocking" in analysis["summary"]


def test_safe_plan_passes(safe):
    analysis = analyse_plan(safe, account_id="111111111111", account_name="prod")
    assert analysis["verdict"] == "PASS"
    assert analysis["new_paths"] == []
    assert analysis["posture"]["after"] == 100


def test_verdict_is_a_diff_not_an_absolute_judgement(risky):
    """Re-running against a baseline that already contains the risk must not
    block: the change introduced nothing new."""
    from app.models import ScanResult

    src = PlanDataSource(risky, account_id="111111111111", account_name="prod")
    already = analyse_sources([src], scan_id="baseline", mode="demo")
    baseline = ScanResult(
        scan_id="baseline",
        mode="demo",
        findings=already.findings,
        attack_paths=already.attack_paths,
        graph=already.graph,
    )

    analysis = analyse_plan(risky, baseline=baseline, account_id="111111111111")
    assert analysis["verdict"] == "PASS"
    assert analysis["new_paths"] == []


def test_removing_risk_is_reported_as_an_improvement(risky, safe):
    from app.models import ScanResult

    src = PlanDataSource(risky, account_id="111111111111", account_name="prod")
    before = analyse_sources([src], scan_id="baseline", mode="demo")
    baseline = ScanResult(
        scan_id="baseline",
        mode="demo",
        findings=before.findings,
        attack_paths=before.attack_paths,
        graph=before.graph,
    )

    analysis = analyse_plan(safe, baseline=baseline, account_id="111111111111")
    assert analysis["verdict"] == "PASS"
    assert analysis["removed_paths"] or analysis["removed_findings"]


def test_account_defaults_to_the_baselines_dominant_account(risky):
    """Node ids are account-namespaced; a mismatched account would report every
    path as new, which would make the gate meaningless."""
    from app.pipeline import run_scan

    baseline, _ = run_scan(mode="demo", persist=False)
    analysis = analyse_plan(risky, baseline=baseline)

    planned = analysis["planned_report"]
    assert all(f["account_id"] == "111111111111" for f in planned["findings"])


# ------------------------------------------------------------ pr comment


def test_pr_comment_renders_the_verdict_and_the_path(risky):
    comment = format_pr_comment(analyse_plan(risky, account_id="111111111111", account_name="prod"))
    assert comment.startswith("## ")
    assert "BLOCK" in comment
    assert "New path to AdministratorAccess" in comment
    assert "| Severity | Issue | Resource | Fix |" in comment


def test_pr_comment_for_a_clean_plan_stays_short(safe):
    comment = format_pr_comment(analyse_plan(safe, account_id="111111111111"))
    assert "PASS" in comment
    assert "New path" not in comment


# --------------------------------------------------------------- robustness


def test_empty_plan_is_handled_not_crashed():
    analysis = analyse_plan({"planned_values": {"root_module": {}}})
    assert analysis["verdict"] == "PASS"
    assert analysis["posture"]["after"] == 100


def test_a_document_that_is_not_a_plan_is_rejected():
    """Silently passing an unparseable file would be the worst outcome: CI goes
    green because nothing was actually checked."""
    with pytest.raises(ValueError, match="not a Terraform plan"):
        parse_plan({"nonsense": 1})


# ----------------------------------------------------------------- scoping


def test_a_partial_plan_does_not_claim_to_have_removed_the_rest(risky):
    """The plan mentions one bucket and one user; the account has far more.

    Everything it doesn't mention is out of scope, not fixed. Without this the
    tool would tell a developer their two-resource pull request resolved most
    of the organisation's findings.
    """
    from app.pipeline import run_scan

    baseline, _ = run_scan(mode="demo", persist=False)
    analysis = analyse_plan(risky, baseline=baseline)

    removed = {f["resource_id"] for f in analysis["removed_findings"]}
    assert "public-uploads-bucket" not in removed
    assert "svc-deploy-bot" not in removed
    assert not analysis["removed_paths"]


def test_posture_delta_is_withheld_when_scopes_differ(risky):
    """Scoring a two-resource plan against a three-account org and calling the
    difference an improvement would be meaningless."""
    from app.pipeline import run_scan

    baseline, _ = run_scan(mode="demo", persist=False)
    analysis = analyse_plan(risky, baseline=baseline)

    posture = analysis["posture"]
    assert posture["comparable"] is False
    assert posture["before"] is None
    assert posture["delta"] is None
    assert "not comparable" in posture["note"]


def test_posture_delta_is_reported_when_scopes_match(risky, safe):
    from app.models import ScanResult

    src = PlanDataSource(risky, account_id="111111111111", account_name="prod")
    before = analyse_sources([src], scan_id="baseline", mode="demo")
    baseline = ScanResult(
        scan_id="baseline",
        mode="demo",
        findings=before.findings,
        attack_paths=before.attack_paths,
        graph=before.graph,
    )

    analysis = analyse_plan(risky, baseline=baseline, account_id="111111111111")
    assert analysis["posture"]["comparable"] is True
    assert analysis["posture"]["delta"] == 0


def test_plan_scope_lists_everything_it_describes(risky):
    src = PlanDataSource(risky, account_id="111111111111")
    scope = src.describes_resources()
    assert ("111111111111", "s3_bucket", "ci-artifacts-bucket") in scope
    assert ("111111111111", "iam_user", "ci-deployer") in scope
    assert ("111111111111", "iam_role", "CiExecutionRole") in scope


def test_child_modules_are_walked(risky):
    """Real plans nest most resources inside modules."""
    nested = {
        "planned_values": {
            "root_module": {
                "child_modules": [risky["planned_values"]["root_module"]]
            }
        }
    }
    src = PlanDataSource(nested)
    assert src.list_buckets() == ["ci-artifacts-bucket"]
    assert src.list_iam_roles() == ["CiExecutionRole"]
