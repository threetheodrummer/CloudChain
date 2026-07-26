"""
Organisation-wide scanning.

The behaviour worth protecting is that a chain crossing an account boundary is
found *and* correctly distinguished from a same-account one. Two accounts can
each look defensible in isolation while the pair is wide open, and that is
precisely the case single-account tooling misses.
"""
import pytest

from app.demo import mock_aws
from app.graph import build_attack_graph, find_attack_paths, node_id, parse_node
from app.models import Finding, Severity, VerdictStatus
from app.pipeline import run_scan
from app.report.generator import build_report
from app.risk import compute_posture
from app.sources import DemoAWSDataSource, get_data_sources
from app.validation import validate_paths


@pytest.fixture(scope="module")
def scan():
    result, _ = run_scan(mode="demo", persist=False)
    return result


@pytest.fixture(scope="module")
def cross_path(scan):
    crossing = [p for p in scan.attack_paths if p.crosses_accounts]
    assert crossing, "the demo org must produce a cross-account chain"
    return crossing[0]


# ------------------------------------------------------------ node identity


def test_node_id_round_trips_through_parse_node():
    nid = node_id("iam_role", "OrgDeploymentRole", "222222222222")
    assert parse_node(nid) == ("222222222222", "iam_role", "OrgDeploymentRole")


def test_unattributed_nodes_keep_the_single_account_form():
    """Findings with no account must behave exactly as they did before."""
    nid = node_id("s3_bucket", "b")
    assert nid == "s3_bucket:b"
    assert parse_node(nid) == ("", "s3_bucket", "b")


def test_resources_with_the_same_name_in_different_accounts_stay_distinct():
    def f(account):
        return Finding(
            account_id=account,
            resource_id="shared-name",
            resource_type="iam_role",
            issue_code="IAM_ROLE_ADMIN_ACCESS",
            title="t",
            description="d",
            base_severity=Severity.HIGH,
            remediation="fix",
        )

    g, _ = build_attack_graph([f("111111111111"), f("222222222222")])
    roles = [n for n in g.nodes if parse_node(n)[1] == "iam_role"]
    assert len(roles) == 2, "same-named roles in different accounts must not collapse"


# --------------------------------------------------------------- discovery


def test_identical_findings_in_two_accounts_get_distinct_fingerprints():
    """Resource names are only unique within an account.

    Every account has an "account" pseudo-resource for its password policy. If
    the account isn't part of the fingerprint these collapse into one id, and
    drift silently under-reports across the whole org.
    """

    def weak_policy(account):
        return Finding(
            account_id=account,
            resource_id="account",
            resource_type="iam_account",
            issue_code="IAM_WEAK_PASSWORD_POLICY",
            title="t",
            description="d",
            base_severity=Severity.MEDIUM,
            remediation="fix",
        )

    a = weak_policy("111111111111")
    b = weak_policy("222222222222")
    assert a.id != b.id


def test_scan_covers_every_account_in_the_org(scan):
    scanned = {f.account_id for f in scan.findings}
    assert scanned == {a["id"] for a in mock_aws.ACCOUNTS}


def test_both_a_local_and_a_cross_account_chain_are_found(scan):
    assert len(scan.attack_paths) >= 2
    assert any(p.crosses_accounts for p in scan.attack_paths)
    assert any(not p.crosses_accounts for p in scan.attack_paths)


def test_cross_account_path_ends_in_the_trusting_account(cross_path):
    """The payoff is admin in the *other* account, not the compromised one."""
    entry_account = parse_node(cross_path.node_ids[0])[0]
    sink_account = parse_node(cross_path.node_ids[-1])[0]
    assert entry_account == mock_aws.PROD
    assert sink_account == mock_aws.SHARED
    assert cross_path.accounts == sorted([mock_aws.PROD, mock_aws.SHARED])


def test_cross_account_hop_uses_assume_role_not_passrole(scan, cross_path):
    """PassRole is same-account by AWS's rules and must never be used to cross.

    If this ever fails, the graph is reporting a chain that cannot actually be
    walked -- the exact failure mode that makes people distrust CSPM output.
    """
    edges = {(e.source, e.target): e.relation for e in scan.graph.edges}
    crossings = [
        edges[(a, b)]
        for a, b in zip(cross_path.node_ids, cross_path.node_ids[1:])
        if parse_node(a)[0] != parse_node(b)[0]
    ]
    assert crossings, "expected at least one boundary-crossing edge"
    for relation in crossings:
        assert relation == "can_assume_cross_account"
        assert "pass_role" not in relation


def test_narrative_calls_out_the_boundary(cross_path):
    assert "crosses an account boundary" in cross_path.narrative


def test_trust_on_root_principal_does_not_become_a_path():
    """':root' trusts a whole account, not one identity -- no edge to draw."""
    finding = Finding(
        account_id="222222222222",
        resource_id="AuditReadOnlyRole",
        resource_type="iam_role",
        issue_code="IAM_CROSS_ACCOUNT_TRUST",
        title="t",
        description="d",
        base_severity=Severity.MEDIUM,
        remediation="fix",
        evidence={"trusted_principals": ["arn:aws:iam::333333333333:root"]},
    )
    g, _ = build_attack_graph([finding])
    assert not [e for e in g.edges if g.edges[e]["relation"] == "can_assume_cross_account"]


# ---------------------------------------------------------------- scoring


def test_cross_account_chain_costs_more_than_a_local_one(scan):
    local = [p for p in scan.attack_paths if not p.crosses_accounts][:1]
    crossing = [p for p in scan.attack_paths if p.crosses_accounts][:1]

    local_score = compute_posture(scan.findings, local, scan.graph)["score"]
    cross_score = compute_posture(scan.findings, crossing, scan.graph)["score"]
    assert cross_score < local_score


def test_reachability_names_the_boundary_crossing(scan):
    posture = compute_posture(scan.findings, scan.attack_paths, scan.graph)
    reach = next(c for c in posture["components"] if c["key"] == "reachability")
    labels = " ".join(f["label"] for f in reach["factors"])
    assert "account boundary" in labels.lower()


# -------------------------------------------------------------- validation


def test_cross_account_path_validates_against_the_owning_account(scan, cross_path):
    """The trust policy lives with the role, so that hop must be checked
    against the account that owns the role -- not the compromised one."""
    validations = validate_paths([cross_path], get_data_sources("demo"), scan.graph)
    v = validations[0]

    assert v.status is VerdictStatus.CONFIRMED
    hop = next(h for h in v.hops if h.relation == "can_assume_cross_account")
    assert any(c.api == "iam:GetRole" for c in hop.calls)
    assert mock_aws.PROD in hop.reason and mock_aws.SHARED in hop.reason


def test_missing_credentials_for_an_account_is_unverifiable_not_confirmed(scan, cross_path):
    """Only holding prod's credentials must not yield a CONFIRMED verdict on a
    chain whose final hops live in another account."""
    prod_only = [DemoAWSDataSource(account_id=mock_aws.PROD)]
    v = validate_paths([cross_path], prod_only, scan.graph)[0]
    assert v.status is not VerdictStatus.CONFIRMED


def test_revoking_the_trust_policy_refutes_the_cross_account_path(scan, cross_path):
    class TrustRevoked(DemoAWSDataSource):
        def list_role_trust_principals(self, role):
            return []

    sources = [
        DemoAWSDataSource(account_id=mock_aws.PROD),
        TrustRevoked(account_id=mock_aws.SHARED),
        DemoAWSDataSource(account_id=mock_aws.SANDBOX),
    ]
    v = validate_paths([cross_path], sources, scan.graph)[0]
    assert v.status is VerdictStatus.REFUTED


# ------------------------------------------------------------------ report


def test_report_rolls_findings_up_by_account(scan):
    report = build_report(scan)
    assert report["summary"]["accounts_scanned"] == len(mock_aws.ACCOUNTS)
    assert report["summary"]["cross_account_paths"] >= 1

    rollup = report["accounts"]
    assert {a["name"] for a in rollup} == {a["name"] for a in mock_aws.ACCOUNTS}
    assert sum(a["findings"] for a in rollup) == report["summary"]["total_findings"]
    # Sorted worst-first so the dashboard leads with the account that matters.
    assert rollup == sorted(rollup, key=lambda a: a["findings"], reverse=True)


def test_findings_carry_their_account(scan):
    report = build_report(scan)
    for f in report["findings"]:
        assert f["account_id"], f"{f['issue_code']} on {f['resource_id']} is unattributed"
        assert f["account_name"]
