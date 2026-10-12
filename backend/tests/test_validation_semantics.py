"""
Validation reads permissions the same way the scanner does, and takes a second
opinion from AWS's policy simulator when one is available.

These cover the gaps that would have corrupted a real-account evaluation:
wildcard grants refuted as "no longer holds", inline policies invisible,
escalation routes with no verifier at all, and Deny/boundary/SCP effects the
static analysis cannot see.
"""
import pytest

from app.models import AttackPath, ScanGraph, GraphEdge, GraphNode, Severity, VerdictStatus
from app.pipeline import run_scan
from app.sources import DemoAWSDataSource
from app.validation import READ_ONLY_METHODS, validate_path, validate_paths

PROD = "111111111111"


@pytest.fixture(scope="module")
def demo_scan():
    result, _ = run_scan(mode="demo", persist=False)
    return result


def _in_account_path(scan):
    return next(p for p in scan.attack_paths if not p.crosses_accounts)


# ------------------------------------------------- scanner/validator parity


def test_wildcard_passrole_is_confirmed_not_refuted(demo_scan):
    """iam:* covers iam:PassRole. An exact string compare used to say otherwise."""

    class WildcardGrant(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            if name == "svc-deploy-bot":
                return [("iam:*", "*"), ("lambda:*", "*")]
            return super().get_identity_policy_statements(identity_type, name)

    v = validate_path(_in_account_path(demo_scan), WildcardGrant(account_id=PROD), demo_scan.graph)
    hop = v.hops[1]
    assert hop.relation.startswith("can_pass_role_to")
    assert hop.status is VerdictStatus.CONFIRMED, hop.reason


def test_scoped_passrole_with_wildcard_name_matches(demo_scan):
    class PrefixGrant(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            if name == "svc-deploy-bot":
                return [
                    ("iam:PassRole", f"arn:aws:iam::{PROD}:role/LambdaExecution*"),
                    ("lambda:CreateFunction", "*"),
                ]
            return super().get_identity_policy_statements(identity_type, name)

    v = validate_path(_in_account_path(demo_scan), PrefixGrant(account_id=PROD), demo_scan.graph)
    assert v.hops[1].status is VerdictStatus.CONFIRMED, v.hops[1].reason


def test_passrole_scoped_elsewhere_is_refuted(demo_scan):
    class OtherRole(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            if name == "svc-deploy-bot":
                return [
                    ("iam:PassRole", f"arn:aws:iam::{PROD}:role/SomethingHarmless"),
                    ("lambda:CreateFunction", "*"),
                ]
            return super().get_identity_policy_statements(identity_type, name)

    v = validate_path(_in_account_path(demo_scan), OtherRole(account_id=PROD), demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED
    assert "not among the permitted targets" in v.hops[1].reason


def test_admin_hop_accepts_full_iam_like_the_scanner(demo_scan):
    """The scanner treats iam:* on * as admin-equivalent; validation must too."""

    class IamStar(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            if name == "LambdaExecutionAdminRole":
                return [("iam:*", "*")]
            return super().get_identity_policy_statements(identity_type, name)

    v = validate_path(_in_account_path(demo_scan), IamStar(account_id=PROD), demo_scan.graph)
    assert v.hops[-1].status is VerdictStatus.CONFIRMED, v.hops[-1].reason


# ------------------------------------------------------- leaked key liveness


def test_leak_hop_refuted_when_every_key_is_inactive(demo_scan):
    class Rotated(DemoAWSDataSource):
        def list_access_keys(self, user):
            return [dict(k, status="Inactive") for k in super().list_access_keys(user)]

    v = validate_path(_in_account_path(demo_scan), Rotated(account_id=PROD), demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED
    assert "inactive" in v.hops[0].reason


def test_leak_hop_unverifiable_when_keys_cannot_be_listed(demo_scan):
    class NoKeys(DemoAWSDataSource):
        def list_access_keys(self, user):
            return []  # e.g. ListAccessKeys denied

    v = validate_path(_in_account_path(demo_scan), NoKeys(account_id=PROD), demo_scan.graph)
    assert v.hops[0].status is VerdictStatus.UNVERIFIABLE
    assert v.status is not VerdictStatus.CONFIRMED


# ------------------------------------------------------- escalation routes


def _self_escalation_path():
    user = f"{PROD}/iam_user:ops-user"
    sink = f"{PROD}/admin_access:AdministratorAccess"
    graph = ScanGraph(
        nodes=[
            GraphNode(id=user, type="iam_user", label="ops-user"),
            GraphNode(id=sink, type="admin_access", label="AdministratorAccess"),
        ],
        edges=[GraphEdge(source=user, target=sink, relation="can_escalate_to_admin")],
    )
    path = AttackPath(
        path_id="selfesc", node_ids=[user, sink], steps=["x"], severity=Severity.CRITICAL,
        narrative="x", entry_kind="identity",
    )
    return path, graph


def test_self_escalation_is_now_verifiable():
    path, graph = _self_escalation_path()

    class Escalator(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            return [("iam:AttachUserPolicy", "*")]

    v = validate_path(path, Escalator(account_id=PROD), graph)
    assert v.status is VerdictStatus.CONFIRMED, v.hops[0].reason
    assert "iam:AttachUserPolicy" in v.hops[0].reason


def test_self_escalation_refuted_once_permission_removed():
    path, graph = _self_escalation_path()

    class Harmless(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            return [("s3:GetObject", "*")]

    v = validate_path(path, Harmless(account_id=PROD), graph)
    assert v.status is VerdictStatus.REFUTED


# ------------------------------------------------------- policy simulator


class _Simulated(DemoAWSDataSource):
    """Demo data plus a fake policy simulator."""

    decisions = {}

    def principal_arn(self, identity_type, name):
        return f"arn:aws:iam::{PROD}:{identity_type}/{name}"

    def simulate_principal_policy(self, principal_arn, actions, resource_arns=None):
        return {
            a: self.decisions.get(
                a,
                {"decision": "allowed", "allowed_by_boundary": None,
                 "allowed_by_organizations": None, "missing_context": []},
            )
            for a in actions
        }


def _denied(**extra):
    base = {"decision": "implicitDeny", "allowed_by_boundary": None,
            "allowed_by_organizations": None, "missing_context": []}
    base.update(extra)
    return base


def test_simulator_agreement_keeps_confirmed(demo_scan):
    src = _Simulated(account_id=PROD)
    src.decisions = {}
    v = validate_path(_in_account_path(demo_scan), src, demo_scan.graph)
    assert v.status is VerdictStatus.CONFIRMED
    apis = [c.api for h in v.hops for c in h.calls]
    assert "iam:SimulatePrincipalPolicy" in apis


def test_scp_denial_refutes_a_statically_confirmed_hop(demo_scan):
    src = _Simulated(account_id=PROD)
    src.decisions = {"iam:PassRole": _denied(allowed_by_organizations=False)}
    v = validate_path(_in_account_path(demo_scan), src, demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED
    assert "service control policy" in v.hops[1].reason


def test_permissions_boundary_denial_refutes(demo_scan):
    src = _Simulated(account_id=PROD)
    src.decisions = {
        a: _denied(allowed_by_boundary=False)
        for a in ("lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances")
    }
    v = validate_path(_in_account_path(demo_scan), src, demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED
    assert "permissions boundary" in v.hops[1].reason


def test_explicit_deny_refutes(demo_scan):
    src = _Simulated(account_id=PROD)
    src.decisions = {"iam:PassRole": _denied(decision="explicitDeny")}
    v = validate_path(_in_account_path(demo_scan), src, demo_scan.graph)
    assert "explicit Deny" in v.hops[1].reason


def test_missing_condition_context_is_unverifiable_not_refuted(demo_scan):
    src = _Simulated(account_id=PROD)
    src.decisions = {"iam:PassRole": _denied(missing_context=["aws:SourceIp"])}
    v = validate_path(_in_account_path(demo_scan), src, demo_scan.graph)
    assert v.hops[1].status is VerdictStatus.UNVERIFIABLE
    assert v.status is VerdictStatus.UNVERIFIABLE


def test_unavailable_simulator_keeps_static_verdict(demo_scan):
    class NoSim(_Simulated):
        def simulate_principal_policy(self, principal_arn, actions, resource_arns=None):
            return None  # AccessDenied on iam:SimulatePrincipalPolicy

    v = validate_path(_in_account_path(demo_scan), NoSim(account_id=PROD), demo_scan.graph)
    assert v.status is VerdictStatus.CONFIRMED
    observed = [c.observed for h in v.hops for c in h.calls if c.api == "iam:SimulatePrincipalPolicy"]
    assert observed and all("unavailable" in o for o in observed)


# ------------------------------------------------------- safety still holds


def test_validation_never_reads_objects_even_with_new_methods(demo_scan):
    calls = []

    class Spy(_Simulated):
        def read_object_head(self, *a, **k):
            calls.append("read_object_head")
            return None

    validate_paths(demo_scan.attack_paths + demo_scan.escalation_paths, Spy(account_id=PROD),
                   demo_scan.graph)
    assert calls == []
    assert "read_object_head" not in READ_ONLY_METHODS
    assert "access_key_account" not in READ_ONLY_METHODS


# ------------------------------------------------ empty policies, settled by AWS
# Found during the real-account stale-path experiment: removing a user's only
# policy left validation unable to tell "no policies" from "couldn't read them".


def _no_policy_source(decision):
    class NoPolicies(_Simulated):
        def get_identity_policy_statements(self, identity_type, name):
            return []

        def simulate_principal_policy(self, principal_arn, actions, resource_arns=None):
            return {a: {"decision": decision, "allowed_by_boundary": None,
                        "allowed_by_organizations": None, "missing_context": []} for a in actions}

    return NoPolicies(account_id=PROD)


def test_removed_policy_is_refuted_when_simulator_confirms_denial():
    path, graph = _self_escalation_path()
    v = validate_path(path, _no_policy_source("implicitDeny"), graph)
    assert v.status is VerdictStatus.REFUTED
    assert "simulator confirms" in v.hops[0].reason


def test_grant_from_elsewhere_is_confirmed_by_simulator():
    path, graph = _self_escalation_path()
    v = validate_path(path, _no_policy_source("allowed"), graph)
    assert v.status is VerdictStatus.CONFIRMED
    assert "group" in v.hops[0].reason


def test_group_grant_overrides_static_refutation():
    path, graph = _self_escalation_path()

    class GroupGranted(_Simulated):
        def get_identity_policy_statements(self, identity_type, name):
            return [("s3:GetObject", "*")]  # own policy: nothing dangerous

    v = validate_path(path, GroupGranted(account_id=PROD), graph)
    assert v.status is VerdictStatus.CONFIRMED


def test_empty_policies_without_simulator_stay_unverifiable():
    path, graph = _self_escalation_path()

    class Blind(DemoAWSDataSource):
        def get_identity_policy_statements(self, identity_type, name):
            return []

    v = validate_path(path, Blind(account_id=PROD), graph)
    assert v.status is VerdictStatus.UNVERIFIABLE
