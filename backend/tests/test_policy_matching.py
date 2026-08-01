"""
Wildcard-aware IAM policy matching.

The defect this closes: every permission check compared action strings exactly,
so `iam:*` never matched `iam:PassRole` and `("iam:*", "*")` was not `("*",
"*")`. Thirteen scans of deliberately vulnerable AWS accounts produced zero
privilege-escalation findings as a result -- real policies are written with
wildcards, and CloudChain was blind to all of them.
"""
import pytest

from app.graph import build_attack_graph, find_escalation_paths
from app.models import Severity
from app.scanners import policy
from app.scanners.iam_scanner import IAMScanner
from app.sources import DemoAWSDataSource


# ------------------------------------------------------------- matching


@pytest.mark.parametrize(
    "granted,wanted",
    [
        ("*", "iam:PassRole"),
        ("iam:*", "iam:PassRole"),
        ("iam:Pass*", "iam:PassRole"),
        ("iam:PassRole", "iam:PassRole"),
        ("lambda:*", "lambda:CreateFunction"),
        ("iam:passrole", "iam:PassRole"),  # IAM action matching is case-insensitive
    ],
)
def test_wildcards_are_followed(granted, wanted):
    assert policy.action_matches(granted, wanted)


@pytest.mark.parametrize(
    "granted,wanted",
    [
        ("s3:*", "iam:PassRole"),
        ("iam:Get*", "iam:PassRole"),
        ("", "iam:PassRole"),
        ("iam:PassRoleToSomething", "iam:PassRole"),
    ],
)
def test_unrelated_grants_do_not_match(granted, wanted):
    assert not policy.action_matches(granted, wanted)


def test_regex_metacharacters_in_an_action_are_literal():
    """An action containing '.' must not become a regex wildcard."""
    assert not policy.action_matches("iam:Pass.ole", "iam:PassRole")


# ---------------------------------------------------------------- admin


def test_literal_wildcard_policy_is_full_admin():
    assert policy.is_full_admin([("*", "*")])
    assert policy.is_admin_equivalent([("*", "*")])


def test_full_iam_control_is_admin_equivalent_but_not_full_admin():
    """`iam:*` on `*` can attach AdministratorAccess to itself. Treating that as
    'some IAM permissions' is how an overpowered role hides from a scanner."""
    statements = [("iam:*", "*")]
    assert not policy.is_full_admin(statements)
    assert policy.is_admin_equivalent(statements)


def test_broad_but_non_iam_wildcards_are_not_admin():
    """`s3:*` is dangerous and is not administrator. Saying otherwise would
    make the finding meaningless."""
    assert not policy.is_admin_equivalent([("s3:*", "*")])
    assert not policy.is_admin_equivalent([("ec2:*", "*"), ("s3:*", "*")])


def test_iam_wildcard_scoped_to_one_resource_is_not_admin():
    assert not policy.is_admin_equivalent([("iam:*", "arn:aws:iam::1:role/one")])


def test_readonly_is_never_admin():
    assert not policy.is_admin_equivalent([("s3:GetObject", "*"), ("iam:Get*", "*")])


# --------------------------------------------------------- primitives


def test_escalation_primitives_are_found_through_wildcards():
    found = {a for a, _ in policy.find_escalation_primitives([("iam:Put*", "*")])}
    assert "iam:PutUserPolicy" in found
    assert "iam:PutRolePolicy" in found


def test_each_primitive_explains_why_it_matters():
    for action, why in policy.find_escalation_primitives([("iam:*", "*")]):
        assert why, f"{action} has no explanation"


def test_a_harmless_policy_has_no_primitives():
    assert policy.find_escalation_primitives([("s3:GetObject", "*")]) == []


# ------------------------------------------------------- end to end


class _WildcardAccount(DemoAWSDataSource):
    """A role granted `iam:*` and a user who can PassRole into it.

    This is the shape of a real training environment, and the shape that
    produced no findings at all before wildcards were handled.
    """

    def list_iam_users(self):
        return ["app-dev"]

    def user_has_mfa(self, user):
        return True

    def list_access_keys(self, user):
        return []

    def list_user_policy_names(self, user):
        return ["DevPolicy"]

    def list_iam_roles(self):
        return ["LabOverpoweredRole"]

    def list_role_policy_names(self, role):
        return ["LabRolePolicy"]

    def list_role_trust_principals(self, role):
        return []

    def get_policy_statements(self, name):
        return []

    def get_identity_policy_statements(self, identity_type, name):
        if identity_type == "user":
            return [
                ("iam:Pass*", "arn:aws:iam::111111111111:role/LabOverpoweredRole"),
                ("lambda:*", "*"),
            ]
        return [("iam:*", "*")]

    def get_account_password_policy(self):
        return {"minimum_password_length": 99, "require_symbols": True}

    def list_buckets(self):
        return []

    def list_security_groups(self):
        return []


@pytest.fixture
def wildcard_findings():
    findings = IAMScanner(_WildcardAccount()).scan()
    for f in findings:
        f.account_id = "111111111111"
        f.account_name = "thm"
    return findings


def test_a_wildcard_passrole_grant_is_now_detected(wildcard_findings):
    escalation = [f for f in wildcard_findings if f.issue_code == "IAM_PRIVILEGE_ESCALATION_RISK"]
    assert any(f.resource_id == "app-dev" for f in escalation)


def test_a_role_with_full_iam_is_now_flagged(wildcard_findings):
    admin = [f for f in wildcard_findings if f.issue_code == "IAM_ROLE_ADMIN_ACCESS"]
    assert any(f.resource_id == "LabOverpoweredRole" for f in admin)


def test_the_escalation_route_is_finally_drawn(wildcard_findings):
    """The whole point: this chain was invisible before."""
    graph, by_resource = build_attack_graph(wildcard_findings)
    paths = find_escalation_paths(graph, by_resource)

    assert paths, "a wildcard PassRole chain must produce an escalation route"
    chain = paths[0].node_ids
    assert chain[0].endswith("iam_user:app-dev")
    assert chain[-1].endswith("admin_access:AdministratorAccess")


def test_self_escalation_reaches_admin_in_one_hop():
    """An identity that can attach a policy to itself hasn't got admin yet, but
    is one call away. That single-hop route must not be filtered out as
    'already an administrator'."""
    from app.models import Finding

    finding = Finding(
        account_id="111111111111",
        resource_id="policy-writer",
        resource_type="iam_user",
        issue_code="IAM_PRIVILEGE_ESCALATION_RISK",
        title="t",
        description="d",
        base_severity=Severity.CRITICAL,
        remediation="fix",
        evidence={"self_escalation_actions": ["iam:AttachUserPolicy"]},
    )
    graph, by_resource = build_attack_graph([finding])
    paths = find_escalation_paths(graph, by_resource)

    assert len(paths) == 1
    assert len(paths[0].node_ids) == 2
    assert "grant itself" in paths[0].steps[0]


def test_an_identity_that_already_holds_admin_is_still_not_an_escalation():
    """The single-hop exception must not swallow the original rule."""
    from app.models import Finding

    finding = Finding(
        account_id="111111111111",
        resource_id="already-admin",
        resource_type="iam_user",
        issue_code="IAM_OVERPERMISSIVE_POLICY",
        title="t",
        description="d",
        base_severity=Severity.CRITICAL,
        remediation="fix",
    )
    graph, by_resource = build_attack_graph([finding])
    assert find_escalation_paths(graph, by_resource) == []
