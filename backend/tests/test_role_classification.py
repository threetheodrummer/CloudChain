"""
Role provenance and operator allowlists.

Two separate concerns, deliberately not collapsed into one boolean:

  - Is this role demonstrably AWS's? Only a path under /aws-service-role/
    proves that, because IAM refuses to let anyone else create one there.
  - Has a human decided this role is acceptable? That's a judgement, it is
    spoofable by whoever names the role, and the report has to say so.

Suppression is where blind spots live. Nothing here removes a finding; it only
changes severity and records why.
"""
import pytest

from app.scanners import iam_scanner
from app.scanners.iam_scanner import (
    ALLOWLISTED,
    NAMED_AWS,
    NORMAL,
    VERIFIED_AWS,
    classify_role,
    is_aws_managed_role,
)


@pytest.fixture
def allowlist(monkeypatch):
    """Point the scanner at a temporary allowlist.

    Settings is a frozen dataclass, so the whole object is swapped rather than
    one field mutated -- which is also closer to how it behaves in production,
    where the value comes from the environment at import time.
    """
    import dataclasses

    def _set(*patterns):
        monkeypatch.setattr(
            iam_scanner,
            "settings",
            dataclasses.replace(iam_scanner.settings, benign_role_patterns=tuple(patterns)),
        )

    return _set


# --------------------------------------------------------- provenance


def test_service_linked_path_is_proof():
    assert classify_role("AWSServiceRoleForOrganizations", "/aws-service-role/") == VERIFIED_AWS


def test_a_matching_name_at_an_ordinary_path_is_only_a_guess():
    """The weakness this fix exists for: names are chosen by whoever creates
    the role, so a name match must never be treated as proof."""
    assert classify_role("AWSServiceRoleForEvil", "/") == NAMED_AWS


def test_path_beats_name():
    """A genuine service-linked role is verified even if its name is unusual."""
    assert classify_role("something-unexpected", "/aws-service-role/") == VERIFIED_AWS


def test_ordinary_roles_are_not_downgraded():
    assert classify_role("OrgDeploymentRole", "/") == NORMAL
    assert not is_aws_managed_role("OrgDeploymentRole", "/")


def test_the_default_path_earns_no_benefit_of_the_doubt():
    """A source that can't report paths must not accidentally downgrade."""
    assert classify_role("my-app-role") == NORMAL


# --------------------------------------------------------- allowlist


def test_a_matching_role_is_downgraded(allowlist):
    allowlist("LabOrchestratorRole")
    assert classify_role("LabOrchestratorRole", "/") == ALLOWLISTED


def test_glob_patterns_work(allowlist):
    allowlist("ci-*", "*-provisioner")
    assert classify_role("ci-runner", "/") == ALLOWLISTED
    assert classify_role("terraform-provisioner", "/") == ALLOWLISTED
    assert classify_role("prod-admin", "/") == NORMAL


def test_an_empty_allowlist_changes_nothing(allowlist):
    allowlist()
    assert classify_role("LabOrchestratorRole", "/") == NORMAL


def test_aws_provenance_takes_precedence_over_the_allowlist(allowlist):
    """Knowing *why* something was downgraded matters more than that it was."""
    allowlist("AWSServiceRoleFor*")
    assert classify_role("AWSServiceRoleForConfig", "/aws-service-role/") == VERIFIED_AWS


# ------------------------------------------------- visibility of the rule


def test_every_downgrade_explains_itself():
    for role, path in [
        ("AWSServiceRoleForConfig", "/aws-service-role/"),
        ("OrganizationAccountAccessRole", "/"),
    ]:
        note = iam_scanner._downgrade_note(role, classify_role(role, path))
        assert note, f"{role} was downgraded with no explanation"
        assert role in note


def test_a_name_based_downgrade_admits_it_is_not_proof():
    note = iam_scanner._downgrade_note("OrganizationAccountAccessRole", NAMED_AWS)
    assert "not proof" in note
    assert "name" in note.lower()


def test_an_allowlisted_downgrade_names_the_rule(allowlist):
    allowlist("LabOrchestratorRole")
    note = iam_scanner._downgrade_note("LabOrchestratorRole", ALLOWLISTED)
    assert "LabOrchestratorRole" in note
    assert "CLOUDCHAIN_BENIGN_ROLES" in note
    assert "The finding is real" in note


def test_allowlisted_findings_stay_in_the_report(allowlist, monkeypatch):
    """Downgraded, never dropped. A suppression you can't see in the output is
    indistinguishable from a bug."""
    from app.models import Severity
    from app.sources import DemoAWSDataSource

    class _Trusting(DemoAWSDataSource):
        def list_iam_roles(self):
            return ["LabOrchestratorRole"]

        def list_role_policy_names(self, role):
            return ["Admin"]

        def list_role_trust_principals(self, role):
            return ["arn:aws:iam::999999999999:root"]

        def get_identity_policy_statements(self, kind, name):
            return [("*", "*")]

        def get_role_path(self, role):
            return "/"

        def list_iam_users(self):
            return []

        def list_buckets(self):
            return []

        def list_security_groups(self):
            return []

        def get_account_password_policy(self):
            return {"minimum_password_length": 99, "require_symbols": True}

    allowlist("LabOrchestratorRole")
    findings = iam_scanner.IAMScanner(_Trusting()).scan()
    trust = [f for f in findings if f.issue_code == "IAM_CROSS_ACCOUNT_TRUST"]

    assert trust, "an allowlisted role must still appear in the report"
    assert trust[0].base_severity is Severity.LOW
    assert trust[0].evidence["allowlist_rule"] == "LabOrchestratorRole"
    assert trust[0].evidence["role_classification"] == ALLOWLISTED
