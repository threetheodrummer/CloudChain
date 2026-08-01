"""
Three defects found by scanning real TryHackMe AWS accounts.

Each of these was invisible against seeded demo data and only appeared once
CloudChain was pointed at accounts it hadn't been built around:

  1. Identities whose over-privilege lived in a customer-managed or inline
     policy came back clean, because policies were resolved by name and only
     AWS-managed policies have resolvable names.
  2. OrganizationAccountAccessRole and StackSets execution roles were reported
     as CRITICAL cross-account trust in four of six reports, burying the real
     findings under AWS's own plumbing.
  3. S3_NO_ENCRYPTION never fired, because AWS has applied SSE-S3 to every new
     bucket since January 2023 and the check only asked whether encryption
     existed, not which key.
"""
import pytest

from app.graph import build_attack_graph
from app.models import Severity
from app.pipeline import run_scan
from app.scanners.iam_scanner import is_aws_managed_role
from app.scanners.s3_scanner import S3Scanner
from app.sources import AWSDataSource, DemoAWSDataSource, _flatten_policy_document


# ------------------------------------------------- 1. policy resolution


class _InlineOnlySource(DemoAWSDataSource):
    """A user whose only permissions come from an inline policy.

    Resolution by name cannot see this: an inline policy has no ARN, and
    get_policy_statements has nothing to look up.
    """

    def list_iam_users(self):
        return ["inline-admin"]

    def user_has_mfa(self, user):
        return True

    def list_access_keys(self, user):
        return []

    def list_user_policy_names(self, user):
        return ["InlineAdminPolicy"]

    def get_policy_statements(self, policy_name):
        return []  # by-name lookup finds nothing, exactly like a real account

    def get_identity_policy_statements(self, identity_type, name):
        if identity_type == "user" and name == "inline-admin":
            return _flatten_policy_document(
                '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
            )
        return []


def test_inline_policy_permissions_are_now_seen():
    """The Over-Privileged User miss: found, but flagged only for MFA."""
    from app.scanners import IAMScanner

    findings = IAMScanner(_InlineOnlySource()).scan()
    codes = {f.issue_code for f in findings if f.resource_id == "inline-admin"}
    assert "IAM_OVERPERMISSIVE_POLICY" in codes


def test_resolution_by_name_alone_would_have_missed_it():
    """Guards the regression: the old path must genuinely have been blind."""
    source = _InlineOnlySource()
    assert source.get_policy_statements("InlineAdminPolicy") == []
    assert ("*", "*") in source.get_identity_policy_statements("user", "inline-admin")


def test_the_default_resolution_still_works_for_named_policies():
    """Demo and Terraform-plan sources rely on the by-name fallback."""
    source = DemoAWSDataSource()
    statements = source.get_identity_policy_statements("user", "svc-deploy-bot")
    assert ("iam:PassRole", "arn:aws:iam::111111111111:role/LambdaExecutionAdminRole") in statements


def test_policy_documents_flatten_from_both_dict_and_json_string():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    assert _flatten_policy_document(doc) == [("s3:GetObject", "*")]
    assert _flatten_policy_document('{"Statement":[{"Effect":"Allow","Action":"*"}]}') == [("*", "*")]
    assert _flatten_policy_document("not json") == []
    assert _flatten_policy_document(None) == []


def test_deny_statements_are_never_treated_as_grants():
    doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert _flatten_policy_document(doc) == []


# ------------------------------------------- 2. AWS service-managed roles


@pytest.mark.parametrize(
    "role",
    [
        "OrganizationAccountAccessRole",
        "stacksets-exec-43bd003f43dfcdc460afa4cce84b613e",
        "AWSServiceRoleForOrganizations",
        "AWSControlTowerExecution",
        "AWSReservedSSO_AdministratorAccess_1a2b",
    ],
)
def test_aws_created_roles_are_recognised(role):
    assert is_aws_managed_role(role)


@pytest.mark.parametrize("role", ["OrgDeploymentRole", "LambdaExecutionAdminRole", "my-app-role"])
def test_customer_roles_are_not_mistaken_for_aws_ones(role):
    assert not is_aws_managed_role(role)


def test_org_role_trust_is_reported_but_not_as_critical():
    result, _ = run_scan(mode="demo", persist=False)
    org = [
        f
        for f in result.findings
        if f.resource_id == "OrganizationAccountAccessRole"
        and f.issue_code == "IAM_CROSS_ACCOUNT_TRUST"
    ]
    assert org, "the finding should still be reported, just not screamed about"
    assert org[0].base_severity is Severity.LOW
    assert org[0].evidence["aws_managed"] is True


def test_org_role_admin_access_is_also_downgraded():
    result, _ = run_scan(mode="demo", persist=False)
    admin = [
        f
        for f in result.findings
        if f.resource_id == "OrganizationAccountAccessRole"
        and f.issue_code == "IAM_ROLE_ADMIN_ACCESS"
    ]
    assert admin
    assert admin[0].base_severity is Severity.LOW


def test_no_attack_edge_is_drawn_from_an_aws_managed_role():
    """Modelling 'AWS Organizations works as documented' as a breach route is
    noise, and it was crowding out the real cross-account chain."""
    result, _ = run_scan(mode="demo", persist=False)
    graph, _ = build_attack_graph(result.findings)

    for source, target, data in graph.edges(data=True):
        if data["relation"] == "can_assume_cross_account":
            assert "OrganizationAccountAccessRole" not in target


def test_the_genuine_cross_account_chain_still_survives():
    """The downgrade must not silence the finding that matters."""
    result, _ = run_scan(mode="demo", persist=False)
    genuine = [
        f
        for f in result.findings
        if f.resource_id == "OrgDeploymentRole" and f.issue_code == "IAM_CROSS_ACCOUNT_TRUST"
    ]
    assert genuine
    assert genuine[0].base_severity is Severity.CRITICAL
    assert any(p.crosses_accounts for p in result.attack_paths)


# --------------------------------------------------- 3. S3 encryption


class _EncryptionSource(DemoAWSDataSource):
    def __init__(self, config, public=True, keys=("backup/credentials.csv",)):
        super().__init__()
        self._config = config
        self._public = public
        self._keys = list(keys)

    def list_buckets(self):
        return ["subject"]

    def get_public_access_block(self, bucket):
        return {k: not self._public for k in
                ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")}

    def is_bucket_acl_public(self, bucket):
        return self._public

    def is_bucket_policy_public(self, bucket):
        return False

    def is_bucket_versioned(self, bucket):
        return True

    def list_object_keys(self, bucket, limit=1000):
        return self._keys

    def leaked_credentials_hint(self, bucket):
        return None

    def get_bucket_encryption(self, bucket):
        return self._config


NONE = {"enabled": False, "algorithm": "", "kms_key_id": None, "bucket_key_enabled": False}
SSE_S3 = {"enabled": True, "algorithm": "AES256", "kms_key_id": None, "bucket_key_enabled": False}
SSE_KMS = {
    "enabled": True,
    "algorithm": "aws:kms",
    "kms_key_id": "arn:aws:kms:us-east-1:111111111111:key/abc",
    "bucket_key_enabled": True,
}


def _codes(source):
    return {f.issue_code for f in S3Scanner(source).scan()}


def test_unencrypted_bucket_still_reported():
    assert "S3_NO_ENCRYPTION" in _codes(_EncryptionSource(NONE))


def test_aws_owned_key_on_an_exposed_bucket_is_now_flagged():
    """The Plain Bucket miss. SSE-S3 is AWS's default on every new bucket, so
    'encrypted: yes' stopped meaning anything."""
    codes = _codes(_EncryptionSource(SSE_S3))
    assert "S3_AWS_OWNED_ENCRYPTION_KEY" in codes
    assert "S3_NO_ENCRYPTION" not in codes


def test_customer_managed_kms_is_not_flagged():
    assert "S3_AWS_OWNED_ENCRYPTION_KEY" not in _codes(_EncryptionSource(SSE_KMS))


def test_private_buckets_with_sse_s3_are_left_alone():
    """Flagging every bucket in the account would be noise. The finding is
    raised only where the data is exposed or credential-shaped."""
    private = _EncryptionSource(SSE_S3, public=False, keys=["report.pdf"])
    assert "S3_AWS_OWNED_ENCRYPTION_KEY" not in _codes(private)


def test_the_new_finding_is_low_not_alarmist():
    findings = S3Scanner(_EncryptionSource(SSE_S3)).scan()
    weak = next(f for f in findings if f.issue_code == "S3_AWS_OWNED_ENCRYPTION_KEY")
    assert weak.base_severity is Severity.LOW
    assert "rotated" in weak.description


def test_sources_that_cannot_tell_the_difference_still_work():
    """The base class derives the detail from the old boolean, so a data source
    that hasn't been updated keeps functioning."""

    class Old(AWSDataSource):
        def list_buckets(self): return []
        def get_public_access_block(self, b): return {}
        def is_bucket_acl_public(self, b): return False
        def is_bucket_policy_public(self, b): return False
        def is_bucket_encrypted(self, b): return True
        def is_bucket_versioned(self, b): return True
        def list_object_keys(self, b, limit=1000): return []
        def list_iam_users(self): return []
        def user_has_mfa(self, u): return True
        def list_access_keys(self, u): return []
        def list_user_policy_names(self, u): return []
        def list_iam_roles(self): return []
        def list_role_policy_names(self, r): return []
        def get_policy_statements(self, p): return []
        def get_account_password_policy(self): return {}
        def list_security_groups(self): return []

    assert Old().get_bucket_encryption("b")["enabled"] is True
