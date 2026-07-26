from app.scanners import IAMScanner, S3Scanner, SecurityGroupScanner, run_all_scanners
from app.sources import get_data_source


def test_s3_scanner_finds_public_bucket_and_leaked_credentials():
    src = get_data_source("demo")
    findings = S3Scanner(src).scan()
    codes = {(f.resource_id, f.issue_code) for f in findings}

    assert ("public-uploads-bucket", "S3_PUBLIC_ACCESS") in codes
    assert ("public-uploads-bucket", "S3_SENSITIVE_OBJECT_EXPOSED") in codes
    assert ("internal-data-lake", "S3_PUBLIC_ACCESS") not in codes  # this bucket is properly locked down


def test_s3_scanner_sensitive_finding_carries_leak_hint():
    src = get_data_source("demo")
    findings = S3Scanner(src).scan()
    leak_finding = next(f for f in findings if f.issue_code == "S3_SENSITIVE_OBJECT_EXPOSED")
    assert leak_finding.evidence["leaked_identity_hint"] == "svc-deploy-bot"
    assert leak_finding.sensitive is True
    assert leak_finding.internet_facing is True


def test_iam_scanner_flags_privilege_escalation():
    src = get_data_source("demo")
    findings = IAMScanner(src).scan()
    esc = [f for f in findings if f.issue_code == "IAM_PRIVILEGE_ESCALATION_RISK"]
    assert len(esc) == 1
    assert esc[0].resource_id == "svc-deploy-bot"
    assert "LambdaExecutionAdminRole" in esc[0].evidence["pass_role_targets"]


def test_iam_scanner_no_mfa_users():
    src = get_data_source("demo")
    findings = IAMScanner(src).scan()
    no_mfa_users = {f.resource_id for f in findings if f.issue_code == "IAM_USER_NO_MFA"}
    assert no_mfa_users == {"svc-deploy-bot", "legacy-ci-user"}
    assert "read-only-analyst" not in no_mfa_users  # has MFA enabled in demo data


def test_iam_scanner_role_admin_access():
    src = get_data_source("demo")
    findings = IAMScanner(src).scan()
    admin_roles = {f.resource_id for f in findings if f.issue_code == "IAM_ROLE_ADMIN_ACCESS"}
    assert admin_roles == {"LambdaExecutionAdminRole"}


def test_sg_scanner_flags_open_ports_but_not_internal_sg():
    src = get_data_source("demo")
    findings = SecurityGroupScanner(src).scan()
    flagged = {f.resource_id for f in findings}
    assert "sg-0demo0webserver" in flagged
    assert "sg-0demo0internaldb" not in flagged  # restricted to 10.0.0.0/16, not internet-facing


def test_sg_scanner_produces_distinct_findings_per_port():
    src = get_data_source("demo")
    findings = SecurityGroupScanner(src).scan()
    web_findings = [f for f in findings if f.resource_id == "sg-0demo0webserver"]
    # web-sg has 3 ingress rules in demo data, 2 of which touch sensitive ports (22, 3389);
    # port 443 is not in the sensitive-port list so only 2 findings are expected.
    assert len(web_findings) == 2
    assert len({f.id for f in web_findings}) == 2  # fingerprints must be distinct, not collide


def test_run_all_scanners_returns_every_category():
    src = get_data_source("demo")
    findings = run_all_scanners(src)
    resource_types = {f.resource_type for f in findings}
    assert resource_types == {"s3_bucket", "iam_user", "iam_role", "iam_account", "security_group"}
