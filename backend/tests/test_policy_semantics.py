"""
Explicit Deny, NotAction, the wider escalation catalogue and same-account trust.

Each case mirrors a published test case in Bishop Fox's IAM Vulnerable
benchmark (fp1-fp3 explicit denies, fn4 NotAction, the PassRole-to-service and
resource-abuse paths, and the AssumeRole chain), so the behaviour the paper
reports is pinned by a test.
"""
from app.graph import build_attack_graph, find_escalation_paths
from app.scanners import policy
from app.scanners.iam_scanner import IAMScanner
from app.sources import AWSDataSource, _flatten_policy_document

ACCT = "123456789012"


def flat(*stmts):
    return _flatten_policy_document({"Statement": list(stmts)})


# ------------------------------------------------------------- deny


def test_allow_and_deny_in_one_policy_cancel():  # fp1
    s = flat({"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
             {"Effect": "Deny", "Action": "iam:*", "Resource": "*"})
    assert not policy.grants(s, "iam:AttachUserPolicy")
    assert not policy.is_admin_equivalent(s)
    assert policy.find_escalation_primitives(s) == []


def test_deny_in_another_policy_still_wins():  # fp2
    s = flat({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}) + \
        flat({"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"})
    assert not policy.grants(s, "iam:CreatePolicyVersion")


def test_resource_scoped_deny_does_not_remove_the_grant():
    s = flat({"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "*"},
             {"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "arn:aws:iam::1:user/x"})
    assert policy.grants(s, "iam:PutUserPolicy")


def test_conditional_deny_is_left_to_the_simulator():
    s = flat({"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": "*"},
             {"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "*",
              "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}})
    assert policy.grants(s, "iam:PutUserPolicy")


def test_deny_star_removes_full_admin():
    s = flat({"Effect": "Allow", "Action": "*", "Resource": "*"},
             {"Effect": "Deny", "Action": "iam:*", "Resource": "*"})
    assert not policy.is_full_admin(s)


# ------------------------------------------------------------- NotAction


def test_not_action_grants_everything_except_the_listed():  # fn4
    s = flat({"Effect": "Allow", "NotAction": ["s3:*", "ec2:*"], "Resource": "*"})
    assert policy.grants(s, "iam:AttachUserPolicy")
    assert not policy.grants(s, "s3:GetObject")
    assert "iam:AttachUserPolicy" in [a for a, _ in policy.find_escalation_primitives(s)]


def test_not_action_is_not_mistaken_for_full_admin():
    s = flat({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert not policy.is_full_admin(s)
    assert not policy.is_admin_equivalent(s)


# ------------------------------------------------------------- catalogue


class _Src(AWSDataSource):
    account_id = ACCT
    account_name = ACCT

    def __init__(self, users=None, roles=None, trust=None, console=True):
        self.users, self.roles, self.trust, self.console = users or {}, roles or {}, trust or {}, console

    def list_buckets(self): return []
    def get_public_access_block(self, b): return {}
    def is_bucket_acl_public(self, b): return False
    def is_bucket_policy_public(self, b): return False
    def is_bucket_encrypted(self, b): return True
    def is_bucket_versioned(self, b): return True
    def list_object_keys(self, b, limit=1000): return []
    def list_iam_users(self): return list(self.users)
    def user_has_mfa(self, u): return False
    def has_console_password(self, u): return self.console
    def list_access_keys(self, u): return []
    def list_user_policy_names(self, u): return []
    def list_iam_roles(self): return list(self.roles)
    def list_role_policy_names(self, r): return []
    def list_role_trust_principals(self, r): return self.trust.get(r, [])
    def get_policy_statements(self, n): return []
    def get_identity_policy_statements(self, t, n): return (self.users if t == "user" else self.roles).get(n, [])
    def get_account_password_policy(self):
        return {"MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
                "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True}
    def list_security_groups(self): return []
    def lookup_events(self, *a, **k): return []


def _codes(src):
    out = {}
    for f in IAMScanner(src).scan():
        f.account_id = ACCT
        out.setdefault(f.resource_id, set()).add(f.issue_code)
    return out


def test_passrole_into_new_service_is_escalation():
    for create in ("cloudformation:CreateStack", "codebuild:CreateProject", "glue:CreateDevEndpoint",
                   "sagemaker:CreateNotebookInstance", "datapipeline:CreatePipeline"):
        src = _Src(users={"u": [("iam:PassRole", "*"), (create, "*")]})
        assert "IAM_PRIVILEGE_ESCALATION_RISK" in _codes(src)["u"], create


def test_passrole_with_only_invoke_is_not_escalation():
    src = _Src(users={"u": [("iam:PassRole", "*"), ("lambda:InvokeFunction", "*")]})
    assert "IAM_PRIVILEGE_ESCALATION_RISK" not in _codes(src).get("u", set())


def test_resource_role_abuse_is_reported_without_a_route():
    src = _Src(users={"u": [("ssm:SendCommand", "*")]})
    assert "IAM_RESOURCE_ROLE_ABUSE_RISK" in _codes(src)["u"]


def test_key_only_user_gets_no_mfa_finding():
    src = _Src(users={"u": [("s3:GetObject", "*")]}, console=False)
    assert "IAM_USER_NO_MFA" not in _codes(src).get("u", set())
    src = _Src(users={"u": [("s3:GetObject", "*")]}, console=True)
    assert "IAM_USER_NO_MFA" in _codes(src)["u"]


# ------------------------------------------------------------- same-account trust


def test_assume_role_chain_reaches_admin():
    src = _Src(
        users={"start": [("sts:AssumeRole", "*")]},
        roles={"mid": [("sts:AssumeRole", "*")], "end": [("*", "*")]},
        trust={"mid": [f"arn:aws:iam::{ACCT}:user/start"], "end": [f"arn:aws:iam::{ACCT}:role/mid"]},
    )
    findings = IAMScanner(src).scan()
    for f in findings:
        f.account_id = ACCT
    g, by = build_attack_graph(findings)
    paths = find_escalation_paths(g, by)
    chains = [[n.split(":")[-1] for n in p.node_ids] for p in paths]
    assert ["start", "mid", "end", "AdministratorAccess"] in chains


def test_routes_do_not_start_at_an_administrator():
    src = _Src(
        users={"admin": [("*", "*")]},
        roles={"r": [("*", "*")]},
        trust={"r": [f"arn:aws:iam::{ACCT}:user/admin"]},
    )
    findings = IAMScanner(src).scan()
    for f in findings:
        f.account_id = ACCT
    g, by = build_attack_graph(findings)
    assert all(not p.node_ids[0].endswith("user:admin") for p in find_escalation_paths(g, by))


def test_policy_edit_scoped_to_aws_managed_policies_is_not_escalation():  # fp4
    s = flat({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "arn:aws:iam::aws:policy/fp4-*"})
    assert policy.find_escalation_primitives(s) == []


def test_policy_edit_scoped_to_customer_policies_is_escalation():  # fn2
    s = flat({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "arn:aws:iam::*:policy/fn2-*"})
    assert [a for a, _ in policy.find_escalation_primitives(s)] == ["iam:CreatePolicyVersion"]
