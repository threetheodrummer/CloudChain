"""
IAM misconfiguration scanner.

Standard checks: MFA, stale access keys, weak account password policy,
wildcard-permission policies. The differentiator is
IAM_PRIVILEGE_ESCALATION_RISK: it looks for the specific *combination* of
iam:PassRole plus a compute-creation action (Lambda/EC2), which is one of
the best-known real-world AWS privilege escalation primitives -- a single
policy statement rarely looks dangerous on its own, but the combination is
critical. This is what lets the graph engine chain a leaked credential all
the way to admin access.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Set, Tuple

from app.config import settings
from app.models import Finding, Severity
from app.scanners import policy
from app.sources import AWSDataSource

COMPUTE_CREATE_ACTIONS = {
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
}


def _account_from_arn(arn: str) -> str:
    """'arn:aws:iam::111111111111:user/bob' -> '111111111111'.

    Returns "" for wildcards and anything unparseable, so a malformed trust
    policy can never be mistaken for a same-account principal.
    """
    parts = arn.split(":")
    if len(parts) < 5 or not parts[4].isdigit():
        return ""
    return parts[4]


def _principal_name_from_arn(arn: str) -> Tuple[str, str]:
    """'arn:aws:iam::111:user/bob' -> ('iam_user', 'bob'). ('', '') if not an
    IAM user/role ARN -- ':root' means the whole account, not one identity."""
    tail = arn.rsplit(":", 1)[-1]
    kind, _, name = tail.partition("/")
    if kind == "user" and name:
        return "iam_user", name
    if kind == "role" and name:
        return "iam_role", name
    return "", ""


def _extract_role_name(resource: str) -> str:
    if resource == "*":
        return "*"
    if "/role/" in resource:
        return resource.rsplit("/", 1)[-1]
    if "role/" in resource:
        return resource.split("role/", 1)[-1]
    return resource


def _collect_statements(source: AWSDataSource, policy_names: List[str]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for name in policy_names:
        pairs.extend(source.get_policy_statements(name))
    return pairs


# Roles AWS creates and manages itself. Their trust policies name the
# organisation's management account or an AWS service *by design* -- that is
# their entire function.
#
# Reporting them as CRITICAL cross-account trust is technically true and
# practically useless: scanning six real THM org accounts produced these at the
# top of four reports, burying the findings that actually mattered. They are
# still reported, because a compromised management account is a real (if
# out-of-scope) risk, but at a severity that reflects "expected AWS plumbing".
AWS_MANAGED_ROLE_PREFIXES = (
    "OrganizationAccountAccessRole",
    "stacksets-exec-",
    "AWSServiceRoleFor",
    "AWSControlTower",
    "AWSReservedSSO_",
    "aws-controltower-",
)


def is_aws_managed_role(role: str) -> bool:
    """True for roles AWS or its services create, rather than the account owner."""
    return any(role.startswith(prefix) for prefix in AWS_MANAGED_ROLE_PREFIXES)


class IAMScanner:
    def __init__(self, source: AWSDataSource):
        self.source = source

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._scan_users())
        findings.extend(self._scan_roles())
        findings.extend(self._scan_password_policy())
        return findings

    def _scan_users(self) -> List[Finding]:
        findings: List[Finding] = []

        for user in self.source.list_iam_users():
            access_keys = self.source.list_access_keys(user)
            has_mfa = self.source.user_has_mfa(user)

            if not has_mfa:
                findings.append(
                    Finding(
                        resource_id=user,
                        resource_type="iam_user",
                        issue_code="IAM_USER_NO_MFA",
                        title=f"IAM user '{user}' does not have MFA enabled",
                        description="Multi-factor authentication is not configured for this user.",
                        base_severity=Severity.HIGH if access_keys else Severity.MEDIUM,
                        internet_facing=bool(access_keys),
                        remediation="Enforce MFA for this user (console) and prefer temporary credentials over long-lived access keys.",
                        evidence={"access_key_count": len(access_keys)},
                    )
                )

            for key in access_keys:
                created = datetime.fromisoformat(key["created"])
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                if key["status"] == "Active" and age_days > settings.stale_key_age_days:
                    findings.append(
                        Finding(
                            resource_id=user,
                            resource_type="iam_user",
                            issue_code="IAM_STALE_ACCESS_KEY",
                            title=f"IAM user '{user}' has an access key older than {settings.stale_key_age_days} days",
                            description=f"Access key {key['id']} is {age_days} days old and still active.",
                            base_severity=Severity.MEDIUM,
                            remediation="Rotate or deactivate this access key.",
                            evidence={"access_key_id": key["id"], "age_days": age_days, "last_used": key.get("last_used")},
                            dedupe_key=key["id"],
                        )
                    )

            policy_names = self.source.list_user_policy_names(user)
            # Resolved through the identity rather than by policy name, so
            # customer-managed and inline policies are actually read.
            statements = self.source.get_identity_policy_statements("user", user)
            full_admin = policy.is_full_admin(statements)
            if policy.is_admin_equivalent(statements):
                findings.append(
                    Finding(
                        resource_id=user,
                        resource_type="iam_user",
                        issue_code="IAM_OVERPERMISSIVE_POLICY",
                        title=(
                            f"IAM user '{user}' has a wildcard (*:*) policy attached"
                            if full_admin
                            else f"IAM user '{user}' has full control of IAM, which is "
                            f"administrator access in one step"
                        ),
                        description=(
                            f"Attached polic{'y' if len(policy_names) == 1 else 'ies'} "
                            f"{policy_names} grant unrestricted access."
                            if full_admin
                            else "This identity can perform any IAM action on any resource. It "
                            "can attach AdministratorAccess to itself, so the distinction "
                            "between this and being an administrator is one API call."
                        ),
                        base_severity=Severity.CRITICAL,
                        remediation=(
                            "Replace with a least-privilege policy scoped to the specific "
                            "actions/resources this identity needs."
                        ),
                        evidence={
                            "policies": policy_names,
                            "full_admin": full_admin,
                            "granted_actions": policy.summarise_actions(statements),
                        },
                    )
                )

            findings.extend(
                self._escalation_findings("iam_user", user, policy_names, statements)
            )

        return findings

    def _escalation_findings(
        self,
        resource_type: str,
        name: str,
        policy_names: List[str],
        statements: List[Tuple[str, str]],
    ) -> List[Finding]:
        """Ways this identity can reach administrator that aren't simply having it.

        Two distinct mechanisms, reported as one issue code with evidence saying
        which applies:

          - PassRole into an over-privileged role, plus a compute action to run
            code as it. Needs a target role, so the graph draws an edge to it.
          - Self-escalation via IAM write permissions (attach a policy, publish a
            policy version, mint another user's access key...). No target role is
            involved -- the identity grants itself.
        """
        has_passrole = policy.grants(statements, "iam:PassRole")
        compute = sorted(a for a in COMPUTE_CREATE_ACTIONS if policy.grants(statements, a))
        primitives = policy.find_escalation_primitives(statements)

        # An identity that already holds admin hasn't escalated to it.
        if policy.is_full_admin(statements):
            return []
        if not ((has_passrole and compute) or primitives):
            return []

        reasons: List[str] = []
        if has_passrole and compute:
            reasons.append(
                f"holds iam:PassRole together with {', '.join(compute)}, so it can pass an "
                f"over-privileged role into new compute and run code as that role"
            )
        for action, why in primitives:
            reasons.append(f"holds {action}, so it {why}")

        pass_role_targets = (
            [_extract_role_name(r) for r in policy.granted_resources(statements, "iam:PassRole")]
            if has_passrole and compute
            else []
        )

        label = "IAM user" if resource_type == "iam_user" else "IAM role"
        return [
            Finding(
                resource_id=name,
                resource_type=resource_type,
                issue_code="IAM_PRIVILEGE_ESCALATION_RISK",
                title=f"{label} '{name}' can escalate to administrator access",
                description=(
                    f"This identity {'; and '.join(reasons)}. Each of these is a documented "
                    f"AWS privilege-escalation path."
                ),
                base_severity=Severity.CRITICAL,
                remediation=(
                    "Scope iam:PassRole to specific role ARNs with a condition, and remove IAM "
                    "write permissions this identity doesn't need."
                ),
                evidence={
                    "policies": policy_names,
                    "pass_role_targets": pass_role_targets,
                    "compute_actions": compute,
                    "self_escalation_actions": [a for a, _ in primitives],
                },
            )
        ]

    def _scan_roles(self) -> List[Finding]:
        findings: List[Finding] = []
        for role in self.source.list_iam_roles():
            policy_names = self.source.list_role_policy_names(role)
            statements = self.source.get_identity_policy_statements("role", role)
            aws_managed = is_aws_managed_role(role)

            if not aws_managed:
                findings.extend(
                    self._escalation_findings("iam_role", role, policy_names, statements)
                )

            if policy.is_admin_equivalent(statements):
                findings.append(
                    Finding(
                        resource_id=role,
                        resource_type="iam_role",
                        issue_code="IAM_ROLE_ADMIN_ACCESS",
                        title=(
                            f"AWS-managed role '{role}' has administrator-level access "
                            f"(expected)"
                            if aws_managed
                            else f"IAM role '{role}' has administrator-level access"
                        ),
                        description=(
                            f"'{role}' is created and managed by AWS, and administrator "
                            f"access is inherent to its purpose. Reported for visibility, "
                            f"not as a misconfiguration."
                            if aws_managed
                            else f"Attached polic{'y' if len(policy_names)==1 else 'ies'} "
                            f"{policy_names} grant unrestricted access."
                        ),
                        base_severity=Severity.LOW if aws_managed else Severity.HIGH,
                        remediation=(
                            "No action required unless this role should not exist. Verify "
                            "the account it trusts is your own organisation management account."
                            if aws_managed
                            else "Scope this role to only the permissions its workload requires."
                        ),
                        evidence={"policies": policy_names, "aws_managed": aws_managed},
                    )
                )

            findings.extend(self._scan_role_trust(role, policy_names, statements))
        return findings

    def _scan_role_trust(
        self, role: str, policy_names: List[str], statements: List[Tuple[str, str]]
    ) -> List[Finding]:
        """Roles whose trust policy lets a principal in another account in.

        This is where organisation-level risk actually lives. A role can be
        perfectly scoped inside its own account and still be the reason the
        whole org falls over, because its trust policy names a principal in a
        less-protected account. Single-account scanners cannot see this at all:
        the role looks fine locally, and the trusting relationship is only
        dangerous in combination with what's wrong somewhere else.
        """
        principals = self.source.list_role_trust_principals(role)
        if not principals:
            return []

        this_account = getattr(self.source, "account_id", "") or ""
        external = sorted(
            {
                acct
                for acct in (_account_from_arn(p) for p in principals)
                if acct and acct != this_account
            }
        )
        if not external:
            return []

        is_admin = policy.is_admin_equivalent(statements)
        aws_managed = is_aws_managed_role(role)

        if aws_managed:
            # AWS created this role and its trust policy names the organisation
            # management account on purpose. Still worth surfacing -- the
            # trusted account should be one you recognise -- but calling it
            # CRITICAL drowns the findings that are actually actionable.
            return [
                Finding(
                    resource_id=role,
                    resource_type="iam_role",
                    issue_code="IAM_CROSS_ACCOUNT_TRUST",
                    title=f"AWS-managed role '{role}' is assumable from account(s) {', '.join(external)}",
                    description=(
                        f"'{role}' is created by AWS (Organizations, StackSets or a "
                        f"service-linked role) and trusting an external account is inherent "
                        f"to how it works. Listed so the trusted account can be verified, "
                        f"not because the configuration is wrong."
                    ),
                    base_severity=Severity.LOW,
                    remediation=(
                        f"Confirm that {', '.join(external)} is your own organisation "
                        f"management account. If it isn't, treat this as urgent."
                    ),
                    evidence={
                        "trusted_principals": principals,
                        "external_accounts": external,
                        "grants_admin": is_admin,
                        "policies": policy_names,
                        "aws_managed": True,
                    },
                )
            ]

        return [
            Finding(
                resource_id=role,
                resource_type="iam_role",
                issue_code="IAM_CROSS_ACCOUNT_TRUST",
                title=(
                    f"IAM role '{role}' can be assumed from outside this account"
                    + (" and grants administrator access" if is_admin else "")
                ),
                description=(
                    f"The trust policy on '{role}' allows sts:AssumeRole from "
                    f"{', '.join(principals)}. "
                    + (
                        "The role carries unrestricted (*:*) permissions, so compromising any "
                        "of those external principals yields administrator access in this account."
                        if is_admin
                        else "Compromising any of those external principals grants this role's "
                        "permissions in this account."
                    )
                ),
                base_severity=Severity.CRITICAL if is_admin else Severity.MEDIUM,
                sensitive=is_admin,
                remediation=(
                    "Scope the trust policy to the specific role that needs it, add an "
                    "sts:ExternalId condition, and reduce the role's permissions to least privilege."
                ),
                evidence={
                    "trusted_principals": principals,
                    "external_accounts": external,
                    "grants_admin": is_admin,
                    "policies": policy_names,
                    "aws_managed": False,
                },
            )
        ]

    def _scan_password_policy(self) -> List[Finding]:
        policy = self.source.get_account_password_policy()
        weak = (
            policy.get("minimum_password_length", 0) < settings.min_password_length
            or not policy.get("require_symbols", False)
        )
        if not weak:
            return []
        return [
            Finding(
                resource_id="account",
                resource_type="iam_account",
                issue_code="IAM_WEAK_PASSWORD_POLICY",
                title="Account password policy is weaker than recommended",
                description=(
                    f"Minimum length is {policy.get('minimum_password_length', 0)} "
                    f"(recommended >= {settings.min_password_length}); symbols required: "
                    f"{policy.get('require_symbols', False)}."
                ),
                base_severity=Severity.LOW,
                remediation=f"Require a minimum length of {settings.min_password_length}+ with symbols, numbers, and mixed case.",
                evidence={"policy": policy},
            )
        ]
