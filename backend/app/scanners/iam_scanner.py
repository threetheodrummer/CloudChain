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
from app.sources import AWSDataSource

COMPUTE_CREATE_ACTIONS = {
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
}


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
            statements = _collect_statements(self.source, policy_names)
            actions: Set[str] = {a for a, _ in statements}

            if ("*", "*") in statements:
                findings.append(
                    Finding(
                        resource_id=user,
                        resource_type="iam_user",
                        issue_code="IAM_OVERPERMISSIVE_POLICY",
                        title=f"IAM user '{user}' has a wildcard (*:*) policy attached",
                        description=f"Attached polic{'y' if len(policy_names)==1 else 'ies'} {policy_names} grant unrestricted access.",
                        base_severity=Severity.CRITICAL,
                        remediation="Replace with a least-privilege policy scoped to the specific actions/resources this identity needs.",
                        evidence={"policies": policy_names},
                    )
                )

            has_passrole = "iam:PassRole" in actions
            has_compute_create = bool(actions & COMPUTE_CREATE_ACTIONS)
            if has_passrole and has_compute_create:
                pass_role_targets = [
                    _extract_role_name(r) for a, r in statements if a == "iam:PassRole"
                ]
                findings.append(
                    Finding(
                        resource_id=user,
                        resource_type="iam_user",
                        issue_code="IAM_PRIVILEGE_ESCALATION_RISK",
                        title=f"IAM user '{user}' can escalate privileges via PassRole + compute creation",
                        description=(
                            "This identity holds iam:PassRole together with a compute-creation "
                            "action (Lambda/EC2). It can pass an over-privileged role into a new "
                            "function/instance and run code as that role -- a well-known AWS "
                            "privilege escalation primitive."
                        ),
                        base_severity=Severity.CRITICAL,
                        remediation=(
                            "Scope iam:PassRole to specific role ARNs with a condition, and remove "
                            "compute-creation permissions this identity doesn't need."
                        ),
                        evidence={
                            "policies": policy_names,
                            "pass_role_targets": pass_role_targets,
                            "compute_actions": sorted(actions & COMPUTE_CREATE_ACTIONS),
                        },
                    )
                )

        return findings

    def _scan_roles(self) -> List[Finding]:
        findings: List[Finding] = []
        for role in self.source.list_iam_roles():
            policy_names = self.source.list_role_policy_names(role)
            statements = _collect_statements(self.source, policy_names)
            if ("*", "*") in statements:
                findings.append(
                    Finding(
                        resource_id=role,
                        resource_type="iam_role",
                        issue_code="IAM_ROLE_ADMIN_ACCESS",
                        title=f"IAM role '{role}' has administrator-level access",
                        description=f"Attached polic{'y' if len(policy_names)==1 else 'ies'} {policy_names} grant unrestricted access.",
                        base_severity=Severity.HIGH,
                        remediation="Scope this role to only the permissions its workload requires.",
                        evidence={"policies": policy_names},
                    )
                )
        return findings

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
