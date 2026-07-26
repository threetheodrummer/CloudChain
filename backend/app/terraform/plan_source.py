"""
Terraform plans as a data source.

Finding an attack path after it exists is useful. Not merging it is better.
This module lets CloudChain answer the same question against a `terraform
plan` that it answers against a live account: *if this change were applied,
would there be a route from the internet to AdministratorAccess?*

The implementation deliberately adds no new analysis. PlanDataSource
implements the same AWSDataSource interface the live scanners already read
from, so the scanners, the graph engine, the risk scoring and the posture
score all run against a plan completely unchanged. That parity is the whole
point: the verdict a developer gets in CI is computed by the identical code
that will judge the account after apply. Vendors sell pre-deploy and
post-deploy as separate products, and they drift apart precisely because they
are separate implementations.

Input is the output of:

    terraform plan -out=tfplan && terraform show -json tfplan > plan.json

which contains `planned_values` -- the full desired state after apply, not
just the diff. Scanning the desired state rather than the changed resources
matters: a change that makes a *pre-existing* role dangerous only shows up if
you evaluate the whole resulting picture.

What a plan cannot tell you, and what this does about it
-------------------------------------------------------
A plan describes intended infrastructure, not operational reality. It cannot
know whether a user has enrolled an MFA device or how old an access key is --
those are runtime facts, and no `terraform plan` contains them. Rather than
guess, this source returns the *safe* answer for anything a plan can't prove
(MFA enrolled, no stale keys, password policy compliant when unmanaged), so
those checks stay silent in CI.

That's a deliberate trade. Shift-left tooling dies from false positives: a
gate that flags every pull request for things the author cannot fix from the
plan gets switched off within a week. CloudChain reports only what the plan
genuinely proves, and the post-apply scan continues to cover the rest.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.sources import AWSDataSource

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def _walk_modules(module: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Every resource in a planned_values tree, including child modules."""
    for resource in module.get("resources", []) or []:
        yield resource
    for child in module.get("child_modules", []) or []:
        yield from _walk_modules(child)


def parse_plan(plan: Dict[str, Any] | str) -> Dict[str, List[Dict[str, Any]]]:
    """Group a `terraform show -json` document by resource type.

    Accepts either a parsed dict or raw JSON text.
    """
    if isinstance(plan, str):
        plan = json.loads(plan)

    if "planned_values" not in plan:
        raise ValueError(
            "not a Terraform plan document: no 'planned_values' key. Generate one with "
            "`terraform plan -out=tfplan && terraform show -json tfplan`."
        )

    root = (plan.get("planned_values") or {}).get("root_module") or {}
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for resource in _walk_modules(root):
        by_type.setdefault(resource.get("type", ""), []).append(resource)
    return by_type


def _values(resource: Dict[str, Any]) -> Dict[str, Any]:
    return resource.get("values") or {}


def _policy_statements(document: Any) -> List[Tuple[str, str]]:
    """Flatten an IAM policy document into (action, resource) Allow pairs."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return []
    if not isinstance(document, dict):
        return []

    statements = document.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]

    pairs: List[Tuple[str, str]] = []
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = stmt.get("Resource", [])
        resources = [resources] if isinstance(resources, str) else resources
        for action in actions:
            for res in resources or ["*"]:
                pairs.append((action, res))
    return pairs


def _trust_principals(document: Any) -> List[str]:
    """IAM principal ARNs from an assume_role_policy. Service principals are
    excluded -- they can't carry an attacker across an account boundary."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return []
    if not isinstance(document, dict):
        return []

    statements = document.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]

    principals: List[str] = []
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        if "sts:AssumeRole" not in actions:
            continue
        aws = (stmt.get("Principal") or {}).get("AWS")
        if isinstance(aws, str):
            principals.append(aws)
        elif isinstance(aws, list):
            principals.extend(aws)
    return principals


# AWS-managed policies CloudChain needs to understand by name alone, because a
# plan references them by ARN without including their contents.
_MANAGED_POLICIES: Dict[str, List[Tuple[str, str]]] = {
    "AdministratorAccess": [("*", "*")],
    "PowerUserAccess": [("*", "*")],
    "ReadOnlyAccess": [("s3:GetObject", "*"), ("s3:ListBucket", "*")],
}


def _policy_name_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if arn else ""


class PlanDataSource(AWSDataSource):
    """Reads planned Terraform state through the live-scan interface."""

    def __init__(self, plan: Dict[str, Any] | str, account_id: str = "", account_name: str = ""):
        self._by_type = parse_plan(plan)
        self.account_id = account_id
        self.account_name = account_name or (account_id and f"{account_id} (planned)") or "planned"

        self._buckets = self._index_buckets()
        self._users = self._index_users()
        self._roles = self._index_roles()
        self._policies = self._index_policies()

    # ------------------------------------------------------------- indexing

    def _index_buckets(self) -> Dict[str, Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = {}

        for res in self._by_type.get("aws_s3_bucket", []):
            name = _values(res).get("bucket")
            if not name:
                continue
            buckets[name] = {
                # Terraform's default when no public_access_block resource is
                # declared: AWS applies account-level defaults, and the plan
                # cannot see them. Treated as not-blocking so an explicitly
                # public ACL is still caught.
                "public_access_block": {
                    "BlockPublicAcls": False,
                    "BlockPublicPolicy": False,
                    "IgnorePublicAcls": False,
                    "RestrictPublicBuckets": False,
                },
                "acl_public": False,
                "policy_public": False,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "objects": [],
            }

        def bucket_of(res) -> Optional[Dict[str, Any]]:
            return buckets.get(_values(res).get("bucket"))

        for res in self._by_type.get("aws_s3_bucket_public_access_block", []):
            target = bucket_of(res)
            if target is None:
                continue
            v = _values(res)
            target["public_access_block"] = {
                "BlockPublicAcls": bool(v.get("block_public_acls")),
                "BlockPublicPolicy": bool(v.get("block_public_policy")),
                "IgnorePublicAcls": bool(v.get("ignore_public_acls")),
                "RestrictPublicBuckets": bool(v.get("restrict_public_buckets")),
            }

        for res in self._by_type.get("aws_s3_bucket_acl", []):
            target = bucket_of(res)
            if target is not None and _values(res).get("acl") in PUBLIC_ACLS:
                target["acl_public"] = True

        for res in self._by_type.get("aws_s3_bucket_policy", []):
            target = bucket_of(res)
            if target is None:
                continue
            doc = _values(res).get("policy")
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except (ValueError, TypeError):
                    doc = {}
            statements = (doc or {}).get("Statement", [])
            statements = statements if isinstance(statements, list) else [statements]
            for stmt in statements:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal")
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    target["policy_public"] = True

        for res in self._by_type.get("aws_s3_bucket_server_side_encryption_configuration", []):
            target = bucket_of(res)
            if target is not None:
                target["encryption_enabled"] = True

        for res in self._by_type.get("aws_s3_bucket_versioning", []):
            target = bucket_of(res)
            if target is None:
                continue
            config = _values(res).get("versioning_configuration")
            config = config[0] if isinstance(config, list) and config else config
            if isinstance(config, dict) and config.get("status") == "Enabled":
                target["versioning_enabled"] = True

        for res in self._by_type.get("aws_s3_object", []):
            target = bucket_of(res)
            key = _values(res).get("key")
            if target is not None and key:
                target["objects"].append(key)

        return buckets

    def _index_users(self) -> Dict[str, Dict[str, Any]]:
        users = {
            _values(r).get("name"): {"policies": []}
            for r in self._by_type.get("aws_iam_user", [])
            if _values(r).get("name")
        }

        for res in self._by_type.get("aws_iam_user_policy_attachment", []):
            v = _values(res)
            user = users.get(v.get("user"))
            if user is not None:
                user["policies"].append(_policy_name_from_arn(v.get("policy_arn", "")))

        for res in self._by_type.get("aws_iam_user_policy", []):
            v = _values(res)
            user = users.get(v.get("user"))
            if user is not None and v.get("name"):
                user["policies"].append(v["name"])

        return users

    def _index_roles(self) -> Dict[str, Dict[str, Any]]:
        roles = {}
        for res in self._by_type.get("aws_iam_role", []):
            v = _values(res)
            name = v.get("name")
            if not name:
                continue
            roles[name] = {
                "policies": list(v.get("managed_policy_arns") or []),
                "trust": _trust_principals(v.get("assume_role_policy")),
            }
            roles[name]["policies"] = [_policy_name_from_arn(a) for a in roles[name]["policies"]]

        for res in self._by_type.get("aws_iam_role_policy_attachment", []):
            v = _values(res)
            role = roles.get(v.get("role"))
            if role is not None:
                role["policies"].append(_policy_name_from_arn(v.get("policy_arn", "")))

        for res in self._by_type.get("aws_iam_role_policy", []):
            v = _values(res)
            role = roles.get(v.get("role"))
            if role is not None and v.get("name"):
                role["policies"].append(v["name"])

        return roles

    def _index_policies(self) -> Dict[str, List[Tuple[str, str]]]:
        policies: Dict[str, List[Tuple[str, str]]] = dict(_MANAGED_POLICIES)

        for res in self._by_type.get("aws_iam_policy", []):
            v = _values(res)
            if v.get("name"):
                policies[v["name"]] = _policy_statements(v.get("policy"))

        # Inline policies are addressed by their own name on the identity.
        for kind in ("aws_iam_user_policy", "aws_iam_role_policy"):
            for res in self._by_type.get(kind, []):
                v = _values(res)
                if v.get("name"):
                    policies[v["name"]] = _policy_statements(v.get("policy"))

        return policies

    # ------------------------------------------------------------- coverage

    def describes_resources(self) -> set:
        """(account_id, resource_type, resource_id) for everything in the plan.

        A plan almost never describes a whole account. Knowing exactly what it
        does cover is what lets the analyser tell "this change removed a
        finding" apart from "this plan simply doesn't mention that resource" --
        conflating the two would report most of an account as fixed by any
        small pull request.
        """
        described = set()
        for bucket in self._buckets:
            described.add((self.account_id, "s3_bucket", bucket))
        for user in self._users:
            described.add((self.account_id, "iam_user", user))
        for role in self._roles:
            described.add((self.account_id, "iam_role", role))
        for group in self.list_security_groups():
            described.add((self.account_id, "security_group", group["group_id"]))
        if self._by_type.get("aws_iam_account_password_policy"):
            described.add((self.account_id, "iam_account", "account"))
        return described

    # ------------------------------------------------------------------ S3

    def list_buckets(self) -> List[str]:
        return list(self._buckets)

    def get_public_access_block(self, bucket: str) -> Dict[str, bool]:
        return dict(self._buckets[bucket]["public_access_block"])

    def is_bucket_acl_public(self, bucket: str) -> bool:
        return self._buckets[bucket]["acl_public"]

    def is_bucket_policy_public(self, bucket: str) -> bool:
        return self._buckets[bucket]["policy_public"]

    def is_bucket_encrypted(self, bucket: str) -> bool:
        return self._buckets[bucket]["encryption_enabled"]

    def is_bucket_versioned(self, bucket: str) -> bool:
        return self._buckets[bucket]["versioning_enabled"]

    def list_object_keys(self, bucket: str, limit: int = 1000) -> List[str]:
        return list(self._buckets[bucket]["objects"])[:limit]

    # ----------------------------------------------------------------- IAM

    def list_iam_users(self) -> List[str]:
        return list(self._users)

    def user_has_mfa(self, user: str) -> bool:
        # Not expressible in a plan. Returning True keeps the MFA check silent
        # in CI rather than flagging every planned user for something the
        # author cannot fix from Terraform.
        return True

    def list_access_keys(self, user: str) -> List[Dict[str, Any]]:
        # Key age is a runtime fact; a plan has nothing to say about it.
        return []

    def list_user_policy_names(self, user: str) -> List[str]:
        return list(self._users[user]["policies"])

    def list_iam_roles(self) -> List[str]:
        return list(self._roles)

    def list_role_policy_names(self, role: str) -> List[str]:
        return list(self._roles[role]["policies"])

    def list_role_trust_principals(self, role: str) -> List[str]:
        return list(self._roles[role]["trust"])

    def get_policy_statements(self, policy_name: str) -> List[Tuple[str, str]]:
        return list(self._policies.get(policy_name, []))

    def get_account_password_policy(self) -> Dict[str, Any]:
        for res in self._by_type.get("aws_iam_account_password_policy", []):
            v = _values(res)
            return {
                "minimum_password_length": v.get("minimum_password_length", 0),
                "require_symbols": bool(v.get("require_symbols")),
                "require_numbers": bool(v.get("require_numbers")),
                "require_uppercase": bool(v.get("require_uppercase_characters")),
                "require_lowercase": bool(v.get("require_lowercase_characters")),
            }
        # Unmanaged by this plan: report compliant so CI stays quiet about
        # something the change doesn't touch. The live scan still checks it.
        return {
            "minimum_password_length": 999,
            "require_symbols": True,
            "require_numbers": True,
            "require_uppercase": True,
            "require_lowercase": True,
        }

    # ----------------------------------------------------------------- EC2

    def list_security_groups(self) -> List[Dict[str, Any]]:
        groups: List[Dict[str, Any]] = []
        for res in self._by_type.get("aws_security_group", []):
            v = _values(res)
            ingress = []
            for rule in v.get("ingress") or []:
                for cidr in rule.get("cidr_blocks") or []:
                    ingress.append(
                        {
                            "cidr": cidr,
                            "from_port": rule.get("from_port", 0),
                            "to_port": rule.get("to_port", 65535),
                            "protocol": rule.get("protocol", "-1"),
                        }
                    )
            groups.append(
                {
                    "group_id": v.get("id") or v.get("name") or res.get("address", ""),
                    "name": v.get("name") or res.get("address", ""),
                    "ingress": ingress,
                }
            )

        for res in self._by_type.get("aws_security_group_rule", []):
            v = _values(res)
            if v.get("type") != "ingress":
                continue
            groups.append(
                {
                    "group_id": v.get("security_group_id", res.get("address", "")),
                    "name": v.get("security_group_id", res.get("address", "")),
                    "ingress": [
                        {
                            "cidr": cidr,
                            "from_port": v.get("from_port", 0),
                            "to_port": v.get("to_port", 65535),
                            "protocol": v.get("protocol", "-1"),
                        }
                        for cidr in v.get("cidr_blocks") or []
                    ],
                }
            )

        return groups
