"""
Data source abstraction.

Every scanner is written against the AWSDataSource interface below and does
not know or care whether it's talking to a live AWS account or to seeded
demo data. This is what lets CloudChain run identically in --mode demo and
--mode real: swap the data source, everything downstream (scanners, graph,
risk scoring) is unaffected.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("cloudchain.sources")


def _as_list(value: Any) -> List[Any]:
    """AWS policy documents use a bare string where a list of one is meant."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _flatten_policy_document(document: Any) -> List[Tuple[str, str]]:
    """An IAM policy document -> flat (action, resource) Allow pairs.

    Handles both the dict form boto3 returns for inline policies and the JSON
    string form that sometimes appears, plus AWS's habit of using a bare string
    where a single-element list is meant.
    """
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return []
    if not isinstance(document, dict):
        return []

    pairs: List[Tuple[str, str]] = []
    for stmt in _as_list(document.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        for action in _as_list(stmt.get("Action")):
            for resource in _as_list(stmt.get("Resource")) or ["*"]:
                pairs.append((action, resource))
    return pairs


class AWSDataSource(ABC):
    # Identity of the account this source reads from. Findings are stamped with
    # it so the graph can tell same-account escalation apart from a chain that
    # crosses an organisation boundary.
    account_id: str = ""
    account_name: str = ""

    # --- S3 ---
    @abstractmethod
    def list_buckets(self) -> List[str]: ...

    @abstractmethod
    def get_public_access_block(self, bucket: str) -> Dict[str, bool]: ...

    @abstractmethod
    def is_bucket_acl_public(self, bucket: str) -> bool: ...

    @abstractmethod
    def is_bucket_policy_public(self, bucket: str) -> bool: ...

    @abstractmethod
    def is_bucket_encrypted(self, bucket: str) -> bool: ...

    def get_bucket_encryption(self, bucket: str) -> Dict[str, Any]:
        """What kind of default encryption a bucket has, not merely whether.

        AWS has applied SSE-S3 to every new bucket since January 2023, so
        "is it encrypted?" is now nearly always yes and the check stops telling
        you anything. The useful question is which key: an AWS-owned key
        (AES256) gives you no control over rotation or access, while a
        customer-managed KMS key does.

        Returns {"enabled", "algorithm", "kms_key_id", "bucket_key_enabled"}.
        Default derives from is_bucket_encrypted so sources that can't tell the
        difference keep working.
        """
        enabled = self.is_bucket_encrypted(bucket)
        return {
            "enabled": enabled,
            "algorithm": "AES256" if enabled else "",
            "kms_key_id": None,
            "bucket_key_enabled": False,
        }

    @abstractmethod
    def is_bucket_versioned(self, bucket: str) -> bool: ...

    @abstractmethod
    def list_object_keys(self, bucket: str, limit: int = 1000) -> List[str]: ...

    def leaked_credentials_hint(self, bucket: str) -> Optional[str]:
        """Ground-truth hint used only in demo mode. Real mode returns None;
        real correlation instead relies purely on object-key pattern matching
        (see s3_scanner.CREDENTIAL_KEY_PATTERNS)."""
        return None

    # --- IAM ---
    @abstractmethod
    def list_iam_users(self) -> List[str]: ...

    @abstractmethod
    def user_has_mfa(self, user: str) -> bool: ...

    @abstractmethod
    def list_access_keys(self, user: str) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def list_user_policy_names(self, user: str) -> List[str]: ...

    @abstractmethod
    def list_iam_roles(self) -> List[str]: ...

    @abstractmethod
    def list_role_policy_names(self, role: str) -> List[str]: ...

    def list_role_trust_principals(self, role: str) -> List[str]:
        """Principal ARNs allowed to assume this role by its trust policy.

        Service principals (lambda.amazonaws.com and friends) are excluded --
        only IAM principals, which is what can carry an attacker across an
        account boundary. Concrete, non-abstract default so a data source that
        can't answer this degrades to "no external trust" rather than breaking.
        """
        return []

    @abstractmethod
    def get_policy_statements(self, policy_name: str) -> List[Tuple[str, str]]:
        """Return a flattened list of (action, resource) pairs granted (Allow
        effect only) by the given policy name."""
        ...

    def get_identity_policy_statements(
        self, identity_type: str, name: str
    ) -> List[Tuple[str, str]]:
        """Every (action, resource) pair granted to a user or role.

        This exists because resolving a policy *by name* is not sufficient on a
        real account. An identity's permissions can come from three places:

          - an attached AWS-managed policy  (resolvable by name)
          - an attached customer-managed policy  (needs its full ARN)
          - an inline policy  (has no ARN at all; it is read from the identity)

        Only the first is answerable from a name, so a source that can do
        better overrides this. Scanning a real THM lab surfaced exactly this
        gap: users whose over-privilege lived in an inline policy came back
        looking clean.

        identity_type is "user" or "role".
        """
        names = (
            self.list_user_policy_names(name)
            if identity_type == "user"
            else self.list_role_policy_names(name)
        )
        pairs: List[Tuple[str, str]] = []
        for policy_name in names:
            pairs.extend(self.get_policy_statements(policy_name))
        return pairs

    @abstractmethod
    def get_account_password_policy(self) -> Dict[str, Any]: ...

    # --- EC2 / Security Groups ---
    @abstractmethod
    def list_security_groups(self) -> List[Dict[str, Any]]: ...

    # --- CloudTrail ---
    def lookup_events(
        self,
        resource_name: str,
        event_names: Sequence[str],
        lookback_days: int = 90,
    ) -> List[Dict[str, Any]]:
        """Management events touching a resource, most recent first.

        Concrete default returning nothing, so a data source that has no trail
        (or no permission to read one) degrades to "cannot attribute" rather
        than breaking a scan.
        """
        return []


class DemoAWSDataSource(AWSDataSource):
    """Reads one account of the seeded synthetic org in app/demo/mock_aws.py.

    Defaults to the primary (prod) account so single-account callers and the
    existing tests behave exactly as before; pass an account_id to read one of
    the other org members.
    """

    def __init__(self, account_id: Optional[str] = None):
        from app.demo import mock_aws

        self._m = mock_aws
        account = (
            mock_aws.ACCOUNTS_BY_ID[account_id] if account_id else mock_aws.PRIMARY_ACCOUNT
        )
        self._account = account
        self.account_id = account["id"]
        self.account_name = account["name"]
        self._policies = account["policies"]
        self._buckets = {b["name"]: b for b in account["buckets"]}
        self._users = {u["name"]: u for u in account["users"]}
        self._roles = {r["name"]: r for r in account["roles"]}

    def list_buckets(self) -> List[str]:
        return list(self._buckets.keys())

    def get_public_access_block(self, bucket: str) -> Dict[str, bool]:
        return dict(self._buckets[bucket]["public_access_block"])

    def is_bucket_acl_public(self, bucket: str) -> bool:
        return bool(self._buckets[bucket]["acl_public"])

    def is_bucket_policy_public(self, bucket: str) -> bool:
        return bool(self._buckets[bucket]["policy_public"])

    def is_bucket_encrypted(self, bucket: str) -> bool:
        return bool(self._buckets[bucket]["encryption_enabled"])

    def is_bucket_versioned(self, bucket: str) -> bool:
        return bool(self._buckets[bucket]["versioning_enabled"])

    def list_object_keys(self, bucket: str, limit: int = 1000) -> List[str]:
        return list(self._buckets[bucket]["objects"])[:limit]

    def leaked_credentials_hint(self, bucket: str) -> Optional[str]:
        return self._buckets[bucket].get("leaked_credentials_for")

    def list_iam_users(self) -> List[str]:
        return list(self._users.keys())

    def user_has_mfa(self, user: str) -> bool:
        return bool(self._users[user]["mfa_enabled"])

    def list_access_keys(self, user: str) -> List[Dict[str, Any]]:
        return list(self._users[user]["access_keys"])

    def list_user_policy_names(self, user: str) -> List[str]:
        return list(self._users[user]["attached_policies"])

    def list_iam_roles(self) -> List[str]:
        return list(self._roles.keys())

    def list_role_policy_names(self, role: str) -> List[str]:
        return list(self._roles[role]["attached_policies"])

    def list_role_trust_principals(self, role: str) -> List[str]:
        return list(self._roles[role].get("trust_principals", []))

    def get_policy_statements(self, policy_name: str) -> List[Tuple[str, str]]:
        return list(self._policies.get(policy_name, []))

    def get_account_password_policy(self) -> Dict[str, Any]:
        return dict(self._account["password_policy"])

    def list_security_groups(self) -> List[Dict[str, Any]]:
        return [dict(sg) for sg in self._account["security_groups"]]

    def lookup_events(
        self,
        resource_name: str,
        event_names: Sequence[str],
        lookback_days: int = 90,
    ) -> List[Dict[str, Any]]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        wanted = set(event_names)

        matches = []
        for event in self._m.CLOUDTRAIL_EVENTS:
            if event["account_id"] != self.account_id:
                continue
            if resource_name not in event.get("resources", []):
                continue
            if wanted and event["event_name"] not in wanted:
                continue
            if datetime.fromisoformat(event["event_time"]) < cutoff:
                continue
            matches.append(dict(event))

        matches.sort(key=lambda e: e["event_time"], reverse=True)
        return matches


class RealAWSDataSource(AWSDataSource):
    """Talks to a live AWS account via boto3.

    Credentials come from one of two places:
      1. Explicitly passed in (what the web UI does -- the user submits an
         access key pair, it is used for the duration of one scan and then
         discarded). These are NEVER written to the database, to disk, or to
         logs; see app/jobs.py.
      2. The ambient boto3 credential chain (env vars, ~/.aws/credentials,
         instance role) when nothing is passed -- what the CLI uses.

    Every call is wrapped so a missing permission (AccessDenied) degrades to
    an empty/safe result with a logged warning instead of crashing the whole
    scan -- real accounts rarely grant a scanner every permission it asks for.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
    ):
        import boto3

        if access_key_id and secret_access_key:
            session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token or None,
                region_name=region,
            )
        else:
            session = boto3.Session(region_name=region)

        self._s3 = session.client("s3")
        self._iam = session.client("iam")
        self._ec2 = session.client("ec2")
        self._cloudtrail = session.client("cloudtrail")

        # Resolve the account id once so findings can be attributed. A failure
        # here is non-fatal: the scan still runs, findings are just unattributed.
        self.account_id = self._safe(
            lambda: session.client("sts").get_caller_identity().get("Account", ""), ""
        )
        self.account_name = self.account_id

    @staticmethod
    def _safe(fn, default):
        try:
            return fn()
        except Exception as exc:  # botocore.exceptions.ClientError, etc.
            logger.warning("AWS call failed, degrading to default: %s", exc)
            return default

    # --- S3 ---
    def list_buckets(self) -> List[str]:
        resp = self._safe(lambda: self._s3.list_buckets(), {"Buckets": []})
        return [b["Name"] for b in resp.get("Buckets", [])]

    def get_public_access_block(self, bucket: str) -> Dict[str, bool]:
        def call():
            resp = self._s3.get_public_access_block(Bucket=bucket)
            return resp["PublicAccessBlockConfiguration"]

        return self._safe(
            call,
            {
                "BlockPublicAcls": False,
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": False,
                "RestrictPublicBuckets": False,
            },
        )

    def is_bucket_acl_public(self, bucket: str) -> bool:
        def call():
            grants = self._s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
            public_uris = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }
            for g in grants:
                grantee = g.get("Grantee", {})
                if grantee.get("URI") in public_uris:
                    return True
            return False

        return self._safe(call, False)

    def is_bucket_policy_public(self, bucket: str) -> bool:
        def call():
            import json

            policy = json.loads(self._s3.get_bucket_policy(Bucket=bucket)["Policy"])
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    return True
            return False

        return self._safe(call, False)

    def is_bucket_encrypted(self, bucket: str) -> bool:
        return bool(self.get_bucket_encryption(bucket)["enabled"])

    def get_bucket_encryption(self, bucket: str) -> Dict[str, Any]:
        def call():
            resp = self._s3.get_bucket_encryption(Bucket=bucket)
            rules = resp["ServerSideEncryptionConfiguration"].get("Rules", [])
            if not rules:
                return {
                    "enabled": False,
                    "algorithm": "",
                    "kms_key_id": None,
                    "bucket_key_enabled": False,
                }
            rule = rules[0]
            default = rule.get("ApplyServerSideEncryptionByDefault", {}) or {}
            return {
                "enabled": True,
                "algorithm": default.get("SSEAlgorithm", ""),
                "kms_key_id": default.get("KMSMasterKeyID"),
                "bucket_key_enabled": bool(rule.get("BucketKeyEnabled")),
            }

        # ServerSideEncryptionConfigurationNotFoundError means genuinely
        # unencrypted, which _safe collapses to the same default.
        return self._safe(
            call,
            {"enabled": False, "algorithm": "", "kms_key_id": None, "bucket_key_enabled": False},
        )

    def is_bucket_versioned(self, bucket: str) -> bool:
        def call():
            resp = self._s3.get_bucket_versioning(Bucket=bucket)
            return resp.get("Status") == "Enabled"

        return self._safe(call, False)

    def list_object_keys(self, bucket: str, limit: int = 1000) -> List[str]:
        def call():
            keys: List[str] = []
            paginator = self._s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket, PaginationConfig={"MaxItems": limit}):
                for obj in page.get("Contents", []):
                    keys.append(obj["Key"])
            return keys

        return self._safe(call, [])

    # --- IAM ---
    def list_iam_users(self) -> List[str]:
        def call():
            users = []
            paginator = self._iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(u["UserName"] for u in page["Users"])
            return users

        return self._safe(call, [])

    def user_has_mfa(self, user: str) -> bool:
        def call():
            resp = self._iam.list_mfa_devices(UserName=user)
            return len(resp.get("MFADevices", [])) > 0

        return self._safe(call, False)

    def list_access_keys(self, user: str) -> List[Dict[str, Any]]:
        def call():
            resp = self._iam.list_access_keys(UserName=user)
            keys = []
            for k in resp.get("AccessKeyMetadata", []):
                keys.append(
                    {
                        "id": k["AccessKeyId"],
                        "status": k["Status"],
                        "created": k["CreateDate"].isoformat(),
                        "last_used": self._get_key_last_used(k["AccessKeyId"]),
                    }
                )
            return keys

        return self._safe(call, [])

    def _get_key_last_used(self, access_key_id: str) -> Optional[str]:
        def call():
            resp = self._iam.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used = resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            return last_used.isoformat() if last_used else None

        return self._safe(call, None)

    def list_user_policy_names(self, user: str) -> List[str]:
        def call():
            names = [
                p["PolicyName"]
                for p in self._iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
            ]
            names += self._iam.list_user_policies(UserName=user).get("PolicyNames", [])
            return names

        return self._safe(call, [])

    def list_iam_roles(self) -> List[str]:
        def call():
            roles = []
            paginator = self._iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(r["RoleName"] for r in page["Roles"])
            return roles

        return self._safe(call, [])

    def list_role_policy_names(self, role: str) -> List[str]:
        def call():
            names = [
                p["PolicyName"]
                for p in self._iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
            ]
            names += self._iam.list_role_policies(RoleName=role).get("PolicyNames", [])
            return names

        return self._safe(call, [])

    def list_role_trust_principals(self, role: str) -> List[str]:
        def call():
            doc = self._iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]
            statements = doc.get("Statement", [])
            statements = statements if isinstance(statements, list) else [statements]

            principals: List[str] = []
            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue
                if "sts:AssumeRole" not in _as_list(stmt.get("Action", [])):
                    continue
                # Only IAM principals matter here. A Service principal
                # (lambda.amazonaws.com) can't carry an attacker across an
                # account boundary, so it is deliberately not collected.
                aws = stmt.get("Principal", {}).get("AWS")
                principals.extend(_as_list(aws))
            return principals

        return self._safe(call, [])

    def get_identity_policy_statements(
        self, identity_type: str, name: str
    ) -> List[Tuple[str, str]]:
        """Resolve an identity's real permissions: attached *and* inline.

        Attached policies are read from their ARN, which covers both AWS-managed
        and customer-managed. Inline policies have no ARN and are fetched from
        the identity itself. Resolving only by name -- as this used to -- misses
        both customer-managed and inline, which is the majority of the
        interesting permissions on a real account.
        """
        is_user = identity_type == "user"
        pairs: List[Tuple[str, str]] = []

        def attached():
            if is_user:
                resp = self._iam.list_attached_user_policies(UserName=name)
            else:
                resp = self._iam.list_attached_role_policies(RoleName=name)
            return [p["PolicyArn"] for p in resp.get("AttachedPolicies", [])]

        for arn in self._safe(attached, []):
            pairs.extend(self._statements_from_policy_arn(arn))

        def inline_names():
            if is_user:
                return self._iam.list_user_policies(UserName=name).get("PolicyNames", [])
            return self._iam.list_role_policies(RoleName=name).get("PolicyNames", [])

        for policy_name in self._safe(inline_names, []):

            def document(policy_name=policy_name):
                if is_user:
                    resp = self._iam.get_user_policy(UserName=name, PolicyName=policy_name)
                else:
                    resp = self._iam.get_role_policy(RoleName=name, PolicyName=policy_name)
                return resp["PolicyDocument"]

            doc = self._safe(document, None)
            if doc:
                pairs.extend(_flatten_policy_document(doc))

        return pairs

    def _statements_from_policy_arn(self, arn: str) -> List[Tuple[str, str]]:
        """Read a managed policy's default version. Works for both AWS-managed
        (arn:aws:iam::aws:policy/...) and customer-managed ARNs."""

        def call():
            policy = self._iam.get_policy(PolicyArn=arn)["Policy"]
            version = self._iam.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )
            return _flatten_policy_document(version["PolicyVersion"]["Document"])

        return self._safe(call, [])

    def get_policy_statements(self, policy_name: str) -> List[Tuple[str, str]]:
        """Best-effort resolution: tries AWS-managed policy by name first,
        since that covers the common escalation-relevant policies (e.g.
        AdministratorAccess). Customer-managed/inline lookups by bare name
        require the caller to pass a full ARN in real deployments; this
        keeps the interface simple for the demo/real parity we need here."""

        def call():
            arn = f"arn:aws:iam::aws:policy/{policy_name}"
            pol = self._iam.get_policy(PolicyArn=arn)["Policy"]
            version_id = pol["DefaultVersionId"]
            doc = self._iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            statement = doc["PolicyVersion"]["Document"].get("Statement", [])
            pairs = []
            for stmt in statement if isinstance(statement, list) else [statement]:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = stmt.get("Resource", [])
                resources = [resources] if isinstance(resources, str) else resources
                for a in actions:
                    for r in resources or ["*"]:
                        pairs.append((a, r))
            return pairs

        return self._safe(call, [])

    def get_account_password_policy(self) -> Dict[str, Any]:
        def call():
            resp = self._iam.get_account_password_policy()
            p = resp["PasswordPolicy"]
            return {
                "minimum_password_length": p.get("MinimumPasswordLength", 0),
                "require_symbols": p.get("RequireSymbols", False),
                "require_numbers": p.get("RequireNumbers", False),
                "require_uppercase": p.get("RequireUppercaseCharacters", False),
                "require_lowercase": p.get("RequireLowercaseCharacters", False),
            }

        return self._safe(
            call,
            {
                "minimum_password_length": 0,
                "require_symbols": False,
                "require_numbers": False,
                "require_uppercase": False,
                "require_lowercase": False,
            },
        )

    # --- CloudTrail ---
    def lookup_events(
        self,
        resource_name: str,
        event_names: Sequence[str],
        lookback_days: int = 90,
    ) -> List[Dict[str, Any]]:
        """CloudTrail LookupEvents for one resource.

        LookupEvents accepts only a single lookup attribute per call, so the
        query is by ResourceName and the event-name filter is applied here.
        Note the hard 90-day limit: LookupEvents reads CloudTrail's own event
        history, not a trail's S3 bucket, so anything older is simply not
        answerable this way.
        """

        def call():
            start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
            wanted = set(event_names)
            results: List[Dict[str, Any]] = []

            paginator = self._cloudtrail.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "ResourceName", "AttributeValue": resource_name}
                ],
                StartTime=start,
                PaginationConfig={"MaxItems": 200},
            )
            for page in pages:
                for event in page.get("Events", []):
                    name = event.get("EventName", "")
                    if wanted and name not in wanted:
                        continue
                    results.append(self._normalise_event(event, resource_name))
            return results

        events = self._safe(call, [])
        events.sort(key=lambda e: e["event_time"], reverse=True)
        return events

    @staticmethod
    def _normalise_event(event: Dict[str, Any], resource_name: str) -> Dict[str, Any]:
        """Flatten a LookupEvents record into the shape the attributor expects."""
        import json as _json

        detail: Dict[str, Any] = {}
        raw = event.get("CloudTrailEvent")
        if raw:
            try:
                detail = _json.loads(raw)
            except (ValueError, TypeError):
                detail = {}

        identity = detail.get("userIdentity", {}) or {}
        event_time = event.get("EventTime")

        return {
            "account_id": identity.get("accountId", ""),
            "event_id": event.get("EventId", ""),
            "event_name": event.get("EventName", ""),
            "event_time": event_time.isoformat() if hasattr(event_time, "isoformat") else str(event_time),
            "actor_arn": identity.get("arn") or event.get("Username", "") or "unknown",
            "actor_type": identity.get("type", "Unknown"),
            "source_ip": detail.get("sourceIPAddress", ""),
            "user_agent": detail.get("userAgent", ""),
            "resources": [
                r.get("ResourceName", "") for r in event.get("Resources", [])
            ] or [resource_name],
            "request_parameters": detail.get("requestParameters") or {},
        }

    # --- EC2 / Security Groups ---
    def list_security_groups(self) -> List[Dict[str, Any]]:
        def call():
            groups = []
            paginator = self._ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    ingress = []
                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort", 0)
                        to_port = perm.get("ToPort", 65535)
                        protocol = perm.get("IpProtocol", "-1")
                        for ip_range in perm.get("IpRanges", []):
                            ingress.append(
                                {
                                    "cidr": ip_range.get("CidrIp"),
                                    "from_port": from_port,
                                    "to_port": to_port,
                                    "protocol": protocol,
                                }
                            )
                    groups.append(
                        {
                            "group_id": sg["GroupId"],
                            "name": sg.get("GroupName", sg["GroupId"]),
                            "ingress": ingress,
                        }
                    )
            return groups

        return self._safe(call, [])


def validate_credentials(
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a credential pair via STS GetCallerIdentity before running a full
    scan, so the UI can fail fast with a clear message instead of returning an
    empty report. Returns {"valid": bool, "account": str, "arn": str, "error": str}.
    """
    try:
        # Imported inside the try: a broken or missing boto3 install must
        # surface as a clean validation failure, not a 500 from the API.
        import boto3

        if access_key_id and secret_access_key:
            session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token or None,
                region_name=region,
            )
        else:
            session = boto3.Session(region_name=region)

        identity = session.client("sts").get_caller_identity()
        return {
            "valid": True,
            "account": identity.get("Account", ""),
            "arn": identity.get("Arn", ""),
            "error": "",
        }
    except Exception as exc:
        # Deliberately does not echo the submitted keys back in the message.
        return {"valid": False, "account": "", "arn": "", "error": str(exc)}


def get_data_source(
    mode: str,
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
) -> AWSDataSource:
    """A single data source. Demo mode returns the primary account."""
    if mode == "demo":
        return DemoAWSDataSource()
    if mode == "real":
        return RealAWSDataSource(
            region=region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
        )
    raise ValueError(f"Unknown mode: {mode!r} (expected 'demo' or 'real')")


def get_data_sources(
    mode: str,
    region: str = "us-east-1",
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
) -> List[AWSDataSource]:
    """Every account a scan should cover.

    Demo mode returns one source per account in the synthetic org, which is
    what lets the graph engine find chains that cross an account boundary.
    Real mode returns a single source: scanning a whole AWS Organization needs
    a management-account role and an sts:AssumeRole fan-out, which this
    deliberately doesn't attempt with a single submitted key pair.
    """
    if mode == "demo":
        from app.demo import mock_aws

        return [DemoAWSDataSource(account_id=a["id"]) for a in mock_aws.ACCOUNTS]

    return [
        get_data_source(
            mode,
            region=region,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
        )
    ]
