"""
Synthetic AWS *organisation* used for demo mode.

Single-account scanning is the standard limitation of portfolio CSPM projects,
and it hides the attack paths that matter most: in a real org, the interesting
chain almost always crosses an account boundary. A workload account gets
compromised, and the actual damage happens because some role in the shared
services or security account trusts that workload account far too broadly.

So the demo models three accounts:

    111111111111  prod             the workload account, and where the
                                   initial foothold is
    222222222222  shared-services  hosts a deployment role that trusts prod
                                   and carries AdministratorAccess
    333333333333  sandbox          mostly clean, so the risk engine has
                                   something to rank below the chained findings

Two escalation chains fall out of this, and the difference between them is the
point of the whole feature:

  1. In-account (prod):
        public-uploads-bucket (public, leaks an access key)
          -> svc-deploy-bot (owns that key, no MFA, holds iam:PassRole
             + lambda:CreateFunction/InvokeFunction)
          -> LambdaExecutionAdminRole (passed into a new Lambda, then invoked)
          -> AdministratorAccess in prod

  2. Cross-account (prod -> shared-services):
        public-uploads-bucket
          -> svc-deploy-bot
          -> OrgDeploymentRole in 222222222222, whose trust policy names
             arn:aws:iam::111111111111:user/svc-deploy-bot
          -> AdministratorAccess in shared-services

Note the mechanism differs. iam:PassRole is inherently same-account -- AWS will
not let you pass a role that lives in another account -- so chain 1 cannot
cross the boundary. Crossing requires sts:AssumeRole against a role whose
*trust policy* names an external principal. The graph engine models these as
two distinct edge types for exactly that reason.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

NOW = datetime.now(timezone.utc)


def _days_ago(n: int) -> str:
    return (NOW - timedelta(days=n)).isoformat()


PROD = "111111111111"
SHARED = "222222222222"
SANDBOX = "333333333333"

_OPEN_PAB = {
    "BlockPublicAcls": False,
    "BlockPublicPolicy": False,
    "IgnorePublicAcls": False,
    "RestrictPublicBuckets": False,
}
_LOCKED_PAB = {
    "BlockPublicAcls": True,
    "BlockPublicPolicy": True,
    "IgnorePublicAcls": True,
    "RestrictPublicBuckets": True,
}

_DEFAULT_PASSWORD_POLICY = {
    "minimum_password_length": 8,
    "require_symbols": False,
    "require_numbers": True,
    "require_uppercase": True,
    "require_lowercase": True,
}

_STRONG_PASSWORD_POLICY = {
    "minimum_password_length": 16,
    "require_symbols": True,
    "require_numbers": True,
    "require_uppercase": True,
    "require_lowercase": True,
}


ACCOUNTS: List[Dict[str, Any]] = [
    # ---------------------------------------------------------------- prod
    {
        "id": PROD,
        "name": "prod",
        "buckets": [
            {
                "name": "public-uploads-bucket",
                "public_access_block": dict(_OPEN_PAB),
                "acl_public": True,
                "policy_public": False,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "tags": {"env": "prod"},
                "objects": [
                    "uploads/logo.png",
                    "uploads/report_q1.pdf",
                    "backup/credentials.csv",  # <- leaked secret, matched by key pattern
                ],
                # Demo-only correlation hint: in a real account this relationship
                # is inferred by the object-key pattern scan (see s3_scanner.py);
                # here we encode which identity the leaked object belongs to so
                # the graph engine can wire the edge with confidence.
                "leaked_credentials_for": "svc-deploy-bot",
            },
            {
                "name": "app-assets-public",
                "public_access_block": dict(_OPEN_PAB),
                "acl_public": True,
                "policy_public": True,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "tags": {"env": "prod", "purpose": "static-website"},
                "objects": ["index.html", "styles.css", "app.js"],
                "leaked_credentials_for": None,
            },
            {
                "name": "internal-data-lake",
                "public_access_block": dict(_LOCKED_PAB),
                "acl_public": False,
                "policy_public": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "tags": {"env": "prod", "sensitivity": "high"},
                "objects": ["warehouse/customers.parquet"],
                "leaked_credentials_for": None,
            },
        ],
        "users": [
            {
                "name": "svc-deploy-bot",
                "mfa_enabled": False,
                "access_keys": [
                    {
                        "id": "AKIADEMOACCESSKEY01",
                        "status": "Active",
                        "created": _days_ago(410),
                        "last_used": _days_ago(1),
                    }
                ],
                "attached_policies": ["DeployBotPolicy"],
            },
            {
                "name": "read-only-analyst",
                "mfa_enabled": True,
                "access_keys": [
                    {
                        "id": "AKIADEMOACCESSKEY02",
                        "status": "Active",
                        "created": _days_ago(20),
                        "last_used": _days_ago(1),
                    }
                ],
                "attached_policies": ["ReadOnlyAnalystPolicy"],
            },
            {
                "name": "legacy-ci-user",
                "mfa_enabled": False,
                "access_keys": [
                    {
                        "id": "AKIADEMOACCESSKEY03",
                        "status": "Active",
                        "created": _days_ago(730),
                        "last_used": _days_ago(400),
                    }
                ],
                "attached_policies": ["ReadOnlyAnalystPolicy"],
            },
        ],
        "roles": [
            {
                "name": "LambdaExecutionAdminRole",
                "attached_policies": ["AdministratorAccess"],
                "trust_policy_services": ["lambda.amazonaws.com"],
                "trust_principals": [],
            },
            {
                "name": "ReadOnlyServiceRole",
                "attached_policies": ["ReadOnlyAnalystPolicy"],
                "trust_policy_services": ["ec2.amazonaws.com"],
                "trust_principals": [],
            },
        ],
        "policies": {
            "DeployBotPolicy": [
                ("iam:PassRole", f"arn:aws:iam::{PROD}:role/LambdaExecutionAdminRole"),
                ("lambda:CreateFunction", "*"),
                ("lambda:InvokeFunction", "*"),
                ("sts:AssumeRole", "*"),
            ],
            "ReadOnlyAnalystPolicy": [
                ("s3:GetObject", "*"),
                ("s3:ListBucket", "*"),
            ],
            "AdministratorAccess": [("*", "*")],
        },
        "security_groups": [
            {
                "group_id": "sg-0demo0webserver",
                "name": "web-sg",
                "ingress": [
                    {"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"},
                    {"cidr": "0.0.0.0/0", "from_port": 3389, "to_port": 3389, "protocol": "tcp"},
                    {"cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443, "protocol": "tcp"},
                ],
            },
            {
                "group_id": "sg-0demo0internaldb",
                "name": "internal-db-sg",
                "ingress": [
                    {"cidr": "10.0.0.0/16", "from_port": 5432, "to_port": 5432, "protocol": "tcp"},
                ],
            },
        ],
        "password_policy": dict(_DEFAULT_PASSWORD_POLICY),
    },
    # ------------------------------------------------------ shared-services
    {
        "id": SHARED,
        "name": "shared-services",
        "buckets": [
            {
                "name": "shared-terraform-state",
                "public_access_block": dict(_LOCKED_PAB),
                "acl_public": False,
                "policy_public": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "tags": {"env": "shared"},
                "objects": ["state/prod.tfstate"],
                "leaked_credentials_for": None,
            },
        ],
        "users": [
            {
                "name": "platform-admin",
                "mfa_enabled": True,
                "access_keys": [
                    {
                        "id": "AKIADEMOACCESSKEY04",
                        "status": "Active",
                        "created": _days_ago(45),
                        "last_used": _days_ago(2),
                    }
                ],
                "attached_policies": ["ReadOnlyAnalystPolicy"],
            },
        ],
        "roles": [
            {
                # The crux of the cross-account chain: this role carries
                # AdministratorAccess in shared-services, and its trust policy
                # names an individual user in the prod account. Compromising
                # that one prod identity therefore yields admin *here*.
                "name": "OrgDeploymentRole",
                "attached_policies": ["AdministratorAccess"],
                "trust_policy_services": [],
                "trust_principals": [f"arn:aws:iam::{PROD}:user/svc-deploy-bot"],
            },
            {
                "name": "AuditReadOnlyRole",
                "attached_policies": ["ReadOnlyAnalystPolicy"],
                "trust_policy_services": [],
                "trust_principals": [f"arn:aws:iam::{SANDBOX}:root"],
            },
            {
                # AWS Organizations creates this in every member account, and
                # its trust policy names the management account by design.
                # Present so the demo exercises the AWS-managed-role rule that
                # stops it being reported as a CRITICAL finding.
                "name": "OrganizationAccountAccessRole",
                "attached_policies": ["AdministratorAccess"],
                "trust_policy_services": [],
                "trust_principals": ["arn:aws:iam::999999999999:root"],
            },
        ],
        "policies": {
            "ReadOnlyAnalystPolicy": [
                ("s3:GetObject", "*"),
                ("s3:ListBucket", "*"),
            ],
            "AdministratorAccess": [("*", "*")],
        },
        "security_groups": [
            {
                "group_id": "sg-0demo0bastion",
                "name": "bastion-sg",
                "ingress": [
                    {"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22, "protocol": "tcp"},
                ],
            },
        ],
        "password_policy": dict(_STRONG_PASSWORD_POLICY),
    },
    # ------------------------------------------------------------- sandbox
    {
        "id": SANDBOX,
        "name": "sandbox",
        "buckets": [
            {
                "name": "sandbox-scratch",
                "public_access_block": dict(_LOCKED_PAB),
                "acl_public": False,
                "policy_public": False,
                "encryption_enabled": False,
                "versioning_enabled": False,
                "tags": {"env": "sandbox"},
                "objects": ["tmp/notes.txt"],
                "leaked_credentials_for": None,
            },
        ],
        "users": [
            {
                "name": "dev-sandbox-user",
                "mfa_enabled": True,
                "access_keys": [
                    {
                        "id": "AKIADEMOACCESSKEY05",
                        "status": "Active",
                        "created": _days_ago(10),
                        "last_used": _days_ago(1),
                    }
                ],
                "attached_policies": ["ReadOnlyAnalystPolicy"],
            },
        ],
        "roles": [
            {
                "name": "SandboxExecutionRole",
                "attached_policies": ["ReadOnlyAnalystPolicy"],
                "trust_policy_services": ["ec2.amazonaws.com"],
                "trust_principals": [],
            },
        ],
        "policies": {
            "ReadOnlyAnalystPolicy": [
                ("s3:GetObject", "*"),
                ("s3:ListBucket", "*"),
            ],
        },
        "security_groups": [],
        "password_policy": dict(_STRONG_PASSWORD_POLICY),
    },
]


# --------------------------------------------------------------------------
# Seeded CloudTrail management events.
#
# These give demo mode something to attribute its findings to: who made the
# bucket public, who opened the cross-account trust, and when. Each event is
# keyed to the resources it touched, mirroring the `resources` array CloudTrail
# returns from LookupEvents.
#
# One deliberate gap: nothing here explains the stale access keys. They were
# created well over the 90-day CloudTrail retention window, so attribution
# correctly comes back UNATTRIBUTED rather than inventing a culprit -- which is
# the honest behaviour on a real account too.
# --------------------------------------------------------------------------

CLOUDTRAIL_EVENTS: List[Dict[str, Any]] = [
    {
        "account_id": PROD,
        "event_id": "9f1c0a3e-2b77-4c11-9f3a-1d2e3f4a5b6c",
        "event_name": "PutBucketAcl",
        "event_time": _days_ago(3),
        "actor_arn": f"arn:aws:iam::{PROD}:user/legacy-ci-user",
        "actor_type": "IAMUser",
        "source_ip": "203.0.113.47",
        "user_agent": "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0",
        "resources": ["public-uploads-bucket"],
        "request_parameters": {
            "bucketName": "public-uploads-bucket",
            "acl": "public-read",
        },
    },
    {
        "account_id": PROD,
        "event_id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
        "event_name": "DeleteBucketEncryption",
        "event_time": _days_ago(3),
        "actor_arn": f"arn:aws:iam::{PROD}:user/legacy-ci-user",
        "actor_type": "IAMUser",
        "source_ip": "203.0.113.47",
        "user_agent": "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0",
        "resources": ["public-uploads-bucket"],
        "request_parameters": {"bucketName": "public-uploads-bucket"},
    },
    {
        # An earlier, different actor also widened this bucket. Two candidate
        # events means attribution reports LIKELY rather than EXACT and hands
        # back both, instead of quietly picking one and sounding certain.
        "account_id": PROD,
        "event_id": "8b9c0d1e-2f3a-4b5c-6d7e-8f9012345678",
        "event_name": "PutBucketPolicy",
        "event_time": _days_ago(28),
        "actor_arn": f"arn:aws:sts::{PROD}:assumed-role/TerraformDeployRole/ci-run-7104",
        "actor_type": "AssumedRole",
        "source_ip": "198.51.100.12",
        "user_agent": "Terraform/1.9.5 (+https://www.terraform.io)",
        "resources": ["public-uploads-bucket"],
        "request_parameters": {
            "bucketName": "public-uploads-bucket",
            "policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}',
        },
    },
    {
        "account_id": PROD,
        "event_id": "2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e",
        "event_name": "AttachUserPolicy",
        "event_time": _days_ago(41),
        "actor_arn": f"arn:aws:sts::{PROD}:assumed-role/TerraformDeployRole/ci-run-8821",
        "actor_type": "AssumedRole",
        "source_ip": "198.51.100.12",
        "user_agent": "Terraform/1.9.5 (+https://www.terraform.io)",
        "resources": ["svc-deploy-bot"],
        "request_parameters": {
            "userName": "svc-deploy-bot",
            "policyArn": f"arn:aws:iam::{PROD}:policy/DeployBotPolicy",
        },
    },
    {
        "account_id": PROD,
        "event_id": "3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f",
        "event_name": "AuthorizeSecurityGroupIngress",
        "event_time": _days_ago(9),
        "actor_arn": f"arn:aws:iam::{PROD}:user/legacy-ci-user",
        "actor_type": "IAMUser",
        "source_ip": "203.0.113.47",
        "user_agent": "console.amazonaws.com",
        "resources": ["sg-0demo0webserver"],
        "request_parameters": {
            "groupId": "sg-0demo0webserver",
            "ipPermissions": [{"fromPort": 22, "toPort": 22, "cidrIp": "0.0.0.0/0"}],
        },
    },
    {
        "account_id": PROD,
        "event_id": "4d5e6f7a-8b9c-0d1e-2f3a-4b5c6d7e8f90",
        "event_name": "AttachRolePolicy",
        "event_time": _days_ago(41),
        "actor_arn": f"arn:aws:sts::{PROD}:assumed-role/TerraformDeployRole/ci-run-8821",
        "actor_type": "AssumedRole",
        "source_ip": "198.51.100.12",
        "user_agent": "Terraform/1.9.5 (+https://www.terraform.io)",
        "resources": ["LambdaExecutionAdminRole"],
        "request_parameters": {
            "roleName": "LambdaExecutionAdminRole",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    },
    {
        "account_id": SHARED,
        "event_id": "5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9012",
        "event_name": "UpdateAssumeRolePolicy",
        "event_time": _days_ago(12),
        "actor_arn": f"arn:aws:iam::{SHARED}:user/platform-admin",
        "actor_type": "IAMUser",
        "source_ip": "198.51.100.203",
        "user_agent": "console.amazonaws.com",
        "resources": ["OrgDeploymentRole"],
        "request_parameters": {
            "roleName": "OrgDeploymentRole",
            "policyDocument": (
                '{"Statement":[{"Effect":"Allow","Principal":'
                f'{{"AWS":"arn:aws:iam::{PROD}:user/svc-deploy-bot"}},'
                '"Action":"sts:AssumeRole"}]}'
            ),
        },
    },
    {
        "account_id": SHARED,
        "event_id": "6f7a8b9c-0d1e-2f3a-4b5c-6d7e8f901234",
        "event_name": "AttachRolePolicy",
        "event_time": _days_ago(12),
        "actor_arn": f"arn:aws:iam::{SHARED}:user/platform-admin",
        "actor_type": "IAMUser",
        "source_ip": "198.51.100.203",
        "user_agent": "console.amazonaws.com",
        "resources": ["OrgDeploymentRole"],
        "request_parameters": {
            "roleName": "OrgDeploymentRole",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    },
    {
        "account_id": SANDBOX,
        "event_id": "7a8b9c0d-1e2f-3a4b-5c6d-7e8f90123456",
        "event_name": "CreateBucket",
        "event_time": _days_ago(6),
        "actor_arn": f"arn:aws:iam::{SANDBOX}:user/dev-sandbox-user",
        "actor_type": "IAMUser",
        "source_ip": "192.0.2.88",
        "user_agent": "aws-cli/2.15.30",
        "resources": ["sandbox-scratch"],
        "request_parameters": {"bucketName": "sandbox-scratch"},
    },
]


ACCOUNTS_BY_ID = {a["id"]: a for a in ACCOUNTS}
PRIMARY_ACCOUNT = ACCOUNTS[0]


def account_name(account_id: str) -> str:
    """Friendly alias for an account id, for display. Falls back to the id."""
    acct = ACCOUNTS_BY_ID.get(account_id)
    return acct["name"] if acct else account_id


# Back-compat aliases: these used to be the module-level shape of the demo
# account, and are kept pointing at the primary account so anything importing
# them directly keeps working.
BUCKETS = PRIMARY_ACCOUNT["buckets"]
IAM_USERS = PRIMARY_ACCOUNT["users"]
IAM_ROLES = PRIMARY_ACCOUNT["roles"]
IAM_POLICY_DOCUMENTS = PRIMARY_ACCOUNT["policies"]
SECURITY_GROUPS = PRIMARY_ACCOUNT["security_groups"]
ACCOUNT_PASSWORD_POLICY = PRIMARY_ACCOUNT["password_policy"]
