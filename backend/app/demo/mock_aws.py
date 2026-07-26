"""
Synthetic AWS account used for demo mode.

This models a small but realistic account with an intentional, end-to-end
privilege escalation chain so CloudChain's attack-path graph has something
real to find, even with no AWS account connected:

    public-uploads-bucket (public, contains a leaked access key)
        -> svc-deploy-bot (IAM user owning that leaked key, no MFA,
           holds iam:PassRole + lambda:CreateFunction/InvokeFunction)
        -> LambdaExecutionAdminRole (role svc-deploy-bot can pass into
           a new Lambda function, then invoke)
        -> AdministratorAccess (attached to that role)

A couple of "noise" resources are included that are either clean or only
locally risky (not chained), so the risk-scoring engine has something to
rank *below* the chained findings.
"""
from datetime import datetime, timedelta, timezone

NOW = datetime.now(timezone.utc)


def _days_ago(n: int) -> str:
    return (NOW - timedelta(days=n)).isoformat()


BUCKETS = [
    {
        "name": "public-uploads-bucket",
        "public_access_block": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
        "acl_public": True,
        "policy_public": False,
        "encryption_enabled": False,
        "versioning_enabled": False,
        "tags": {"env": "prod"},
        "objects": [
            "uploads/logo.png",
            "uploads/report_q1.pdf",
            "backup/credentials.csv",  # <- leaked secret, matched by content scan
        ],
        # Demo-only correlation hint: in a real account this relationship is
        # inferred by CloudChain's object-content scan (see s3_scanner.py)
        # matching a key pattern; here we encode which identity the leaked
        # object actually belongs to so the graph engine can wire the edge.
        "leaked_credentials_for": "svc-deploy-bot",
    },
    {
        "name": "app-assets-public",
        "public_access_block": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
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
        "public_access_block": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "acl_public": False,
        "policy_public": False,
        "encryption_enabled": True,
        "versioning_enabled": True,
        "tags": {"env": "prod", "sensitivity": "high"},
        "objects": ["warehouse/customers.parquet"],
        "leaked_credentials_for": None,
    },
]

IAM_USERS = [
    {
        "name": "svc-deploy-bot",
        "mfa_enabled": False,
        "access_keys": [
            {"id": "AKIADEMOACCESSKEY01", "status": "Active", "created": _days_ago(410), "last_used": _days_ago(1)},
        ],
        "attached_policies": ["DeployBotPolicy"],
    },
    {
        "name": "read-only-analyst",
        "mfa_enabled": True,
        "access_keys": [
            {"id": "AKIADEMOACCESSKEY02", "status": "Active", "created": _days_ago(20), "last_used": _days_ago(1)},
        ],
        "attached_policies": ["ReadOnlyAnalystPolicy"],
    },
    {
        "name": "legacy-ci-user",
        "mfa_enabled": False,
        "access_keys": [
            {"id": "AKIADEMOACCESSKEY03", "status": "Active", "created": _days_ago(730), "last_used": _days_ago(400)},
        ],
        "attached_policies": ["ReadOnlyAnalystPolicy"],
    },
]

IAM_ROLES = [
    {
        "name": "LambdaExecutionAdminRole",
        "attached_policies": ["AdministratorAccess"],
        "trust_policy_services": ["lambda.amazonaws.com"],
    },
    {
        "name": "ReadOnlyServiceRole",
        "attached_policies": ["ReadOnlyAnalystPolicy"],
        "trust_policy_services": ["ec2.amazonaws.com"],
    },
]

# Simplified policy documents: each maps a policy name to the set of
# (action, resource) pairs it grants. "*" means wildcard.
IAM_POLICY_DOCUMENTS = {
    "DeployBotPolicy": [
        ("iam:PassRole", "arn:aws:iam::123456789012:role/LambdaExecutionAdminRole"),
        ("lambda:CreateFunction", "*"),
        ("lambda:InvokeFunction", "*"),
    ],
    "ReadOnlyAnalystPolicy": [
        ("s3:GetObject", "*"),
        ("s3:ListBucket", "*"),
    ],
    "AdministratorAccess": [
        ("*", "*"),
    ],
}

SECURITY_GROUPS = [
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
]

ACCOUNT_PASSWORD_POLICY = {
    "minimum_password_length": 8,
    "require_symbols": False,
    "require_numbers": True,
    "require_uppercase": True,
    "require_lowercase": True,
}
