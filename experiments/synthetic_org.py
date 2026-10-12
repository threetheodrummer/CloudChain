"""
Seeded synthetic AWS organisations for offline experiments.

Generates a multi-account estate with a realistic mix of identities: mostly
benign, a few admins, some with escalation primitives, some with PassRole into
other roles, cross-account trust between accounts, and public buckets that leak
a user's credentials. Everything is deterministic for a given seed, so every
number in the paper can be regenerated exactly.

Used by benchmark_scalability.py and sensitivity.py. Not used by the product.
"""
from __future__ import annotations

import random
from typing import Dict, List, Tuple

from app.sources import AWSDataSource

ESCALATION = [
    "iam:CreatePolicyVersion", "iam:AttachUserPolicy", "iam:PutUserPolicy",
    "iam:AttachRolePolicy", "iam:CreateAccessKey", "iam:UpdateAssumeRolePolicy",
]
BENIGN = [("s3:GetObject", "*"), ("dynamodb:Query", "*"), ("logs:PutLogEvents", "*"), ("sqs:SendMessage", "*")]


class SyntheticAccount(AWSDataSource):
    def __init__(self, account_id: str, rng: random.Random, n_identities: int, peers: List[str]):
        self.account_id = account_id
        self.account_name = f"acct-{account_id[-4:]}"
        n_users = max(2, int(n_identities * 0.6))
        n_roles = max(2, n_identities - n_users)
        self.users = [f"user{i}" for i in range(n_users)]
        self.roles = [f"role{i}" for i in range(n_roles)]
        self.user_policies: Dict[str, List[Tuple[str, str]]] = {}
        self.role_policies: Dict[str, List[Tuple[str, str]]] = {}
        self.trust: Dict[str, List[str]] = {}
        self.mfa = {u: rng.random() < 0.5 for u in self.users}

        admin_roles = [r for r in self.roles if rng.random() < 0.10] or [self.roles[0]]
        for r in self.roles:
            self.role_policies[r] = [("*", "*")] if r in admin_roles else [rng.choice(BENIGN)]
            # Some roles trust a principal in another account.
            if peers and rng.random() < 0.15:
                peer = rng.choice(peers)
                kind = rng.choice(["user", "role"])
                idx = rng.randrange(max(2, int(n_identities * (0.6 if kind == "user" else 0.4))))
                self.trust[r] = [f"arn:aws:iam::{peer}:{kind}/{kind}{idx}"]
            else:
                self.trust[r] = []

        for u in self.users:
            x = rng.random()
            if x < 0.05:
                pol = [("*", "*")]
            elif x < 0.15:
                pol = [(rng.choice(ESCALATION), "*")]
            elif x < 0.25:
                target = rng.choice(self.roles)
                pol = [("iam:PassRole", f"arn:aws:iam::{account_id}:role/{target}"),
                       ("lambda:CreateFunction", "*"), ("lambda:InvokeFunction", "*")]
            elif x < 0.30:
                pol = [("iam:PassRole", "*"), ("ec2:RunInstances", "*")]
            else:
                pol = [rng.choice(BENIGN)]
            self.user_policies[u] = pol

        n_buckets = max(1, n_identities // 10)
        self.buckets = {}
        for i in range(n_buckets):
            public = rng.random() < 0.2
            leaks = public and rng.random() < 0.5
            self.buckets[f"bucket{i}-{account_id[-4:]}"] = {
                "public": public,
                "objects": ["backup/credentials.csv"] if leaks else ["index.html"],
                "hint": rng.choice(self.users) if leaks else None,
            }

    # --- S3 ---
    def list_buckets(self): return list(self.buckets)
    def get_public_access_block(self, b): return {}
    def is_bucket_acl_public(self, b): return self.buckets[b]["public"]
    def is_bucket_policy_public(self, b): return False
    def is_bucket_encrypted(self, b): return True
    def is_bucket_versioned(self, b): return True
    def list_object_keys(self, b, limit=1000): return self.buckets[b]["objects"]
    def leaked_credentials_hint(self, b): return self.buckets[b]["hint"]

    # --- IAM ---
    def list_iam_users(self): return list(self.users)
    def user_has_mfa(self, u): return self.mfa[u]
    def list_access_keys(self, u): return []
    def list_user_policy_names(self, u): return []
    def list_iam_roles(self): return list(self.roles)
    def list_role_policy_names(self, r): return []
    def list_role_trust_principals(self, r): return self.trust.get(r, [])
    def get_policy_statements(self, n): return []

    def get_identity_policy_statements(self, identity_type, name):
        return (self.user_policies if identity_type == "user" else self.role_policies).get(name, [])

    def get_account_password_policy(self):
        return {"MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
                "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True}

    def list_security_groups(self): return []
    def lookup_events(self, *a, **k): return []


def make_org(n_identities: int, n_accounts: int = 3, seed: int = 0) -> List[SyntheticAccount]:
    """n_identities is the total across the organisation."""
    rng = random.Random(seed)
    ids = [f"{100000000000 + i * 111111111111 % 900000000000:012d}" for i in range(n_accounts)]
    per = max(4, n_identities // n_accounts)
    return [SyntheticAccount(a, rng, per, [p for p in ids if p != a]) for a in ids]
