"""
IAM policy semantics: does this policy actually grant that action?

CloudChain originally compared actions as exact strings -- `"iam:PassRole" in
actions`, `("*", "*") in statements`. That works on hand-written demo data and
fails completely on real accounts, because real policies are written with
wildcards. Scanning thirteen deliberately vulnerable AWS accounts produced
*zero* privilege-escalation findings for exactly this reason: a role granting
`iam:*` is an administrator in all but name, and an exact-match check sees
nothing at all.

This module implements the small part of IAM's evaluation model CloudChain
needs: wildcard action matching, admin equivalence, and the well-known
self-escalation primitives.

What it deliberately does NOT model: explicit Deny, SCPs, permission
boundaries, and condition keys. All four can make a grant that looks live
actually unusable. That's why a finding raised here is a *claim*, and why the
validation engine exists to re-check it against the account rather than
trusting this analysis. Overstating certainty is the failure mode that makes
people distrust CSPM output.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Dict, Iterable, List, Sequence, Tuple

Statement = Tuple[str, str]


@lru_cache(maxsize=512)
def _pattern(granted: str) -> re.Pattern:
    """An IAM action pattern as a regex.

    IAM supports `*` (any sequence) and `?` (any single character), and action
    matching is case-insensitive.
    """
    escaped = re.escape(granted).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def action_matches(granted: str, wanted: str) -> bool:
    """Does a granted action pattern cover a specific action?

    `iam:*` covers `iam:PassRole`; `iam:Pass*` does too; `*` covers everything.
    """
    if not granted:
        return False
    return bool(_pattern(granted).match(wanted))


def grants(statements: Sequence[Statement], wanted: str) -> bool:
    """Is `wanted` granted by any statement, regardless of resource?"""
    return any(action_matches(action, wanted) for action, _ in statements)


def granted_resources(statements: Sequence[Statement], wanted: str) -> List[str]:
    """Every resource an action is granted on, following wildcards."""
    return [resource for action, resource in statements if action_matches(action, wanted)]


def is_full_admin(statements: Sequence[Statement]) -> bool:
    """A statement allowing every action on every resource.

    Deliberately strict: the action pattern must cover an arbitrary action, not
    merely one service. `s3:*` on `*` is dangerous but is not administrator.
    """
    return any(
        resource == "*" and action_matches(action, "cloudchain:ArbitraryProbeAction")
        for action, resource in statements
    )


def is_admin_equivalent(statements: Sequence[Statement]) -> bool:
    """Admin, or able to make itself admin in one step.

    Full control of IAM is administrator access with an extra API call: attach
    AdministratorAccess to yourself and the distinction disappears. Treating
    `iam:*` as merely "some IAM permissions" is how an overpowered role hides
    from a scanner.
    """
    if is_full_admin(statements):
        return True
    return any(
        resource == "*" and action_matches(action, "iam:ArbitraryProbeAction")
        for action, resource in statements
    )


# Actions that let an identity grant itself (or someone it controls) more
# privilege. Drawn from the widely documented AWS privilege-escalation paths;
# each one alone is enough to reach administrator given a little patience.
ESCALATION_PRIMITIVES: Dict[str, str] = {
    "iam:CreatePolicyVersion": "can publish a new default version of an existing policy, granting itself anything",
    "iam:SetDefaultPolicyVersion": "can roll a policy back to a more permissive existing version",
    "iam:AttachUserPolicy": "can attach AdministratorAccess to a user",
    "iam:AttachRolePolicy": "can attach AdministratorAccess to a role",
    "iam:AttachGroupPolicy": "can attach AdministratorAccess to a group it belongs to",
    "iam:PutUserPolicy": "can write an inline policy granting itself anything",
    "iam:PutRolePolicy": "can write an inline policy onto a role it can assume",
    "iam:PutGroupPolicy": "can write an inline policy onto its own group",
    "iam:CreateAccessKey": "can mint credentials for a more privileged user",
    "iam:CreateLoginProfile": "can set a console password on a more privileged user",
    "iam:UpdateLoginProfile": "can reset a more privileged user's console password",
    "iam:UpdateAssumeRolePolicy": "can rewrite a role's trust policy to make it assumable",
    "iam:AddUserToGroup": "can add itself to a more privileged group",
}


def find_escalation_primitives(statements: Sequence[Statement]) -> List[Tuple[str, str]]:
    """Which self-escalation actions this policy grants, and why each matters."""
    found: List[Tuple[str, str]] = []
    for action, description in ESCALATION_PRIMITIVES.items():
        if grants(statements, action):
            found.append((action, description))
    return found


def summarise_actions(statements: Iterable[Statement], limit: int = 6) -> List[str]:
    """A short, stable sample of granted action patterns, for evidence."""
    seen: List[str] = []
    for action, _ in statements:
        if action not in seen:
            seen.append(action)
        if len(seen) >= limit:
            break
    return seen
