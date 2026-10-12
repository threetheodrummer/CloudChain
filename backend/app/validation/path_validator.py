"""
Attack path validation -- re-checking a reported chain against the account.

This is the part commercial CSPMs don't do. Wiz, Orca and Prisma Cloud all
derive attack paths from configuration analysis and present them as fact. The
path is a *model output*, not an observation, and security teams know it: a
large share of reported paths turn out to be blocked by an SCP, a permission
boundary, or a resource policy the analyser never read. The result is that
teams stop trusting path findings entirely.

CloudChain treats a reported path as a claim to be re-tested. For each hop it
issues read-only API calls, records what came back, and marks the hop:

    CONFIRMED     an API response proves the hop's precondition still holds
    REFUTED       an API response contradicts it -- the path is stale
    UNVERIFIABLE  the API didn't return enough to decide (usually AccessDenied
                  in real mode, or a policy that can't be resolved by name)

Two things this deliberately does NOT do, and the reason each matters:

1. It never performs the escalation. Verifying "this identity can pass an
   admin role into a new Lambda" means confirming the *grant* exists via
   iam:GetPolicyVersion -- not creating a function. A security tool that
   exploits the account it is auditing is not a security tool.

2. It never reads object contents. The S3 hop confirms a bucket is public and
   that a credential-shaped key is listable. It does not GetObject. Whether
   that file really contains live credentials is not something a scanner
   should determine by reading it.

So a CONFIRMED verdict means "every precondition for this chain is verifiable
right now", not "we ran it". That's a weaker claim than exploitation and a much
stronger one than configuration inference, and every hop ships the API calls
behind it so the reader can check the work.

Safety is structural rather than by convention: validation is written against
AWSDataSource, whose entire surface is read-only. READ_ONLY_METHODS below is
asserted against that interface in tests, so adding a mutating method to the
data source breaks the build.
"""
from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from app.graph.attack_graph import is_admin_sink, parse_node
from app.models import (
    AttackPath,
    EvidenceCall,
    HopVerification,
    PathValidation,
    ScanGraph,
    VerdictStatus,
)
from app.scanners import policy
from app.scanners.iam_scanner import COMPUTE_CREATE_ACTIONS, _extract_role_name
from app.scanners.s3_scanner import CREDENTIAL_KEY_PATTERNS
from app.sources import AWSDataSource

# The complete set of data-source methods validation is permitted to call.
# Every one is a read. Tests assert this list against the AWSDataSource
# interface so a mutating method can never quietly become reachable from here.
READ_ONLY_METHODS = frozenset(
    {
        "get_public_access_block",
        "is_bucket_acl_public",
        "is_bucket_policy_public",
        "list_object_keys",
        "list_user_policy_names",
        "list_role_policy_names",
        "list_role_trust_principals",
        "get_policy_statements",
        "get_identity_policy_statements",
        "list_access_keys",
        "principal_arn",
        "simulate_principal_policy",
    }
)


def _split_node(node: str) -> Tuple[str, str]:
    """('s3_bucket', 'my-bucket'), dropping the account namespace."""
    _, kind, name = parse_node(node)
    return kind, name


def _statements(source: AWSDataSource, policy_names: Sequence[str]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for name in policy_names:
        pairs.extend(source.get_policy_statements(name))
    return pairs


def _identity_statements(source: AWSDataSource, kind: str, name: str) -> List[Tuple[str, str]]:
    """Everything a user or role is granted: attached AWS-managed,
    customer-managed and inline policies.

    Validation used to resolve policies by *name* only, which on a real account
    sees AWS-managed policies and nothing else. The scanner already used the
    full resolution, so a path the scanner found from an inline policy came
    back UNVERIFIABLE (or worse, REFUTED) here. Both now read the same thing.
    """
    return source.get_identity_policy_statements("user" if kind == "iam_user" else "role", name)


def _identity_type(kind: str) -> str:
    return "user" if kind == "iam_user" else "role"


def _role_matches(pattern: str, role: str) -> bool:
    """Does a PassRole resource pattern cover this role name?

    Patterns are ARNs with optional wildcards and an optional path, e.g.
    arn:aws:iam::111111111111:role/service-role/Lambda*. Only the part after
    the last '/' names the role; wildcards in it are honoured.
    """
    if pattern == "*":
        return True
    tail = _extract_role_name(pattern)
    return fnmatchcase(role, tail) or pattern == role


# --------------------------------------------------------------------------
# AWS policy simulator -- a second opinion from AWS itself
# --------------------------------------------------------------------------


def _simulate(
    source: AWSDataSource,
    kind: str,
    name: str,
    actions: Sequence[str],
    resource_arns: Optional[Sequence[str]] = None,
    need: str = "all",
) -> Tuple[Optional[VerdictStatus], Optional[str], Optional[EvidenceCall]]:
    """Ask iam:SimulatePrincipalPolicy whether the hop's actions are allowed.

    CloudChain's static analysis does not model explicit Deny, permissions
    boundaries, SCPs or conditions. The simulator does. So after a static check
    confirms a hop, this can overturn it: if AWS says the needed actions are
    denied, the hop is REFUTED and the reason says which layer blocked it.

    need="all": every action must be allowed. need="any": at least one.

    Returns (override, reason, evidence). override is None when the simulator
    agrees, isn't available (demo, Terraform plan), or can't decide because a
    condition needs request context it doesn't have. Missing information never
    becomes a verdict.
    """
    arn = source.principal_arn(_identity_type(kind), name)
    if not arn:
        return None, None, None

    resources = list(resource_arns or ["*"])
    cli = (
        f"aws iam simulate-principal-policy --policy-source-arn {arn} "
        f"--action-names {' '.join(actions)} --resource-arns {' '.join(resources)}"
    )
    results = source.simulate_principal_policy(arn, actions, resources)
    if results is None:
        return None, None, EvidenceCall(
            api="iam:SimulatePrincipalPolicy",
            request=f"PolicySourceArn={arn}",
            observed="simulator unavailable (no permission, or call failed); static verdict kept",
            cli=cli,
        )

    def describe(action: str, r: Dict[str, Any]) -> str:
        bits = [r.get("decision") or "unknown"]
        if r.get("allowed_by_boundary") is False:
            bits.append("blocked by permissions boundary")
        if r.get("allowed_by_organizations") is False:
            bits.append("blocked by SCP")
        if r.get("missing_context"):
            bits.append("needs context: " + ", ".join(r["missing_context"]))
        return f"{action}: {'; '.join(bits)}"

    observed = "; ".join(describe(a, results.get(a, {})) for a in actions)
    evidence = EvidenceCall(
        api="iam:SimulatePrincipalPolicy",
        request=f"PolicySourceArn={arn}, ResourceArns={', '.join(resources)}",
        observed=observed,
        cli=cli,
    )

    allowed = [a for a in actions if results.get(a, {}).get("decision") == "allowed"]
    undecidable = [
        a for a in actions
        if a not in allowed and results.get(a, {}).get("missing_context")
    ]
    denied = [a for a in actions if a not in allowed and a not in undecidable]

    satisfied = (len(allowed) == len(actions)) if need == "all" else bool(allowed)
    if satisfied:
        return None, None, evidence
    if undecidable:
        # A condition key the simulator had no value for. That is "we don't
        # know", not "denied".
        return VerdictStatus.UNVERIFIABLE, (
            f"AWS's policy simulator could not decide {', '.join(undecidable)} for '{name}' "
            f"without request context ({', '.join(results[undecidable[0]]['missing_context'])})."
        ), evidence

    blockers = []
    for a in denied:
        r = results.get(a, {})
        if r.get("allowed_by_organizations") is False:
            blockers.append("a service control policy")
        if r.get("allowed_by_boundary") is False:
            blockers.append("a permissions boundary")
        if r.get("decision") == "explicitDeny":
            blockers.append("an explicit Deny")
    why = f" ({', '.join(sorted(set(blockers)))})" if blockers else ""
    return VerdictStatus.REFUTED, (
        f"The policy grants it on paper, but AWS's policy simulator denies "
        f"{', '.join(denied)} for '{name}'{why}. The hop cannot be walked."
    ), evidence


def _apply_simulation(
    verdict: Tuple[VerdictStatus, str, List[EvidenceCall]],
    simulation: Tuple[Optional[VerdictStatus], Optional[str], Optional[EvidenceCall]],
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """Fold a simulator result into a static verdict. Only a CONFIRMED static
    verdict can be overturned; a static REFUTED or UNVERIFIABLE stands."""
    status, reason, calls = verdict
    override, sim_reason, evidence = simulation
    if evidence is not None:
        calls = calls + [evidence]
    if status is VerdictStatus.CONFIRMED and override is not None:
        return override, sim_reason or reason, calls
    if status is VerdictStatus.CONFIRMED and evidence is not None and override is None and \
            "unavailable" not in evidence.observed:
        reason = reason + " AWS's policy simulator agrees."
    return status, reason, calls


def _ask_simulator_when_blind(
    source: AWSDataSource,
    kind: str,
    name: str,
    actions: Sequence[str],
    calls: List[EvidenceCall],
    resource_arns: Optional[Sequence[str]] = None,
    need: str = "any",
) -> Optional[Tuple[VerdictStatus, str, List[EvidenceCall]]]:
    """Settle a hop the static reader can't, by asking AWS directly.

    An identity whose policies come back empty is ambiguous: it may have none
    (the permission was removed, so the hop is REFUTED), the read may have been
    denied, or the grant may come from somewhere the static reader doesn't look,
    such as an IAM group. Only the policy simulator can tell these apart.

    Returns a verdict, or None when the simulator isn't available, in which
    case the caller keeps its UNVERIFIABLE answer.
    """
    arn = source.principal_arn(_identity_type(kind), name)
    if not arn:
        return None
    resources = list(resource_arns or ["*"])
    results = source.simulate_principal_policy(arn, actions, resources)
    if results is None:
        return None

    allowed = [a for a in actions if results.get(a, {}).get("decision") == "allowed"]
    undecidable = [
        a for a in actions if a not in allowed and results.get(a, {}).get("missing_context")
    ]
    evidence = EvidenceCall(
        api="iam:SimulatePrincipalPolicy",
        request=f"PolicySourceArn={arn}, ResourceArns={', '.join(resources)}",
        observed="; ".join(f"{a}: {results.get(a, {}).get('decision', 'unknown')}" for a in actions),
        cli=(
            f"aws iam simulate-principal-policy --policy-source-arn {arn} "
            f"--action-names {' '.join(actions)} --resource-arns {' '.join(resources)}"
        ),
    )
    calls = calls + [evidence]

    satisfied = (len(allowed) == len(actions)) if need == "all" else bool(allowed)
    if satisfied:
        return (
            VerdictStatus.CONFIRMED,
            f"No grant was visible in '{name}''s own policies, but AWS's policy simulator "
            f"allows {', '.join(allowed)}, so the permission comes from somewhere else "
            f"(for example an IAM group). The hop still holds.",
            calls,
        )
    if undecidable:
        return (
            VerdictStatus.UNVERIFIABLE,
            f"AWS's policy simulator could not decide {', '.join(undecidable)} for '{name}' "
            f"without request context.",
            calls,
        )
    return (
        VerdictStatus.REFUTED,
        f"'{name}' no longer has any policy granting {', '.join(actions) if len(actions) <= 3 else 'the required actions'}; "
        f"AWS's policy simulator confirms they are denied. The hop cannot be walked.",
        calls,
    )


# --------------------------------------------------------------------------
# Hop verifiers -- one per relation the graph engine can emit
# --------------------------------------------------------------------------


def _verify_leaked_credentials(
    source: AWSDataSource, bucket: str, user: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """Bucket -> IAM user: a public object with a credential-shaped key."""
    calls: List[EvidenceCall] = []

    pab = source.get_public_access_block(bucket)
    blocking = bool(pab.get("BlockPublicAcls") or pab.get("RestrictPublicBuckets"))
    calls.append(
        EvidenceCall(
            api="s3:GetPublicAccessBlock",
            request=f"Bucket={bucket}",
            observed=f"BlockPublicAcls={pab.get('BlockPublicAcls')}, "
            f"RestrictPublicBuckets={pab.get('RestrictPublicBuckets')}",
            cli=f"aws s3api get-public-access-block --bucket {bucket}",
        )
    )

    acl_public = source.is_bucket_acl_public(bucket)
    calls.append(
        EvidenceCall(
            api="s3:GetBucketAcl",
            request=f"Bucket={bucket}",
            observed="AllUsers/AuthenticatedUsers grant present" if acl_public else "no public grant",
            cli=f"aws s3api get-bucket-acl --bucket {bucket}",
        )
    )

    policy_public = source.is_bucket_policy_public(bucket)
    calls.append(
        EvidenceCall(
            api="s3:GetBucketPolicyStatus",
            request=f"Bucket={bucket}",
            observed='policy allows Principal "*"' if policy_public else "no public policy statement",
            cli=f"aws s3api get-bucket-policy-status --bucket {bucket}",
        )
    )

    keys = source.list_object_keys(bucket, limit=1000)
    matched = [k for k in keys if any(p.search(k) for p in CREDENTIAL_KEY_PATTERNS)]
    calls.append(
        EvidenceCall(
            api="s3:ListObjectsV2",
            request=f"Bucket={bucket}",
            observed=(
                f"{len(keys)} object(s); {len(matched)} credential-shaped key(s): "
                f"{', '.join(matched) if matched else 'none'}"
            ),
            cli=f"aws s3api list-objects-v2 --bucket {bucket} --query 'Contents[].Key'",
        )
    )

    public = (acl_public or policy_public) and not blocking

    if not public:
        return (
            VerdictStatus.REFUTED,
            f"Bucket '{bucket}' is not publicly readable any more, so this hop no longer holds.",
            calls,
        )
    if not matched:
        return (
            VerdictStatus.REFUTED,
            f"Bucket '{bucket}' is public but contains no credential-shaped object key.",
            calls,
        )

    # A leaked key only matters while it still works. If every access key the
    # user has is deactivated, the leak is real but the hop is closed.
    keys = source.list_access_keys(user)
    active = [k for k in keys if str(k.get("status", "")).lower() == "active"]
    calls.append(
        EvidenceCall(
            api="iam:ListAccessKeys",
            request=f"UserName={user}",
            observed=(
                f"{len(keys)} access key(s), {len(active)} active"
                if keys else "no access keys visible"
            ),
            cli=f"aws iam list-access-keys --user-name {user}",
        )
    )
    if keys and not active:
        return (
            VerdictStatus.REFUTED,
            f"Every access key belonging to '{user}' is inactive, so a leaked key can no "
            f"longer be used.",
            calls,
        )
    if not keys:
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Bucket '{bucket}' still exposes credential-shaped keys, but no access keys "
            f"are visible for '{user}' (none exist, or ListAccessKeys was denied), so "
            f"whether the leak is still usable could not be checked.",
            calls,
        )

    return (
        VerdictStatus.CONFIRMED,
        (
            f"Bucket '{bucket}' is publicly readable and exposes {len(matched)} "
            f"credential-shaped key ({', '.join(matched)}), which the graph attributes "
            f"to '{user}', who still has {len(active)} active access key(s). Object "
            f"contents were not read during validation."
        ),
        calls,
    )


def _verify_pass_role(
    source: AWSDataSource, src_node: str, role: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """User or role -> IAM role: PassRole plus a compute-creation action.

    Uses the same wildcard-aware matching as the scanner. Comparing action
    strings exactly meant a principal granted iam:* or iam:Pass* came back as
    "no longer holds iam:PassRole" -- a false REFUTED on exactly the
    over-broad grants that matter most.
    """
    account, kind, name = parse_node(src_node)
    calls: List[EvidenceCall] = []

    statements = _identity_statements(source, kind, name)
    list_api = "iam:ListAttachedUserPolicies" if kind == "iam_user" else "iam:ListAttachedRolePolicies"
    list_cli = (
        f"aws iam list-attached-user-policies --user-name {name}"
        if kind == "iam_user"
        else f"aws iam list-attached-role-policies --role-name {name}"
    )
    calls.append(
        EvidenceCall(
            api=list_api,
            request=f"name={name}",
            observed=f"{len(statements)} allow statement(s) across attached and inline policies",
            cli=list_cli + "  # plus list-*-policies for inline policies",
        )
    )

    if not statements:
        role_arn = source.principal_arn("role", role)
        settled = _ask_simulator_when_blind(
            source, kind, name, ["iam:PassRole"], calls, [role_arn] if role_arn else None
        )
        if settled is not None and settled[0] is VerdictStatus.CONFIRMED:
            compute_check = _ask_simulator_when_blind(
                source, kind, name, sorted(COMPUTE_CREATE_ACTIONS), settled[2]
            )
            if compute_check is not None:
                return compute_check
        if settled is not None:
            return settled
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Could not resolve the policy documents attached to '{name}', so the "
            f"PassRole grant could not be re-checked.",
            calls,
        )

    pass_targets = policy.granted_resources(statements, "iam:PassRole")
    compute = sorted(a for a in COMPUTE_CREATE_ACTIONS if policy.grants(statements, a))

    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"identity={name}",
            observed=(
                f"iam:PassRole -> {', '.join(pass_targets) if pass_targets else 'not granted'}; "
                f"compute actions: {', '.join(compute) if compute else 'none'}"
            ),
            cli="aws iam get-policy-version --policy-arn <arn> --version-id <v>",
        )
    )

    if not pass_targets:
        return (VerdictStatus.REFUTED, f"'{name}' no longer holds iam:PassRole.", calls)
    if not compute:
        return (
            VerdictStatus.REFUTED,
            f"'{name}' holds iam:PassRole but no compute-creation action, so it cannot "
            f"launch anything to run as '{role}'.",
            calls,
        )
    if not any(_role_matches(t, role) for t in pass_targets):
        return (
            VerdictStatus.REFUTED,
            f"'{name}' can pass roles, but '{role}' is not among the permitted targets "
            f"({', '.join(pass_targets)}).",
            calls,
        )

    wildcard = any(t == "*" for t in pass_targets)
    static = (
        VerdictStatus.CONFIRMED,
        (
            f"'{name}' holds iam:PassRole ({'unscoped' if wildcard else 'covering ' + role}) "
            f"together with {', '.join(compute)}. The grant was verified; no function or "
            f"instance was created."
        ),
        calls,
    )

    role_arn = source.principal_arn("role", role)
    pass_check = _simulate(source, kind, name, ["iam:PassRole"], [role_arn] if role_arn else None)
    verdict = _apply_simulation(static, pass_check)
    if verdict[0] is not VerdictStatus.CONFIRMED:
        return verdict
    return _apply_simulation(verdict, _simulate(source, kind, name, compute, need="any"))


def _verify_self_escalation(
    source: AWSDataSource, node: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """Identity -> AdministratorAccess via IAM write permissions.

    The graph emits can_escalate_to_admin for identities that can grant
    themselves admin (attach a policy, publish a policy version, ...). There
    was previously no verifier for it, so every escalation route came back
    UNVERIFIABLE regardless of the account's actual state.
    """
    _, kind, name = parse_node(node)
    calls: List[EvidenceCall] = []
    statements = _identity_statements(source, kind, name)
    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"identity={name}",
            observed=f"{len(statements)} allow statement(s) across attached and inline policies",
            cli=(
                f"aws iam list-attached-{'user' if kind == 'iam_user' else 'role'}-policies "
                f"--{'user' if kind == 'iam_user' else 'role'}-name {name}"
            ),
        )
    )
    if not statements:
        settled = _ask_simulator_when_blind(
            source, kind, name, sorted(policy.ESCALATION_PRIMITIVES), calls
        )
        if settled is not None:
            return settled
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Could not resolve the policy documents attached to '{name}'.",
            calls,
        )

    primitives = [a for a, _ in policy.find_escalation_primitives(statements)]
    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"identity={name}",
            observed=(
                "escalation primitives granted: " + ", ".join(primitives)
                if primitives else "no self-escalation primitive granted"
            ),
            cli="aws iam get-policy-version --policy-arn <arn> --version-id <v>",
        )
    )
    if not primitives:
        # The identity's own policies no longer grant it, but a group might.
        settled = _ask_simulator_when_blind(
            source, kind, name, sorted(policy.ESCALATION_PRIMITIVES), calls
        )
        if settled is not None and settled[0] is VerdictStatus.CONFIRMED:
            return settled
        return (
            VerdictStatus.REFUTED,
            f"'{name}' no longer holds any IAM write permission that would let it grant "
            f"itself administrator access.",
            settled[2] if settled is not None else calls,
        )

    static = (
        VerdictStatus.CONFIRMED,
        f"'{name}' holds {', '.join(primitives)}, any one of which lets it grant itself "
        f"AdministratorAccess. The grant was verified; nothing was attached or changed.",
        calls,
    )
    return _apply_simulation(static, _simulate(source, kind, name, primitives, need="any"))


def _verify_cross_account_trust(
    source: AWSDataSource, principal_node: str, role_node: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """External principal -> role: the role's trust policy still names it.

    `source` must be the account that *owns the role*, since the trust policy
    is a property of the role, not of the principal being trusted.
    """
    src_account, src_kind, src_name = parse_node(principal_node)
    role_account, _, role = parse_node(role_node)
    calls: List[EvidenceCall] = []

    principals = source.list_role_trust_principals(role)
    calls.append(
        EvidenceCall(
            api="iam:GetRole",
            request=f"RoleName={role}",
            observed=(
                f"AssumeRolePolicyDocument trusts: "
                f"{', '.join(principals) if principals else 'no IAM principals'}"
            ),
            cli=f"aws iam get-role --role-name {role} "
            f"--query 'Role.AssumeRolePolicyDocument'",
        )
    )

    if not principals:
        return (
            VerdictStatus.REFUTED,
            f"Role '{role}' in {role_account} no longer trusts any external IAM principal.",
            calls,
        )

    expected = f":{'user' if src_kind == 'iam_user' else 'role'}/{src_name}"
    matched = [p for p in principals if p.endswith(expected) and src_account in p]

    if not matched:
        return (
            VerdictStatus.REFUTED,
            f"Role '{role}' in {role_account} is still assumable, but no longer by "
            f"'{src_name}' in {src_account}.",
            calls,
        )

    return (
        VerdictStatus.CONFIRMED,
        (
            f"The trust policy on '{role}' in account {role_account} explicitly names "
            f"{matched[0]}, so compromising '{src_name}' in account {src_account} crosses "
            f"the boundary via sts:AssumeRole. No role was assumed."
        ),
        calls,
    )


def _verify_admin_grant(
    source: AWSDataSource, node: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """Role or user -> AdministratorAccess.

    Uses the scanner's own definition of admin (policy.is_admin_equivalent:
    *:* on *, or iam:* on *), so a path the scanner drew is checked against the
    same rule rather than a stricter one that would refute it on sight.
    """
    _, kind, name = parse_node(node)
    calls: List[EvidenceCall] = []

    statements = _identity_statements(source, kind, name)
    if kind == "iam_role":
        api, cli = "iam:ListAttachedRolePolicies", f"aws iam list-attached-role-policies --role-name {name}"
    else:
        api, cli = "iam:ListAttachedUserPolicies", f"aws iam list-attached-user-policies --user-name {name}"

    calls.append(
        EvidenceCall(
            api=api,
            request=f"name={name}",
            observed=f"{len(statements)} allow statement(s) across attached and inline policies",
            cli=cli,
        )
    )

    if not statements:
        settled = _ask_simulator_when_blind(
            source, kind, name, ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion"], calls
        )
        if settled is not None:
            return settled
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Could not resolve the policy documents attached to '{name}'.",
            calls,
        )

    full = policy.is_full_admin(statements)
    equivalent = policy.is_admin_equivalent(statements)
    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"identity={name}",
            observed=(
                "unrestricted statement (every action on every resource)" if full
                else "full IAM control on * (admin-equivalent)" if equivalent
                else "no unrestricted or full-IAM statement"
            ),
            cli="aws iam get-policy-version --policy-arn <arn> --version-id <v>",
        )
    )

    if not equivalent:
        return (
            VerdictStatus.REFUTED,
            f"'{name}' no longer carries an unrestricted (*:*) or full-IAM policy.",
            calls,
        )

    static = (
        VerdictStatus.CONFIRMED,
        (
            f"'{name}' carries an unrestricted statement, which is AdministratorAccess in effect."
            if full
            else f"'{name}' holds full control of IAM on every resource, which is one "
            f"API call away from AdministratorAccess."
        ),
        calls,
    )
    # Probe actions any administrator (or IAM-admin) can perform.
    probes = ["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion"]
    return _apply_simulation(static, _simulate(source, kind, name, probes, need="any"))


# --------------------------------------------------------------------------
# Path-level driver
# --------------------------------------------------------------------------

_CLAIMS = {
    "leaks_credentials_for": "A publicly readable object in {src} leaks credentials for {tgt}",
    "can_pass_role_to": "{src} can pass the role {tgt} into new compute and run code as it",
    "can_pass_role_to (wildcard)": "{src} holds unscoped iam:PassRole and can pass any role, including {tgt}",
    "can_assume_cross_account": "{src} is named in the trust policy of {tgt} and can cross the account boundary",
    "can_escalate_to_admin": "{src} can grant itself AdministratorAccess through IAM write permissions",
    "grants_admin_access": "{src} is granted AdministratorAccess",
    "has_admin_policy": "{src} directly holds an unrestricted (*:*) policy",
}


def _relation_map(graph: Optional[ScanGraph]) -> Dict[Tuple[str, str], str]:
    if graph is None:
        return {}
    return {(e.source, e.target): e.relation for e in graph.edges}


Sources = Union[AWSDataSource, Mapping[str, AWSDataSource], Sequence[AWSDataSource]]


def _index_sources(sources: Sources) -> Tuple[Dict[str, AWSDataSource], Optional[AWSDataSource]]:
    """Normalise however the caller supplied sources into {account_id: source}.

    A cross-account path can only be verified if each hop is checked against
    the account that actually owns the resource -- a trust policy lives with
    the role, not with the principal being trusted.
    """
    if isinstance(sources, Mapping):
        by_account = dict(sources)
    elif isinstance(sources, AWSDataSource):
        by_account = {sources.account_id: sources}
    else:
        by_account = {s.account_id: s for s in sources}

    default = next(iter(by_account.values()), None)
    return by_account, default


def validate_path(
    path: AttackPath,
    sources: Sources,
    graph: Optional[ScanGraph] = None,
) -> PathValidation:
    """Re-check every hop of one attack path using read-only API calls.

    `sources` may be a single data source, a sequence of them, or a mapping
    keyed by account id. Hops are routed to the account that owns the resource
    being checked.
    """
    by_account, default_source = _index_sources(sources)
    relations = _relation_map(graph)
    hops: List[HopVerification] = []

    def source_for(node: str) -> Optional[AWSDataSource]:
        account, _, _ = parse_node(node)
        return by_account.get(account, default_source if not account else by_account.get(account))

    for i in range(len(path.node_ids) - 1):
        src, tgt = path.node_ids[i], path.node_ids[i + 1]
        relation = relations.get((src, tgt), "unknown")
        src_account, src_kind, src_name = parse_node(src)
        tgt_account, tgt_kind, tgt_name = parse_node(tgt)

        # The trust-policy check belongs to the account owning the *target*
        # role; every other check belongs to the source resource's account.
        owner = tgt if relation == "can_assume_cross_account" else src
        source = source_for(owner)

        if source is None:
            status, reason, calls = (
                VerdictStatus.UNVERIFIABLE,
                f"No credentials were supplied for account {parse_node(owner)[0]}, so this "
                f"hop could not be re-checked.",
                [],
            )
        elif relation == "leaks_credentials_for":
            status, reason, calls = _verify_leaked_credentials(source, src_name, tgt_name)
        elif relation.startswith("can_pass_role_to"):
            status, reason, calls = _verify_pass_role(source, src, tgt_name)
        elif relation == "can_escalate_to_admin":
            status, reason, calls = _verify_self_escalation(source, src)
        elif relation == "can_assume_cross_account":
            status, reason, calls = _verify_cross_account_trust(source, src, tgt)
        elif relation in ("grants_admin_access", "has_admin_policy"):
            status, reason, calls = _verify_admin_grant(source, src)
        else:
            status, reason, calls = (
                VerdictStatus.UNVERIFIABLE,
                f"No verifier is implemented for relation {relation!r}.",
                [],
            )

        def label(account: str, kind: str, name: str) -> str:
            where = f" in {account}" if account else ""
            return f"{kind} '{name}'{where}"

        claim = _CLAIMS.get(relation, "{src} -> {tgt}").format(
            src=label(src_account, src_kind, src_name),
            tgt=(
                f"AdministratorAccess in {tgt_account}" if is_admin_sink(tgt)
                else label(tgt_account, tgt_kind, tgt_name)
            ),
        )

        hops.append(
            HopVerification(
                index=i + 1,
                source=src,
                target=tgt,
                relation=relation,
                claim=claim,
                status=status,
                reason=reason,
                calls=calls,
            )
        )

    statuses = [h.status for h in hops]
    if not hops:
        overall = VerdictStatus.UNVERIFIABLE
        summary = "This path has no hops to verify."
    elif VerdictStatus.REFUTED in statuses:
        broken = next(h for h in hops if h.status is VerdictStatus.REFUTED)
        overall = VerdictStatus.REFUTED
        summary = (
            f"Path broken at hop {broken.index}: {broken.reason} The chain no longer "
            f"reaches AdministratorAccess."
        )
    elif VerdictStatus.UNVERIFIABLE in statuses:
        overall = VerdictStatus.UNVERIFIABLE
        confirmed = sum(1 for s in statuses if s is VerdictStatus.CONFIRMED)
        summary = (
            f"{confirmed} of {len(hops)} hops confirmed; the rest could not be checked "
            f"with the permissions available. Treat this path as unproven."
        )
    else:
        overall = VerdictStatus.CONFIRMED
        summary = (
            f"All {len(hops)} hops independently re-verified against the account with "
            f"read-only calls. Every precondition for reaching AdministratorAccess holds "
            f"right now. No escalation was performed."
        )

    return PathValidation(
        path_id=path.path_id,
        status=overall,
        summary=summary,
        hops=hops,
    )


def validate_paths(
    paths: Sequence[AttackPath],
    sources: Sources,
    graph: Optional[ScanGraph] = None,
) -> List[PathValidation]:
    return [validate_path(p, sources, graph) for p in paths]
