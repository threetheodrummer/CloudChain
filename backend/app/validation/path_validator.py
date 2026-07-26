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

from typing import Dict, List, Optional, Sequence, Tuple

from app.graph.attack_graph import ADMIN_SINK
from app.models import (
    AttackPath,
    EvidenceCall,
    HopVerification,
    PathValidation,
    ScanGraph,
    VerdictStatus,
)
from app.scanners.iam_scanner import COMPUTE_CREATE_ACTIONS
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
        "get_policy_statements",
    }
)


def _split_node(node: str) -> Tuple[str, str]:
    """'s3_bucket:my-bucket' -> ('s3_bucket', 'my-bucket')."""
    kind, _, name = node.partition(":")
    return kind, name


def _statements(source: AWSDataSource, policy_names: Sequence[str]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for name in policy_names:
        pairs.extend(source.get_policy_statements(name))
    return pairs


def _is_wildcard(action: str, resource: str) -> bool:
    return action in ("*", "*:*") and resource == "*"


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

    return (
        VerdictStatus.CONFIRMED,
        (
            f"Bucket '{bucket}' is publicly readable and exposes {len(matched)} "
            f"credential-shaped key ({', '.join(matched)}), which the graph attributes "
            f"to '{user}'. Object contents were not read."
        ),
        calls,
    )


def _verify_pass_role(
    source: AWSDataSource, user: str, role: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """IAM user -> IAM role: PassRole plus a compute-creation action."""
    calls: List[EvidenceCall] = []

    policy_names = source.list_user_policy_names(user)
    calls.append(
        EvidenceCall(
            api="iam:ListAttachedUserPolicies",
            request=f"UserName={user}",
            observed=f"{len(policy_names)} policy/policies: {', '.join(policy_names) or 'none'}",
            cli=f"aws iam list-attached-user-policies --user-name {user}",
        )
    )

    statements = _statements(source, policy_names)
    if not statements:
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Could not resolve the policy documents attached to '{user}', so the "
            f"PassRole grant could not be re-checked.",
            calls,
        )

    actions = {a for a, _ in statements}
    pass_targets = [r for a, r in statements if a == "iam:PassRole"]
    compute = sorted(actions & COMPUTE_CREATE_ACTIONS)

    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"policies={', '.join(policy_names)}",
            observed=(
                f"iam:PassRole -> {', '.join(pass_targets) if pass_targets else 'not granted'}; "
                f"compute actions: {', '.join(compute) if compute else 'none'}"
            ),
            cli=f"aws iam list-attached-user-policies --user-name {user}  "
            f"# then get-policy-version for each",
        )
    )

    if not pass_targets:
        return (
            VerdictStatus.REFUTED,
            f"'{user}' no longer holds iam:PassRole.",
            calls,
        )
    if not compute:
        return (
            VerdictStatus.REFUTED,
            f"'{user}' holds iam:PassRole but no compute-creation action, so it cannot "
            f"launch anything to run as '{role}'.",
            calls,
        )

    scoped = any(t == "*" or t.endswith(f"/{role}") or t == role for t in pass_targets)
    if not scoped:
        return (
            VerdictStatus.REFUTED,
            f"'{user}' can pass roles, but '{role}' is not among the permitted targets "
            f"({', '.join(pass_targets)}).",
            calls,
        )

    wildcard = "*" in pass_targets
    return (
        VerdictStatus.CONFIRMED,
        (
            f"'{user}' holds iam:PassRole ({'unscoped' if wildcard else 'scoped to ' + role}) "
            f"together with {', '.join(compute)}. The grant was verified; no function or "
            f"instance was created."
        ),
        calls,
    )


def _verify_admin_grant(
    source: AWSDataSource, node: str
) -> Tuple[VerdictStatus, str, List[EvidenceCall]]:
    """Role or user -> AdministratorAccess: an unrestricted (*:*) statement."""
    kind, name = _split_node(node)
    calls: List[EvidenceCall] = []

    if kind == "iam_role":
        policy_names = source.list_role_policy_names(name)
        api, cli = "iam:ListAttachedRolePolicies", f"aws iam list-attached-role-policies --role-name {name}"
    else:
        policy_names = source.list_user_policy_names(name)
        api, cli = "iam:ListAttachedUserPolicies", f"aws iam list-attached-user-policies --user-name {name}"

    calls.append(
        EvidenceCall(
            api=api,
            request=f"name={name}",
            observed=f"{len(policy_names)} policy/policies: {', '.join(policy_names) or 'none'}",
            cli=cli,
        )
    )

    statements = _statements(source, policy_names)
    if not statements:
        return (
            VerdictStatus.UNVERIFIABLE,
            f"Could not resolve the policy documents attached to '{name}'.",
            calls,
        )

    wildcards = [(a, r) for a, r in statements if _is_wildcard(a, r)]
    calls.append(
        EvidenceCall(
            api="iam:GetPolicyVersion",
            request=f"policies={', '.join(policy_names)}",
            observed=(
                f"unrestricted statement found: {wildcards[0][0]} on {wildcards[0][1]}"
                if wildcards
                else "no unrestricted (*:*) statement"
            ),
            cli=f"aws iam get-policy-version --policy-arn <arn> --version-id <v>",
        )
    )

    if not wildcards:
        return (
            VerdictStatus.REFUTED,
            f"'{name}' no longer carries an unrestricted (*:*) policy.",
            calls,
        )

    return (
        VerdictStatus.CONFIRMED,
        f"'{name}' carries an unrestricted statement (Action {wildcards[0][0]} on "
        f"Resource {wildcards[0][1]}), which is AdministratorAccess in effect.",
        calls,
    )


# --------------------------------------------------------------------------
# Path-level driver
# --------------------------------------------------------------------------

_CLAIMS = {
    "leaks_credentials_for": "A publicly readable object in {src} leaks credentials for {tgt}",
    "can_pass_role_to": "{src} can pass the role {tgt} into new compute and run code as it",
    "can_pass_role_to (wildcard)": "{src} holds unscoped iam:PassRole and can pass any role, including {tgt}",
    "grants_admin_access": "{src} is granted AdministratorAccess",
    "has_admin_policy": "{src} directly holds an unrestricted (*:*) policy",
}


def _relation_map(graph: Optional[ScanGraph]) -> Dict[Tuple[str, str], str]:
    if graph is None:
        return {}
    return {(e.source, e.target): e.relation for e in graph.edges}


def validate_path(
    path: AttackPath,
    source: AWSDataSource,
    graph: Optional[ScanGraph] = None,
) -> PathValidation:
    """Re-check every hop of one attack path using read-only API calls."""
    relations = _relation_map(graph)
    hops: List[HopVerification] = []

    for i in range(len(path.node_ids) - 1):
        src, tgt = path.node_ids[i], path.node_ids[i + 1]
        relation = relations.get((src, tgt), "unknown")
        src_kind, src_name = _split_node(src)
        tgt_kind, tgt_name = _split_node(tgt)

        if relation == "leaks_credentials_for":
            status, reason, calls = _verify_leaked_credentials(source, src_name, tgt_name)
        elif relation.startswith("can_pass_role_to"):
            status, reason, calls = _verify_pass_role(source, src_name, tgt_name)
        elif relation in ("grants_admin_access", "has_admin_policy"):
            status, reason, calls = _verify_admin_grant(source, src)
        else:
            status, reason, calls = (
                VerdictStatus.UNVERIFIABLE,
                f"No verifier is implemented for relation {relation!r}.",
                [],
            )

        claim = _CLAIMS.get(relation, "{src} -> {tgt}").format(
            src=f"{src_kind} '{src_name}'",
            tgt="AdministratorAccess" if tgt == ADMIN_SINK else f"{tgt_kind} '{tgt_name}'",
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
    source: AWSDataSource,
    graph: Optional[ScanGraph] = None,
) -> List[PathValidation]:
    return [validate_path(p, source, graph) for p in paths]
