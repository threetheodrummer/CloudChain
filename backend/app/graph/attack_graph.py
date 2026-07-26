"""
Attack-path graph engine -- CloudChain's main differentiator versus flat
CSPM output.

Instead of reporting "bucket X is public" and "user Y can escalate
privileges" as two unrelated medium/high findings, this module wires
findings together into a resource graph and asks: is there a path from
something an attacker can reach on the internet, all the way to
AdministratorAccess? If so, that chain is the real risk -- and it's
reported as a single narrative critical finding, not buried in a list.

The graph is organisation-wide, not per-account. Nodes are namespaced by
account id ("111111111111/iam_user:svc-deploy-bot"), and each account gets its
own AdministratorAccess sink, because admin in a sandbox account is not the
same outcome as admin in shared services.

Correlation rules implemented (see _wire_* functions below):
  1. A publicly exposed object matching a credential-like name pattern in a
     bucket is wired to the IAM identity it belongs to (leaks_credentials_for).
  2. An identity with iam:PassRole + a compute-creation action is wired to
     the role(s) it can pass (can_pass_role_to).
  3. A role trusting a principal in another account is wired from that
     external principal to the role (can_assume_cross_account).
  4. A role or identity carrying a wildcard (*:*) policy is wired to its
     account's AdministratorAccess sink (grants_admin_access /
     has_admin_policy).

Rules 2 and 3 are deliberately separate mechanisms rather than one "can become
this role" edge. iam:PassRole is same-account by construction -- AWS will not
let an identity pass a role that lives in another account -- so it can never
cross an org boundary. Crossing requires sts:AssumeRole against a role whose
*trust policy* names an external principal. Collapsing the two would produce
paths that look plausible and cannot actually be walked.

Note on real-mode correlation: CloudChain never downloads or reads object
*contents* -- only key names -- for safety and to avoid touching
potentially sensitive data during a scan. Rule 1 relies on the demo-mode
ground-truth hint in demo runs; a real deployment would need an explicit
mapping (e.g. from a secrets-scanning pipeline) to wire that edge with the
same confidence. That limitation is intentional and documented rather than
guessed at.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import networkx as nx

from app.models import AttackPath, Finding, GraphEdge, GraphNode, ScanGraph, Severity

ADMIN_LABEL = "AdministratorAccess"
ADMIN_TYPE = "admin_access"

_RELATION_TEMPLATES = {
    "leaks_credentials_for": "A publicly exposed object in {src} leaks credentials for {tgt}",
    "can_pass_role_to": "{src} holds iam:PassRole and can pass the role {tgt} into a new Lambda "
    "function or EC2 instance, then invoke/run it",
    "can_pass_role_to (wildcard)": "{src} holds an unscoped iam:PassRole and can pass any role, "
    "including {tgt}, into a new Lambda function or EC2 instance",
    "can_assume_cross_account": "{src} is named in the trust policy of {tgt} and can cross the "
    "account boundary with sts:AssumeRole",
    "grants_admin_access": "{src} is granted AdministratorAccess ({tgt})",
    "has_admin_policy": "{src} directly holds an unrestricted (*:*) policy, i.e. {tgt}",
}


def node_id(resource_type: str, resource_id: str, account_id: str = "") -> str:
    """Namespaced node identity.

    With no account id this returns the original single-account form, so
    graphs built from unattributed findings behave exactly as before.
    """
    prefix = f"{account_id}/" if account_id else ""
    return f"{prefix}{resource_type}:{resource_id}"


def parse_node(nid: str) -> Tuple[str, str, str]:
    """Inverse of node_id: returns (account_id, resource_type, resource_id).

    Single shared implementation because the posture engine and the path
    validator both need to take node ids apart, and three copies of this
    would drift.
    """
    account, sep, rest = nid.partition("/")
    if not sep:
        account, rest = "", nid
    kind, _, name = rest.partition(":")
    return account, kind, name


def admin_sink(account_id: str = "") -> str:
    return node_id(ADMIN_TYPE, ADMIN_LABEL, account_id)


def is_admin_sink(nid: str) -> bool:
    return parse_node(nid)[1] == ADMIN_TYPE


# Single-account sink, kept as a module constant for callers that predate
# multi-account support.
ADMIN_SINK = admin_sink()


def _finding_node(f: Finding) -> str:
    return node_id(f.resource_type, f.resource_id, f.account_id)


def build_attack_graph(findings: List[Finding]) -> Tuple[nx.DiGraph, Dict[str, List[Finding]]]:
    g = nx.DiGraph()
    findings_by_resource: Dict[str, List[Finding]] = defaultdict(list)

    for f in findings:
        nid = _finding_node(f)
        findings_by_resource[nid].append(f)
        if not g.has_node(nid):
            g.add_node(
                nid,
                type=f.resource_type,
                label=f.resource_id,
                account_id=f.account_id,
                account_name=f.account_name,
                issue_codes=[],
            )
        g.nodes[nid]["issue_codes"].append(f.issue_code)

    # One admin sink per account in scope. Admin in sandbox and admin in
    # shared-services are different outcomes and must not collapse into one node.
    accounts = {f.account_id for f in findings} or {""}
    account_names = {f.account_id: f.account_name for f in findings}
    for acct in accounts:
        sink = admin_sink(acct)
        if not g.has_node(sink):
            g.add_node(
                sink,
                type=ADMIN_TYPE,
                label=ADMIN_LABEL,
                account_id=acct,
                account_name=account_names.get(acct, ""),
                issue_codes=[],
            )

    by_issue: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_issue[f.issue_code].append(f)

    _wire_leaked_credentials(g, by_issue)
    _wire_privilege_escalation(g, by_issue)
    _wire_cross_account_trust(g, by_issue)
    _wire_admin_sink(g, by_issue)

    return g, findings_by_resource


def _wire_leaked_credentials(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    for f in by_issue.get("S3_SENSITIVE_OBJECT_EXPOSED", []):
        leaked_for = f.evidence.get("leaked_identity_hint")
        if not leaked_for:
            continue
        bucket_node = node_id("s3_bucket", f.resource_id, f.account_id)
        # A bucket and the identity whose key it leaks are necessarily in the
        # same account -- the key belongs to that account's IAM.
        user_node = node_id("iam_user", leaked_for, f.account_id)
        if g.has_node(user_node):
            g.add_edge(bucket_node, user_node, relation="leaks_credentials_for")


def _wire_privilege_escalation(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    """iam:PassRole escalation. Same-account only, by AWS's own rules."""
    admin_roles_by_account: Dict[str, Set[str]] = defaultdict(set)
    for f in by_issue.get("IAM_ROLE_ADMIN_ACCESS", []):
        admin_roles_by_account[f.account_id].add(
            node_id("iam_role", f.resource_id, f.account_id)
        )

    for f in by_issue.get("IAM_PRIVILEGE_ESCALATION_RISK", []):
        acct = f.account_id
        user_node = node_id("iam_user", f.resource_id, acct)
        for target in f.evidence.get("pass_role_targets", []):
            if target == "*":
                for role_node in admin_roles_by_account.get(acct, set()):
                    g.add_edge(user_node, role_node, relation="can_pass_role_to (wildcard)")
            else:
                role_node = node_id("iam_role", target, acct)
                if not g.has_node(role_node):
                    g.add_node(
                        role_node,
                        type="iam_role",
                        label=target,
                        account_id=acct,
                        account_name=f.account_name,
                        issue_codes=[],
                    )
                g.add_edge(user_node, role_node, relation="can_pass_role_to")


def _wire_cross_account_trust(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    """sts:AssumeRole across an account boundary, from the trust policy.

    The edge runs from the *external* principal to the role, because that's the
    direction an attacker travels: compromise the named identity in account A,
    assume the role in account B.
    """
    from app.scanners.iam_scanner import _account_from_arn, _principal_name_from_arn

    for f in by_issue.get("IAM_CROSS_ACCOUNT_TRUST", []):
        role_node = node_id("iam_role", f.resource_id, f.account_id)
        for arn in f.evidence.get("trusted_principals", []):
            src_account = _account_from_arn(arn)
            kind, name = _principal_name_from_arn(arn)
            if not src_account or not kind:
                # ':root' or a wildcard: the whole account is trusted, but there
                # is no single identity to draw an edge from. Reported as a
                # finding rather than turned into a speculative path.
                continue
            principal_node = node_id(kind, name, src_account)
            if g.has_node(principal_node):
                g.add_edge(principal_node, role_node, relation="can_assume_cross_account")


def _wire_admin_sink(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    for f in by_issue.get("IAM_ROLE_ADMIN_ACCESS", []):
        role_node = node_id("iam_role", f.resource_id, f.account_id)
        g.add_edge(role_node, admin_sink(f.account_id), relation="grants_admin_access")

    for f in by_issue.get("IAM_OVERPERMISSIVE_POLICY", []):
        node = node_id(f.resource_type, f.resource_id, f.account_id)
        g.add_edge(node, admin_sink(f.account_id), relation="has_admin_policy")

    # A role reachable from outside that also carries admin is itself a route to
    # admin in its own account, even if no separate IAM_ROLE_ADMIN_ACCESS
    # finding was raised for it.
    for f in by_issue.get("IAM_CROSS_ACCOUNT_TRUST", []):
        if not f.evidence.get("grants_admin"):
            continue
        role_node = node_id("iam_role", f.resource_id, f.account_id)
        g.add_edge(role_node, admin_sink(f.account_id), relation="grants_admin_access")


def _describe(g: nx.DiGraph, nid: str) -> str:
    data = g.nodes[nid]
    account = data.get("account_name") or data.get("account_id") or ""
    where = f" in {account}" if account else ""
    if data["type"] == ADMIN_TYPE:
        return f"{ADMIN_LABEL}{where}"
    return f"{data['type']} '{data['label']}'{where}"


def _entry_points(findings_by_resource: Dict[str, List[Finding]]) -> Set[str]:
    entries = set()
    for nid, flist in findings_by_resource.items():
        if any(f.internet_facing and f.sensitive for f in flist):
            entries.add(nid)
    return entries


def find_attack_paths(g: nx.DiGraph, findings_by_resource: Dict[str, List[Finding]]) -> List[AttackPath]:
    sinks = [n for n in g.nodes if is_admin_sink(n)]
    if not sinks:
        return []

    paths: List[AttackPath] = []
    for entry in sorted(_entry_points(findings_by_resource)):
        if entry not in g:
            continue
        for sink in sorted(sinks):
            try:
                raw_paths = list(nx.all_simple_paths(g, entry, sink))
            except nx.NodeNotFound:
                continue

            for raw in raw_paths:
                paths.append(_build_path(g, raw, entry_kind="internet"))

    return paths


def _build_path(g: nx.DiGraph, raw: List[str], entry_kind: str) -> AttackPath:
    steps = []
    for i in range(len(raw) - 1):
        src, tgt = raw[i], raw[i + 1]
        relation = g.edges[src, tgt]["relation"]
        template = _RELATION_TEMPLATES.get(relation, "{src} -> {tgt} ({relation})")
        steps.append(template.format(src=_describe(g, src), tgt=_describe(g, tgt), relation=relation))

    accounts = [g.nodes[n].get("account_id", "") for n in raw]
    involved = sorted({a for a in accounts if a})
    crosses = len(involved) > 1

    if entry_kind == "identity":
        narrative = (
            "Starting from a compromised " + _describe(g, raw[0]) + ": "
            + ". Then, ".join(steps)
            + ", resulting in administrator access."
        )
    else:
        narrative = ". Then, ".join(steps) + ", resulting in full account takeover."
    if crosses:
        narrative += (
            " This chain crosses an account boundary, so no single account's "
            "configuration reveals it."
        )

    return AttackPath(
        path_id=hashlib.sha256("->".join(raw).encode()).hexdigest()[:12],
        node_ids=raw,
        steps=steps,
        severity=Severity.CRITICAL,
        narrative=narrative,
        crosses_accounts=crosses,
        accounts=involved,
        entry_kind=entry_kind,
    )


def find_escalation_paths(
    g: nx.DiGraph, findings_by_resource: Dict[str, List[Finding]]
) -> List[AttackPath]:
    """Routes to admin that start from an ordinary IAM identity.

    find_attack_paths answers "can an unauthenticated attacker reach admin".
    This answers the weaker but still important question: "if any one identity
    were compromised, could it become an administrator?"

    They are kept separate because conflating them overstates risk -- an
    escalation primitive is not a live breach. But for pre-deploy checking the
    escalation question is the one that matters: a plan cannot prove that a
    bucket leaks a specific identity's credentials, so it can rarely establish
    an internet entry point, while it can prove perfectly well that a pull
    request creates a user who can make itself an administrator.

    Direct identity -> admin edges are excluded: an identity that already holds
    a wildcard policy hasn't escalated, it's simply an admin already.
    """
    sinks = [n for n in g.nodes if is_admin_sink(n)]
    if not sinks:
        return []

    identities = sorted(n for n in g.nodes if parse_node(n)[1] in ("iam_user", "iam_role"))
    paths: List[AttackPath] = []

    for start in identities:
        for sink in sorted(sinks):
            if start == sink:
                continue
            try:
                raw_paths = list(nx.all_simple_paths(g, start, sink))
            except nx.NodeNotFound:
                continue
            for raw in raw_paths:
                if len(raw) < 3:
                    continue  # already an administrator, not an escalation
                paths.append(_build_path(g, raw, entry_kind="identity"))

    return paths


def finding_ids_on_paths(paths: List[AttackPath], findings_by_resource: Dict[str, List[Finding]]) -> Set[str]:
    """Finding IDs whose resource sits on at least one attack path -- used by
    the risk scoring engine to boost chained findings above isolated ones."""
    ids: Set[str] = set()
    for path in paths:
        for nid in path.node_ids:
            for f in findings_by_resource.get(nid, []):
                ids.add(f.id)
    return ids


def to_scan_graph(g: nx.DiGraph) -> ScanGraph:
    nodes = [
        GraphNode(
            id=nid,
            type=data["type"],
            label=data["label"],
            attributes={
                "issue_codes": data.get("issue_codes", []),
                "account_id": data.get("account_id", ""),
                "account_name": data.get("account_name", ""),
            },
        )
        for nid, data in g.nodes(data=True)
    ]
    edges = [GraphEdge(source=u, target=v, relation=data["relation"]) for u, v, data in g.edges(data=True)]
    return ScanGraph(nodes=nodes, edges=edges)
