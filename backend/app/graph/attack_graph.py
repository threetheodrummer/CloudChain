"""
Attack-path graph engine -- CloudChain's main differentiator versus flat
CSPM output.

Instead of reporting "bucket X is public" and "user Y can escalate
privileges" as two unrelated medium/high findings, this module wires
findings together into a resource graph and asks: is there a path from
something an attacker can reach on the internet, all the way to
AdministratorAccess? If so, that chain is the real risk -- and it's
reported as a single narrative critical finding, not buried in a list.

Correlation rules implemented (see _wire_* functions below):
  1. A publicly exposed object matching a credential-like name pattern in a
     bucket is wired to the IAM identity it belongs to (leaks_credentials_for).
  2. An identity with iam:PassRole + a compute-creation action is wired to
     the role(s) it can pass (can_pass_role_to).
  3. A role or identity carrying a wildcard (*:*) policy is wired to a
     synthetic AdministratorAccess sink node (grants_admin_access /
     has_admin_policy).

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

ADMIN_SINK = "admin_access:AdministratorAccess"

_RELATION_TEMPLATES = {
    "leaks_credentials_for": "A publicly exposed object in {src} leaks credentials for {tgt}",
    "can_pass_role_to": "{src} holds iam:PassRole and can pass the role {tgt} into a new Lambda "
    "function or EC2 instance, then invoke/run it",
    "can_pass_role_to (wildcard)": "{src} holds an unscoped iam:PassRole and can pass any role, "
    "including {tgt}, into a new Lambda function or EC2 instance",
    "grants_admin_access": "{src} is granted AdministratorAccess ({tgt})",
    "has_admin_policy": "{src} directly holds an unrestricted (*:*) policy, i.e. {tgt}",
}


def node_id(resource_type: str, resource_id: str) -> str:
    return f"{resource_type}:{resource_id}"


def build_attack_graph(findings: List[Finding]) -> Tuple[nx.DiGraph, Dict[str, List[Finding]]]:
    g = nx.DiGraph()
    findings_by_resource: Dict[str, List[Finding]] = defaultdict(list)

    for f in findings:
        nid = node_id(f.resource_type, f.resource_id)
        findings_by_resource[nid].append(f)
        if not g.has_node(nid):
            g.add_node(nid, type=f.resource_type, label=f.resource_id, issue_codes=[])
        g.nodes[nid]["issue_codes"].append(f.issue_code)

    g.add_node(ADMIN_SINK, type="admin_access", label="AdministratorAccess", issue_codes=[])

    by_issue: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_issue[f.issue_code].append(f)

    _wire_leaked_credentials(g, by_issue)
    _wire_privilege_escalation(g, by_issue)
    _wire_admin_sink(g, by_issue)

    return g, findings_by_resource


def _wire_leaked_credentials(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    for f in by_issue.get("S3_SENSITIVE_OBJECT_EXPOSED", []):
        leaked_for = f.evidence.get("leaked_identity_hint")
        if not leaked_for:
            continue
        bucket_node = node_id("s3_bucket", f.resource_id)
        user_node = node_id("iam_user", leaked_for)
        if g.has_node(user_node):
            g.add_edge(bucket_node, user_node, relation="leaks_credentials_for")


def _wire_privilege_escalation(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    admin_roles = {node_id("iam_role", f.resource_id) for f in by_issue.get("IAM_ROLE_ADMIN_ACCESS", [])}

    for f in by_issue.get("IAM_PRIVILEGE_ESCALATION_RISK", []):
        user_node = node_id("iam_user", f.resource_id)
        for target in f.evidence.get("pass_role_targets", []):
            if target == "*":
                for role_node in admin_roles:
                    g.add_edge(user_node, role_node, relation="can_pass_role_to (wildcard)")
            else:
                role_node = node_id("iam_role", target)
                if not g.has_node(role_node):
                    g.add_node(role_node, type="iam_role", label=target, issue_codes=[])
                g.add_edge(user_node, role_node, relation="can_pass_role_to")


def _wire_admin_sink(g: nx.DiGraph, by_issue: Dict[str, List[Finding]]) -> None:
    for f in by_issue.get("IAM_ROLE_ADMIN_ACCESS", []):
        role_node = node_id("iam_role", f.resource_id)
        g.add_edge(role_node, ADMIN_SINK, relation="grants_admin_access")

    for f in by_issue.get("IAM_OVERPERMISSIVE_POLICY", []):
        node = node_id(f.resource_type, f.resource_id)
        g.add_edge(node, ADMIN_SINK, relation="has_admin_policy")


def _describe(g: nx.DiGraph, nid: str) -> str:
    data = g.nodes[nid]
    return f"{data['type']} '{data['label']}'"


def _entry_points(findings_by_resource: Dict[str, List[Finding]]) -> Set[str]:
    entries = set()
    for nid, flist in findings_by_resource.items():
        if any(f.internet_facing and f.sensitive for f in flist):
            entries.add(nid)
    return entries


def find_attack_paths(g: nx.DiGraph, findings_by_resource: Dict[str, List[Finding]]) -> List[AttackPath]:
    if ADMIN_SINK not in g:
        return []

    paths: List[AttackPath] = []
    for entry in _entry_points(findings_by_resource):
        if entry not in g:
            continue
        try:
            raw_paths = list(nx.all_simple_paths(g, entry, ADMIN_SINK))
        except nx.NodeNotFound:
            continue

        for raw in raw_paths:
            steps = []
            for i in range(len(raw) - 1):
                src, tgt = raw[i], raw[i + 1]
                relation = g.edges[src, tgt]["relation"]
                template = _RELATION_TEMPLATES.get(relation, "{src} -> {tgt} ({relation})")
                steps.append(
                    template.format(src=_describe(g, src), tgt=_describe(g, tgt), relation=relation)
                )

            narrative = ". Then, ".join(steps) + ", resulting in full account takeover."
            path_id = hashlib.sha256("->".join(raw).encode()).hexdigest()[:12]
            paths.append(
                AttackPath(
                    path_id=path_id,
                    node_ids=raw,
                    steps=steps,
                    severity=Severity.CRITICAL,
                    narrative=narrative,
                )
            )

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
        GraphNode(id=nid, type=data["type"], label=data["label"], attributes={"issue_codes": data.get("issue_codes", [])})
        for nid, data in g.nodes(data=True)
    ]
    edges = [GraphEdge(source=u, target=v, relation=data["relation"]) for u, v, data in g.edges(data=True)]
    return ScanGraph(nodes=nodes, edges=edges)
