"""
Account-level posture score.

The per-finding risk scores in scoring.py answer "which finding matters most".
This module answers the other question a reader asks first: "how bad is this
account overall?"

Every CSPM on the market puts a single number on a dashboard -- Wiz, Prisma
Cloud, Defender for Cloud all do it -- and none will tell you how that number
was produced. Security teams learn not to trust it, because when the score
moves nobody can say which finding moved it.

This score is built to be argued with. It starts at 100 and deducts across four
independent dimensions, each of which publishes its own arithmetic and names
the exact findings behind it:

    Exposure      (max -25)  How much of the estate is reachable from the
                             internet, weighted by finding severity.
    Privilege     (max -25)  How over-permissioned the identity layer is.
    Reachability  (max -30)  Whether a confirmed chain from an internet entry
                             point to AdministratorAccess exists, and how
                             short and plentiful those chains are.
    Blast radius  (max -20)  What fraction of the resource graph an attacker
                             reaches from the exposed entry points.

Why four dimensions instead of counting findings by severity: a flat ladder
("-4 per HIGH") makes the score a proxy for account size, and it moves by the
same amount whether the HIGH you fixed was a public bucket leaking credentials
or an unencrypted internal volume. Separating the dimensions is what lets the
dashboard say "reachability is what's killing this account" rather than "you
have a lot of findings" -- which is the entire premise of the tool.

Reachability carries the largest weight deliberately: one proven path to admin
is a materially different state from a pile of unrelated misconfigurations.
On top of its points penalty, any confirmed attack path also caps the grade at
F -- if an attacker can demonstrably reach AdministratorAccess, the arithmetic
shouldn't be able to average that away into a passing grade. The numeric score
still conveys magnitude; the grade conveys "compromised by design".
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set

import networkx as nx

from app.graph.attack_graph import ADMIN_SINK, node_id
from app.models import AttackPath, ScanGraph, ScoredFinding, Severity

# --------------------------------------------------------------------------
# Tunables. These are the only magic numbers in the engine; they live here
# together so the whole model can be reviewed in one screen.
# --------------------------------------------------------------------------

COMPONENT_WEIGHTS = {
    "exposure": 25.0,
    "privilege": 25.0,
    "reachability": 30.0,
    "blast_radius": 20.0,
}

SEVERITY_PRESSURE = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 6.0,
    Severity.CRITICAL: 10.0,
}

# Total internet-facing severity pressure at which the exposure dimension is
# fully saturated.
#
# Saturation ceilings are set deliberately above the level a typical small
# estate reaches. A dimension pinned at 1.0 stops discriminating: fixing a
# public bucket wouldn't move the score, and a posture number that doesn't
# respond to remediation trains people to ignore it.
EXPOSURE_SATURATION = 60.0

# Per-issue weight for the identity layer. Escalation primitives and
# unrestricted policies dominate, because they are what turn an ordinary
# foothold into account takeover.
PRIVILEGE_ISSUE_WEIGHTS: Dict[str, float] = {
    "IAM_OVERPERMISSIVE_POLICY": 10.0,
    "IAM_PRIVILEGE_ESCALATION_RISK": 9.0,
    "IAM_ROLE_ADMIN_ACCESS": 6.0,
    "IAM_USER_NO_MFA": 4.0,
    "IAM_STALE_ACCESS_KEY": 3.0,
    "IAM_WEAK_PASSWORD_POLICY": 2.0,
}
PRIVILEGE_SATURATION = 40.0

# Reachability is scored from the existence and shape of confirmed paths.
REACHABILITY_PATH_EXISTS = 0.70  # any proven route to admin
REACHABILITY_SHORT_CHAIN = 0.20  # shortest route is <= SHORT_CHAIN_HOPS
REACHABILITY_MULTI_PATH = 0.10  # several independent routes
SHORT_CHAIN_HOPS = 2
MULTI_PATH_SATURATION = 3  # 3+ distinct paths saturates this term

# (minimum score, grade) checked in order, best first.
GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (20, "E"), (0, "F")]


def grade_for(score: float) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _factor(label: str, detail: str, contribution: float) -> Dict[str, Any]:
    """One auditable line item behind a component's value."""
    return {"label": label, "detail": detail, "contribution": contribution}


def _component(
    key: str,
    name: str,
    raw: float,
    headline: str,
    method: str,
    factors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    weight = COMPONENT_WEIGHTS[key]
    raw = _clamp01(raw)
    return {
        "key": key,
        "name": name,
        "weight": weight,
        "raw": round(raw, 4),
        "points_lost": round(raw * weight, 2),
        "headline": headline,
        "method": method,
        "factors": factors,
    }


# --------------------------------------------------------------------------
# Component 1 -- Exposure
# --------------------------------------------------------------------------


def _exposure(findings: Sequence[ScoredFinding]) -> Dict[str, Any]:
    exposed = [f for f in findings if f.internet_facing]
    factors: List[Dict[str, Any]] = []
    pressure = 0.0

    for f in sorted(exposed, key=lambda x: SEVERITY_PRESSURE[x.base_severity], reverse=True):
        w = SEVERITY_PRESSURE[f.base_severity]
        pressure += w
        factors.append(
            _factor(
                f"{f.issue_code} on {f.resource_id}",
                f"{f.base_severity.value} severity, reachable from the internet",
                w,
            )
        )

    raw = pressure / EXPOSURE_SATURATION
    headline = (
        "No internet-reachable findings."
        if not exposed
        else f"{len(exposed)} internet-reachable finding(s) totalling {pressure:.0f} severity pressure."
    )

    return _component(
        "exposure",
        "Exposure",
        raw,
        headline,
        (
            f"Sum the severity pressure of every internet-facing finding "
            f"(LOW 1, MEDIUM 3, HIGH 6, CRITICAL 10), then divide by a saturation "
            f"ceiling of {EXPOSURE_SATURATION:.0f} "
            f"(= {EXPOSURE_SATURATION / SEVERITY_PRESSURE[Severity.CRITICAL]:.0f} CRITICAL "
            f"internet-facing findings). "
            f"{pressure:.0f} / {EXPOSURE_SATURATION:.0f} = {_clamp01(raw):.2f}."
        ),
        factors,
    )


# --------------------------------------------------------------------------
# Component 2 -- Privilege
# --------------------------------------------------------------------------


def _privilege(findings: Sequence[ScoredFinding]) -> Dict[str, Any]:
    weighted = [(f, PRIVILEGE_ISSUE_WEIGHTS.get(f.issue_code, 0.0)) for f in findings]
    weighted = [(f, w) for f, w in weighted if w > 0]

    factors: List[Dict[str, Any]] = []
    pressure = 0.0
    for f, w in sorted(weighted, key=lambda pair: pair[1], reverse=True):
        pressure += w
        factors.append(_factor(f"{f.issue_code} on {f.resource_id}", f.title, w))

    raw = pressure / PRIVILEGE_SATURATION
    headline = (
        "No over-permissioned identities detected."
        if not factors
        else f"{len(factors)} identity weakness(es) totalling {pressure:.0f} privilege pressure."
    )

    return _component(
        "privilege",
        "Privilege",
        raw,
        headline,
        (
            f"Weight each identity finding by how much it advances an attacker "
            f"(unrestricted policy 10, PassRole escalation 9, admin role 6, missing "
            f"MFA 4, stale key 3, weak password policy 2) and divide by a saturation "
            f"ceiling of {PRIVILEGE_SATURATION:.0f}. "
            f"{pressure:.0f} / {PRIVILEGE_SATURATION:.0f} = {_clamp01(raw):.2f}."
        ),
        factors,
    )


# --------------------------------------------------------------------------
# Component 3 -- Reachability
# --------------------------------------------------------------------------


def _reachability(attack_paths: Sequence[AttackPath]) -> Dict[str, Any]:
    if not attack_paths:
        return _component(
            "reachability",
            "Reachability",
            0.0,
            "No confirmed path from an internet entry point to AdministratorAccess.",
            (
                "The graph engine found no simple path from any internet-exposed entry "
                "point to the AdministratorAccess sink, so this dimension deducts nothing."
            ),
            [],
        )

    raw = REACHABILITY_PATH_EXISTS
    factors = [
        _factor(
            "Confirmed path to AdministratorAccess",
            f"{len(attack_paths)} chain(s) reach full account takeover from an "
            f"internet-exposed entry point",
            REACHABILITY_PATH_EXISTS,
        )
    ]

    hops = min(max(len(p.node_ids) - 1, 1) for p in attack_paths)
    if hops <= SHORT_CHAIN_HOPS:
        raw += REACHABILITY_SHORT_CHAIN
        factors.append(
            _factor(
                "Short chain",
                f"Shortest route is only {hops} hop(s) -- minimal attacker effort",
                REACHABILITY_SHORT_CHAIN,
            )
        )
    else:
        factors.append(
            _factor(
                "Chain length",
                f"Shortest route is {hops} hops, above the {SHORT_CHAIN_HOPS}-hop penalty threshold",
                0.0,
            )
        )

    multi = _clamp01((len(attack_paths) - 1) / (MULTI_PATH_SATURATION - 1))
    multi_contribution = round(REACHABILITY_MULTI_PATH * multi, 4)
    raw += multi_contribution
    factors.append(
        _factor(
            "Independent routes",
            f"{len(attack_paths)} distinct path(s); fixing one node may not break the others",
            multi_contribution,
        )
    )

    return _component(
        "reachability",
        "Reachability",
        raw,
        f"{len(attack_paths)} confirmed path(s) to AdministratorAccess; shortest is {hops} hop(s).",
        (
            f"A proven route to admin sets a floor of {REACHABILITY_PATH_EXISTS:.2f}. Add "
            f"{REACHABILITY_SHORT_CHAIN:.2f} if the shortest chain is {SHORT_CHAIN_HOPS} hops "
            f"or fewer, and up to {REACHABILITY_MULTI_PATH:.2f} for multiple independent "
            f"routes (saturating at {MULTI_PATH_SATURATION} paths). "
            f"Total = {_clamp01(raw):.2f}."
        ),
        factors,
    )


# --------------------------------------------------------------------------
# Component 4 -- Blast radius
# --------------------------------------------------------------------------


def _entry_nodes(findings: Sequence[ScoredFinding]) -> Set[str]:
    """Same entry-point rule the graph engine uses: a resource is an entry
    point when it has a finding that is both internet-facing and sensitive."""
    return {
        node_id(f.resource_type, f.resource_id)
        for f in findings
        if f.internet_facing and f.sensitive
    }


def _to_digraph(graph: Optional[ScanGraph]) -> Optional[nx.DiGraph]:
    """Rebuild a directed graph from the serialised ScanGraph on the scan.

    Posture is computed from a persisted ScanResult (so historical scans can be
    rescored), which stores the graph in its serialised form rather than as a
    live networkx object.
    """
    if graph is None or not graph.nodes:
        return None
    g = nx.DiGraph()
    for n in graph.nodes:
        g.add_node(n.id)
    for e in graph.edges:
        g.add_edge(e.source, e.target)
    return g


def _blast_radius(
    findings: Sequence[ScoredFinding], graph: Optional[ScanGraph]
) -> Dict[str, Any]:
    g = _to_digraph(graph)

    if g is None or g.number_of_nodes() <= 1:
        return _component(
            "blast_radius",
            "Blast radius",
            0.0,
            "No resource graph available to measure downstream reach.",
            "Skipped: the scan produced no correlatable resource graph.",
            [],
        )

    # The synthetic admin sink is an outcome, not a resource an attacker
    # "reaches" -- excluding it keeps the denominator honest.
    real_nodes = {n for n in g.nodes if n != ADMIN_SINK}
    total = len(real_nodes)

    entries = _entry_nodes(findings) & set(g.nodes)
    reached: Set[str] = set()
    factors: List[Dict[str, Any]] = []

    for entry in sorted(entries):
        downstream = (nx.descendants(g, entry) | {entry}) & real_nodes
        reached |= downstream
        factors.append(
            _factor(
                f"Entry point: {entry}",
                f"reaches {len(downstream)} of {total} resources downstream",
                float(len(downstream)),
            )
        )

    raw = (len(reached) / total) if total else 0.0
    headline = (
        "No internet-exposed entry point into the resource graph."
        if not entries
        else f"{len(reached)} of {total} resources ({raw * 100:.0f}%) are reachable "
        f"from an exposed entry point."
    )

    return _component(
        "blast_radius",
        "Blast radius",
        raw,
        headline,
        (
            f"Take every internet-exposed, sensitive resource as an attacker entry point, "
            f"walk the directed graph to collect everything downstream, and divide by the "
            f"{total} real resource(s) in the graph (the synthetic AdministratorAccess sink "
            f"is excluded). {len(reached)} / {total} = {_clamp01(raw):.2f}."
        ),
        factors,
    )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------


def compute_posture(
    findings: List[ScoredFinding],
    attack_paths: List[AttackPath],
    graph: Optional[ScanGraph] = None,
) -> Dict[str, Any]:
    """Produce the 0-100 posture score together with its full derivation."""
    components = [
        _exposure(findings),
        _privilege(findings),
        _reachability(attack_paths),
        _blast_radius(findings, graph),
    ]

    total_deducted = sum(c["points_lost"] for c in components)
    score = int(round(max(0.0, 100.0 - total_deducted)))

    auto_failed = bool(attack_paths)
    grade = "F" if auto_failed else grade_for(score)

    if total_deducted == 0:
        explanation = (
            "Posture 100/100 (grade A). No exposure, privilege, reachability or "
            "blast-radius pressure was detected in this scan."
        )
    else:
        worst = max(components, key=lambda c: c["points_lost"])
        explanation = (
            f"Posture {score}/100 (grade {grade}). {total_deducted:.1f} points were "
            f"deducted across four dimensions; {worst['name'].lower()} is the largest "
            f"single contributor at -{worst['points_lost']:.1f}."
        )
        if auto_failed:
            explanation += (
                " The grade is capped at F because a confirmed path to "
                "AdministratorAccess exists."
            )

    return {
        "score": score,
        "grade": grade,
        "auto_failed": auto_failed,
        "total_deducted": round(min(total_deducted, 100.0), 2),
        "components": components,
        "explanation": explanation,
    }
