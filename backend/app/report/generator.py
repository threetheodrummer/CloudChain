"""
Assembles the final human-facing report from a ScanResult (+ optional
DriftReport). Used by the API, the background job runner and the CLI's
pretty-printed output, so they never drift apart.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from app.models import DriftReport, ScanResult
from app.risk import compute_posture


def _account_rollup(scan: ScanResult):
    """(account_id, account_name, finding_count), worst-hit account first."""
    counts: Dict[str, int] = {}
    names: Dict[str, str] = {}
    for f in scan.findings:
        if not f.account_id:
            continue
        counts[f.account_id] = counts.get(f.account_id, 0) + 1
        names[f.account_id] = f.account_name or f.account_id
    return [
        (aid, names[aid], n)
        for aid, n in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    ]


def _finding_dict(f) -> Dict[str, Any]:
    return {
        "rank": f.rank,
        "risk_score": f.risk_score,
        "in_attack_path": f.in_attack_path,
        "account_id": f.account_id,
        "account_name": f.account_name,
        "severity": f.base_severity.value,
        "issue_code": f.issue_code,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        # The multiplier chain behind risk_score, so the UI can defend the ranking.
        "score_breakdown": [sf.model_dump() for sf in f.score_breakdown],
    }


def build_report(scan: ScanResult, drift: Optional[DriftReport] = None) -> Dict[str, Any]:
    # The graph is passed through so the posture engine can measure blast radius
    # (how much of the estate an attacker reaches from the exposed entry points).
    posture = compute_posture(scan.findings, scan.attack_paths, scan.graph)

    return {
        "scan_id": scan.scan_id,
        "mode": scan.mode,
        "timestamp": scan.timestamp.isoformat(),
        "posture": posture,
        "accounts": [
            {"id": aid, "name": name, "findings": count}
            for aid, name, count in _account_rollup(scan)
        ],
        "summary": {
            "total_findings": len(scan.findings),
            "by_severity": scan.summary,
            "attack_paths_found": len(scan.attack_paths),
            "accounts_scanned": len({f.account_id for f in scan.findings if f.account_id}),
            "cross_account_paths": sum(1 for p in scan.attack_paths if p.crosses_accounts),
        },
        "attack_paths": [
            {
                "path_id": p.path_id,
                "severity": p.severity.value,
                "narrative": p.narrative,
                "steps": p.steps,
                "node_ids": p.node_ids,
                "crosses_accounts": p.crosses_accounts,
                "accounts": p.accounts,
            }
            for p in scan.attack_paths
        ],
        # Graph is included so the frontend can draw the attack path without a
        # second request.
        "graph": {
            "nodes": [
                {"id": n.id, "type": n.type, "label": n.label, "attributes": n.attributes}
                for n in scan.graph.nodes
            ],
            "edges": [
                {"source": e.source, "target": e.target, "relation": e.relation}
                for e in scan.graph.edges
            ],
        },
        # Top 10 drives the dashboard table; the full list backs the downloadable report.
        "top_findings": [_finding_dict(f) for f in scan.findings[:10]],
        "findings": [_finding_dict(f) for f in scan.findings],
        "drift": None
        if drift is None
        else {
            "previous_scan_id": drift.previous_scan_id,
            "new_findings": [e.model_dump() for e in drift.new_findings],
            "resolved_findings": [e.model_dump() for e in drift.resolved_findings],
            "unchanged_count": drift.unchanged_count,
        },
    }
