"""
Plan analysis: what does this change do to our attack surface?

A raw list of findings from a plan isn't very actionable -- most of them were
already true before the change, and a developer reading a pull request can't
tell which ones they caused. What matters is the delta:

    does applying this introduce a route to AdministratorAccess
    that does not exist today?

So the analyser scans the planned state, scans (or loads) the current state,
and reports the difference, ending in a verdict CI can act on:

    BLOCK  the change introduces at least one new path to admin
    WARN   no new path, but new findings appear
    PASS   nothing new, or the change removes risk

Only BLOCK is a build failure. A gate that fails on every new MEDIUM gets
disabled by the second week; one that fires only when someone is about to open
a route to admin keeps its credibility, and people listen when it goes off.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.graph import build_attack_graph, find_escalation_paths
from app.models import AttackPath, ScanResult
from app.pipeline import analyse_sources
from app.report.generator import build_report
from app.risk import compute_posture
from app.terraform.plan_source import PlanDataSource

VERDICT_BLOCK = "BLOCK"
VERDICT_WARN = "WARN"
VERDICT_PASS = "PASS"


def _escalation_paths(scan: ScanResult) -> List[AttackPath]:
    """Identity-to-admin routes, recomputed from the scan's findings.

    Rebuilt rather than stored so the plan and the baseline are always compared
    using the same version of the graph rules.
    """
    graph, by_resource = build_attack_graph(scan.findings)
    return find_escalation_paths(graph, by_resource)


def _path_in_scope(path: AttackPath, in_scope: set) -> bool:
    """True when every real resource on a path is described by the plan.

    A baseline path touching resources the plan says nothing about cannot be
    attributed to the change either way, so it is left out of the diff rather
    than reported as removed.
    """
    from app.graph import is_admin_sink, parse_node

    for nid in path.node_ids:
        if is_admin_sink(nid):
            continue
        account, kind, name = parse_node(nid)
        if (account, kind, name) not in in_scope:
            return False
    return True


def _path_signature(path: AttackPath) -> Tuple[str, ...]:
    """Identity of a path for diffing.

    Keyed on the node sequence rather than path_id so a chain that survives the
    change is recognised as the same chain even if the hash function changes.
    """
    return tuple(path.node_ids)


def _finding_key(f) -> Tuple[str, str, str]:
    return (f.account_id, f.resource_id, f.issue_code)


def _summarise_path(path: AttackPath) -> Dict[str, Any]:
    return {
        "path_id": path.path_id,
        "severity": path.severity.value,
        "narrative": path.narrative,
        "steps": path.steps,
        "node_ids": path.node_ids,
        "crosses_accounts": path.crosses_accounts,
        "accounts": path.accounts,
    }


def _summarise_finding(f) -> Dict[str, Any]:
    return {
        "account_id": f.account_id,
        "account_name": f.account_name,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "issue_code": f.issue_code,
        "title": f.title,
        "severity": f.base_severity.value,
        "risk_score": f.risk_score,
        "in_attack_path": f.in_attack_path,
        "remediation": f.remediation,
    }


def analyse_plan(
    plan: Dict[str, Any] | str,
    baseline: Optional[ScanResult] = None,
    account_id: str = "",
    account_name: str = "",
) -> Dict[str, Any]:
    """Scan a Terraform plan and diff it against the current state.

    `account_id` should match the account the plan targets. It matters because
    graph nodes are namespaced by account: comparing a plan scanned as account
    "" against a baseline scanned as "111111111111" would report every path as
    new. When a baseline is supplied and no account is given, the baseline's
    dominant account is used.
    """
    if baseline is not None and not account_id:
        account_id, account_name = _dominant_account(baseline)

    source = PlanDataSource(plan, account_id=account_id, account_name=account_name)
    planned = analyse_sources([source], scan_id="plan", mode="plan")

    # Internet-entry paths alone are too narrow a gate for pre-deploy checking:
    # a plan can rarely prove that a bucket leaks one specific identity's
    # credentials, so it seldom establishes an internet entry point. It can
    # prove perfectly well that a change creates an identity able to make
    # itself an administrator, and that is worth blocking on.
    planned_all = planned.attack_paths + _escalation_paths(planned)
    baseline_all = (baseline.attack_paths + _escalation_paths(baseline)) if baseline else []

    planned_paths = {_path_signature(p): p for p in planned_all}
    baseline_paths = {_path_signature(p): p for p in baseline_all}

    new_paths = [planned_paths[k] for k in planned_paths.keys() - baseline_paths.keys()]

    # A plan rarely describes a whole account. Anything it doesn't mention is
    # simply out of scope, not removed -- without this, every small pull request
    # would claim to have fixed most of the estate.
    in_scope = source.describes_resources()

    def covered(f) -> bool:
        return (f.account_id, f.resource_type, f.resource_id) in in_scope

    removed_paths = [
        baseline_paths[k]
        for k in baseline_paths.keys() - planned_paths.keys()
        if _path_in_scope(baseline_paths[k], in_scope)
    ]

    planned_findings = {_finding_key(f): f for f in planned.findings}
    baseline_findings = (
        {_finding_key(f): f for f in baseline.findings} if baseline else {}
    )
    new_findings = [planned_findings[k] for k in planned_findings.keys() - baseline_findings.keys()]
    removed_findings = [
        baseline_findings[k]
        for k in baseline_findings.keys() - planned_findings.keys()
        if covered(baseline_findings[k])
    ]

    # Posture is computed over whatever resources it was given, so the planned
    # score is only comparable to the live score when the plan covers the same
    # ground. Reporting a delta between different scopes would be a lie.
    baseline_resources = (
        {(f.account_id, f.resource_type, f.resource_id) for f in baseline.findings}
        if baseline
        else set()
    )
    partial_scope = bool(baseline_resources - in_scope)

    planned_posture = compute_posture(planned.findings, planned.attack_paths, planned.graph)
    baseline_posture = (
        compute_posture(baseline.findings, baseline.attack_paths, baseline.graph)
        if baseline
        else None
    )

    if new_paths:
        verdict = VERDICT_BLOCK
    elif new_findings:
        verdict = VERDICT_WARN
    else:
        verdict = VERDICT_PASS

    return {
        "verdict": verdict,
        "summary": _verdict_summary(verdict, new_paths, new_findings, removed_paths, removed_findings),
        "baseline_scan_id": baseline.scan_id if baseline else None,
        "posture": {
            "before": (
                baseline_posture["score"] if baseline_posture and not partial_scope else None
            ),
            "after": planned_posture["score"],
            "delta": (
                planned_posture["score"] - baseline_posture["score"]
                if baseline_posture and not partial_scope
                else None
            ),
            "grade_after": planned_posture["grade"],
            "comparable": bool(baseline_posture) and not partial_scope,
            "note": (
                "This plan describes only part of the account, so its posture score "
                "covers the planned resources alone and is not comparable to the live "
                "account score."
                if partial_scope
                else ""
            ),
        },
        "new_paths": [_summarise_path(p) for p in new_paths],
        "removed_paths": [_summarise_path(p) for p in removed_paths],
        "new_findings": sorted(
            (_summarise_finding(f) for f in new_findings),
            key=lambda d: d["risk_score"],
            reverse=True,
        ),
        "removed_findings": sorted(
            (_summarise_finding(f) for f in removed_findings),
            key=lambda d: d["risk_score"],
            reverse=True,
        ),
        "planned_report": build_report(planned),
    }


def _dominant_account(scan: ScanResult) -> Tuple[str, str]:
    """The account contributing the most findings to a scan."""
    counts: Dict[str, int] = {}
    names: Dict[str, str] = {}
    for f in scan.findings:
        if not f.account_id:
            continue
        counts[f.account_id] = counts.get(f.account_id, 0) + 1
        names[f.account_id] = f.account_name
    if not counts:
        return "", ""
    best = max(counts, key=counts.get)
    return best, names.get(best, "")


def _verdict_summary(
    verdict: str,
    new_paths: List[AttackPath],
    new_findings: List[Any],
    removed_paths: List[AttackPath],
    removed_findings: List[Any],
) -> str:
    if verdict == VERDICT_BLOCK:
        internet = sum(1 for p in new_paths if p.entry_kind == "internet")
        escalation = len(new_paths) - internet
        parts = []
        if internet:
            parts.append(f"{internet} reachable from the internet")
        if escalation:
            parts.append(f"{escalation} from a compromised identity")
        crossing = sum(1 for p in new_paths if p.crosses_accounts)
        detail = f" {crossing} cross an account boundary." if crossing else ""
        return (
            f"This change introduces {len(new_paths)} new route(s) to AdministratorAccess "
            f"({', '.join(parts)})." + detail + " Blocking."
        )
    if verdict == VERDICT_WARN:
        return (
            f"No new route to AdministratorAccess, but this change adds "
            f"{len(new_findings)} new finding(s)."
        )
    if removed_paths or removed_findings:
        return (
            f"This change removes {len(removed_paths)} attack path(s) and "
            f"{len(removed_findings)} finding(s), and introduces none."
        )
    return "No change to the attack surface."


def format_pr_comment(analysis: Dict[str, Any]) -> str:
    """Render an analysis as Markdown suitable for a pull request comment."""
    icon = {"BLOCK": "🛑", "WARN": "⚠️", "PASS": "✅"}.get(analysis["verdict"], "")
    lines = [
        f"## {icon} CloudChain: {analysis['verdict']}",
        "",
        analysis["summary"],
        "",
    ]

    posture = analysis["posture"]
    if posture["before"] is not None:
        arrow = "↓" if posture["delta"] < 0 else "↑" if posture["delta"] > 0 else "→"
        lines.append(
            f"**Posture** {posture['before']} {arrow} {posture['after']}/100 "
            f"(grade {posture['grade_after']})"
        )
    else:
        lines.append(
            f"**Posture of planned resources** {posture['after']}/100 "
            f"(grade {posture['grade_after']})"
        )
        if posture.get("note"):
            lines.append("")
            lines.append(f"_{posture['note']}_")
    lines.append("")

    for path in analysis["new_paths"]:
        lines.append("### New path to AdministratorAccess")
        if path["crosses_accounts"]:
            lines.append(f"_Crosses accounts: {' → '.join(path['accounts'])}_")
        lines.append("")
        for i, step in enumerate(path["steps"], start=1):
            lines.append(f"{i}. {step}")
        lines.append("")

    if analysis["new_findings"]:
        lines.append("### New findings")
        lines.append("")
        lines.append("| Severity | Issue | Resource | Fix |")
        lines.append("| --- | --- | --- | --- |")
        for f in analysis["new_findings"][:10]:
            lines.append(
                f"| {f['severity']} | `{f['issue_code']}` | `{f['resource_id']}` | {f['remediation']} |"
            )
        lines.append("")

    if analysis["removed_paths"]:
        lines.append(f"_This change also removes {len(analysis['removed_paths'])} existing path(s)._")

    return "\n".join(lines).rstrip() + "\n"
