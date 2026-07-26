"""
CloudChain CLI -- run a scan and print a human-readable report without
needing the API server up.

Usage:
    python -m app.cli scan --mode demo
    python -m app.cli scan --mode real --region us-east-1
    python -m app.cli history --mode demo
    python -m app.cli plan --file plan.json --account 111111111111

The `plan` subcommand is the CI entry point: it exits 1 when a Terraform plan
introduces a new route to AdministratorAccess, and 0 otherwise, so it can be
dropped straight into a pipeline step.
"""
from __future__ import annotations

import argparse
import json
import sys

from app.pipeline import run_scan
from app.report.generator import build_report
from app.storage import get_scan, list_scans
from app.terraform import analyse_plan
from app.terraform.analyzer import format_pr_comment


def _print_report(report: dict) -> None:
    print(f"\nCloudChain scan {report['scan_id']} ({report['mode']} mode)")
    print(f"Timestamp: {report['timestamp']}")
    print(f"Total findings: {report['summary']['total_findings']}  by severity: {report['summary']['by_severity']}")
    print(f"Attack paths found: {report['summary']['attack_paths_found']}")

    if report["attack_paths"]:
        print("\n=== ATTACK PATHS ===")
        for p in report["attack_paths"]:
            print(f"\n[{p['severity']}] {p['path_id']}")
            print(f"  {p['narrative']}")

    print("\n=== TOP FINDINGS (risk-ranked) ===")
    for f in report["top_findings"]:
        chain_marker = " [ON ATTACK PATH]" if f["in_attack_path"] else ""
        print(
            f"#{f['rank']:<3} score={f['risk_score']:<7} [{f['severity']:<8}] "
            f"{f['issue_code']:<30} {f['resource_id']}{chain_marker}"
        )
        print(f"      -> {f['remediation']}")

    if report.get("drift"):
        d = report["drift"]
        print("\n=== DRIFT vs previous scan ===")
        print(f"  New: {len(d['new_findings'])}  Resolved: {len(d['resolved_findings'])}  Unchanged: {d['unchanged_count']}")
        for e in d["new_findings"]:
            print(f"  + NEW      {e['issue_code']} on {e['resource_id']}")
        for e in d["resolved_findings"]:
            print(f"  - RESOLVED {e['issue_code']} on {e['resource_id']}")


def _print_plan_analysis(analysis: dict) -> None:
    verdict = analysis["verdict"]
    print(f"\nCloudChain plan check: {verdict}")
    print(analysis["summary"])

    posture = analysis["posture"]
    if posture["before"] is not None:
        print(
            f"\nPosture: {posture['before']} -> {posture['after']}/100 "
            f"(grade {posture['grade_after']}, delta {posture['delta']:+d})"
        )
    else:
        print(
            f"\nPosture of planned resources: {posture['after']}/100 "
            f"(grade {posture['grade_after']})"
        )
        if posture.get("note"):
            print(f"  {posture['note']}")

    for path in analysis["new_paths"]:
        print("\n=== NEW ROUTE TO ADMINISTRATORACCESS ===")
        if path["crosses_accounts"]:
            print(f"  crosses accounts: {' -> '.join(path['accounts'])}")
        for i, step in enumerate(path["steps"], start=1):
            print(f"  {i}. {step}")

    if analysis["new_findings"]:
        print("\n=== NEW FINDINGS ===")
        for f in analysis["new_findings"]:
            print(f"  [{f['severity']:<8}] {f['issue_code']:<32} {f['resource_id']}")
            print(f"      -> {f['remediation']}")

    if analysis["removed_paths"] or analysis["removed_findings"]:
        print(
            f"\nThis change also removes {len(analysis['removed_paths'])} path(s) "
            f"and {len(analysis['removed_findings'])} finding(s)."
        )


def _run_plan(args) -> int:
    """Pre-apply check. Returns a process exit code so CI can gate on it."""
    with open(args.file, "r", encoding="utf-8") as fh:
        plan = json.load(fh)

    baseline = None
    if args.baseline:
        baseline = get_scan(args.baseline)
        if baseline is None:
            print(f"No scan found with id {args.baseline!r}", file=sys.stderr)
            return 2
    else:
        recent = list_scans(limit=1)
        baseline = recent[0] if recent else None

    analysis = analyse_plan(
        plan,
        baseline=baseline,
        account_id=args.account,
        account_name=args.account_name,
    )

    if args.format == "json":
        print(json.dumps(analysis, indent=2, default=str))
    elif args.format == "markdown":
        print(format_pr_comment(analysis))
    else:
        _print_plan_analysis(analysis)

    # Only a new route to admin fails the build. Warnings are printed and
    # allowed through: a gate that fails on every new MEDIUM gets switched off,
    # and then it protects nothing.
    return 1 if analysis["verdict"] == "BLOCK" else 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="cloudchain")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a scan and print the report")
    scan_p.add_argument("--mode", choices=["demo", "real"], default="demo")
    scan_p.add_argument("--region", default=None)
    scan_p.add_argument("--json", action="store_true", help="Print raw JSON instead of a formatted report")

    hist_p = sub.add_parser("history", help="List past scans")
    hist_p.add_argument("--mode", choices=["demo", "real"], default=None)
    hist_p.add_argument("--limit", type=int, default=20)

    plan_p = sub.add_parser(
        "plan",
        help="Check a Terraform plan before apply; exits 1 if it opens a route to admin",
    )
    plan_p.add_argument("--file", required=True, help="Output of `terraform show -json tfplan`")
    plan_p.add_argument("--account", default="", help="Account id the plan targets")
    plan_p.add_argument("--account-name", default="", help="Friendly name for that account")
    plan_p.add_argument("--baseline", default=None, help="Scan id to diff against (default: latest)")
    plan_p.add_argument("--format", choices=["text", "markdown", "json"], default="text")

    args = parser.parse_args()

    if args.command == "plan":
        return _run_plan(args)

    if args.command == "scan":
        result, drift = run_scan(mode=args.mode, region=args.region)
        report = build_report(result, drift)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            _print_report(report)

    elif args.command == "history":
        scans = list_scans(mode=args.mode, limit=args.limit)
        if not scans:
            print("No scans recorded yet.")
            return
        for s in scans:
            print(f"{s.timestamp.isoformat()}  {s.scan_id:<20} mode={s.mode:<5} findings={len(s.findings)}")


if __name__ == "__main__":
    sys.exit(main())
