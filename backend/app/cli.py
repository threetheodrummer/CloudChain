"""
CloudChain CLI -- run a scan and print a human-readable report without
needing the API server up.

Usage:
    python -m app.cli scan --mode demo
    python -m app.cli scan --mode real --region us-east-1
    python -m app.cli history --mode demo
"""
from __future__ import annotations

import argparse
import json
import sys

from app.pipeline import run_scan
from app.report.generator import build_report
from app.storage import list_scans


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

    args = parser.parse_args()

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
