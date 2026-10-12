"""
Score CloudChain, Prowler and PMapper against Bishop Fox's IAM Vulnerable.

Ground truth (ground_truth.json) is extracted from the benchmark's own
Terraform files: one case per file, with the users, roles and policies it
creates. Cases named fp* are designed NOT to be exploitable (negatives); every
other case is exploitable (positives).

A tool detects a case if it reports privilege escalation for any principal or
policy belonging to that case:
  CloudChain  IAM_PRIVILEGE_ESCALATION_RISK or IAM_RESOURCE_ROLE_ABUSE_RISK on a
              principal of the case, or an escalation route starting at one
  Prowler     any FAIL from a check whose id contains "privilege_escalation"
              naming one of the case's policies or principals
  PMapper     a "<principal> can escalate privileges" line for one of them

Usage (from the CloudChain folder; any tool's file can be omitted):
  python experiments/iam_vulnerable/score.py \
      --cloudchain backend/results/iv_scan.json \
      --validate   backend/results/iv_validate.json \
      --prowler    backend/results/prowler-iv/<file>.csv \
      --pmapper    backend/results/iv_pmapper.txt

Writes experiments/iam_vulnerable/results.csv (per case) and prints totals.
Only case names and verdicts are written, never account ids.
"""
import argparse
import csv
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ESCALATION_CODES = {"IAM_PRIVILEGE_ESCALATION_RISK", "IAM_RESOURCE_ROLE_ABUSE_RISK"}


def load_json(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return json.loads(raw.decode(enc))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"cannot decode {path}")


def node_name(node_id):
    return node_id.rsplit(":", 1)[-1]


def cloudchain_flags(scan):
    flagged = {f["resource_id"] for f in scan.get("findings", []) if f["issue_code"] in ESCALATION_CODES}
    starts = {node_name(p["node_ids"][0]) for p in scan.get("escalation_paths", []) + scan.get("attack_paths", [])}
    return flagged | starts


def validation_by_start(val):
    out = {}
    for v in val.get("validations", []):
        start = node_name(v["hops"][0]["source"]) if v.get("hops") else ""
        out.setdefault(start, []).append(v["status"])
    return out


def prowler_flags(path):
    text = open(path, encoding="utf-8-sig").read()
    rows = list(csv.DictReader(text.splitlines(), delimiter=";"))
    names = set()
    for r in rows:
        if r.get("STATUS") == "FAIL" and "privilege_escalation" in r.get("CHECK_ID", ""):
            blob = " ".join([r.get("RESOURCE_NAME", ""), r.get("RESOURCE_UID", ""), r.get("STATUS_EXTENDED", "")])
            names.update(re.findall(r"[A-Za-z0-9+=,.@_-]+", blob))
    return names


def pmapper_flags(path):
    names = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.search(r"(?:user|role)/([A-Za-z0-9+=,.@_-]+) can escalate privileges", line)
        if m:
            names.add(m.group(1))
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cloudchain")
    ap.add_argument("--validate")
    ap.add_argument("--prowler")
    ap.add_argument("--pmapper")
    ap.add_argument("--inventory", help="text file of the user and role names that exist in the account; "
                    "cases whose principals were not created (for example, blocked by an SCP) are excluded")
    args = ap.parse_args()

    truth = json.load(open(os.path.join(HERE, "ground_truth.json")))
    tools = {}
    if args.cloudchain:
        tools["CloudChain"] = cloudchain_flags(load_json(args.cloudchain))
    if args.prowler:
        tools["Prowler"] = prowler_flags(args.prowler)
    if args.pmapper:
        tools["PMapper"] = pmapper_flags(args.pmapper)
    verdicts = validation_by_start(load_json(args.validate)) if args.validate else {}

    existing = None
    if args.inventory:
        existing = set(open(args.inventory, encoding="utf-8-sig", errors="replace").read().split())

    rows, skipped = [], []
    for case, c in sorted(truth.items()):
        if existing is not None and not (set(c["users"]) | set(c["roles"])) & existing:
            skipped.append(case)
            continue
        members = set(c["users"]) | set(c["roles"]) | set(c["policies"])
        # Role-chain cases escalate through trust policies, not through a
        # dangerous policy on the starting principal. Credit goes only for
        # flagging the starting principal; flagging the administrator policy at
        # the end of the chain does not count as finding the chain.
        if case == "privesc-AssumeRole":
            members = {"privesc-AssumeRole-start-user", "privesc-AssumeRole-starting-role"}
        if case == "sre":
            members = {"privesc-sre-user"}
        row = {"case": case, "module": c["module"], "label": c["label"]}
        for tool, flags in tools.items():
            row[tool] = "yes" if members & flags else "no"
        if verdicts:
            v = sorted({s for m in members for s in verdicts.get(m, [])})
            row["CloudChain validation"] = "/".join(v) if v else ""
        rows.append(row)

    out = os.path.join(HERE, "results.csv")
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    pos = [r for r in rows if r["label"] == "positive"]
    neg = [r for r in rows if r["label"] == "negative"]
    if skipped:
        print(f"Not deployed (excluded): {', '.join(skipped)}")
    print(f"{len(pos)} exploitable cases, {len(neg)} non-exploitable cases\n")
    print(f"{'tool':12s} {'TP':>4s} {'FN':>4s} {'FP':>4s} {'TN':>4s} {'recall':>7s} {'precision':>9s}")
    for tool in tools:
        tp = sum(r[tool] == "yes" for r in pos)
        fp = sum(r[tool] == "yes" for r in neg)
        fn, tn = len(pos) - tp, len(neg) - fp
        rec = tp / len(pos) if pos else 0
        prec = tp / (tp + fp) if tp + fp else 0
        print(f"{tool:12s} {tp:4d} {fn:4d} {fp:4d} {tn:4d} {rec:7.2f} {prec:9.2f}")
    if verdicts:
        from collections import Counter
        print("\nCloudChain validation over detected cases:",
              dict(Counter(r["CloudChain validation"] for r in rows if r.get("CloudChain") == "yes")))
    print(f"\nPer-case table: {out}")


if __name__ == "__main__":
    main()
