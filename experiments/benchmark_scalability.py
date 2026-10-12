"""
Scalability: analysis time against organisation size, with and without the hop limit.

Run from backend/:
    python ../experiments/benchmark_scalability.py

Measures the full offline pipeline (scanners over the data source, graph
construction, attack and escalation path search, scoring, posture) on seeded
synthetic organisations. AWS API latency is excluded on purpose: it depends on
the network and the account's throttling, not on CloudChain.

Writes experiments/results/scalability.csv.
"""
from __future__ import annotations

import csv
import os
import signal
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, os.path.dirname(__file__))

from app.pipeline import analyse_sources  # noqa: E402
from app.report.generator import build_report  # noqa: E402
from app.storage.drift import compare_scans  # noqa: E402
from synthetic_org import make_org  # noqa: E402

SIZES = [30, 100, 300, 1000, 3000, 10000]
REPEATS = 3
TIMEOUT_S = 120
UNBOUNDED = 10_000  # effectively no cutoff


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


def run_once(n, max_hops):
    org = make_org(n, n_accounts=3, seed=42)
    t0 = time.perf_counter()
    result = analyse_sources(org, scan_id="bench", mode="real", max_hops=max_hops)
    build_report(result, compare_scans(result, None))
    return time.perf_counter() - t0, result


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    signal.signal(signal.SIGALRM, _alarm)

    for n in SIZES:
        for label, hops in (("hop_limit_6", 6), ("unbounded", UNBOUNDED)):
            times, result = [], None
            try:
                for _ in range(REPEATS):
                    signal.alarm(TIMEOUT_S)
                    t, result = run_once(n, hops)
                    signal.alarm(0)
                    times.append(t)
                median = statistics.median(times)
                status = "ok"
            except Timeout:
                signal.alarm(0)
                median, status = float("nan"), f"timeout>{TIMEOUT_S}s"
            row = {
                "identities": n,
                "search": label,
                "median_seconds": round(median, 4),
                "status": status,
                "findings": len(result.findings) if result else "",
                "graph_nodes": len(result.graph.nodes) if result else "",
                "graph_edges": len(result.graph.edges) if result else "",
                "attack_paths": len(result.attack_paths) if result else "",
                "escalation_paths": len(result.escalation_paths) if result else "",
                "max_path_hops": (
                    max((len(p.node_ids) - 1 for p in result.attack_paths + result.escalation_paths), default=0)
                    if result else ""
                ),
            }
            rows.append(row)
            print(row, flush=True)

    with open(os.path.join(out_dir, "scalability.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
