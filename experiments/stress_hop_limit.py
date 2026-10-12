"""
Worst case for path search: a densely connected trust mesh.

Realistic organisations produce shallow graphs (see benchmark_scalability.py),
where the hop limit changes nothing. This shows what it protects against: n
identities that can all reach each other, one of which can escalate to admin.
The number of simple paths grows factorially with n.

Run from backend/:  python ../experiments/stress_hop_limit.py
Writes experiments/results/stress_hop_limit.csv.
"""
import csv, os, signal, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import networkx as nx  # noqa: E402
from app.graph.attack_graph import admin_sink, find_escalation_paths, node_id  # noqa: E402

TIMEOUT_S = 60


class Timeout(Exception):
    pass


def _alarm(*_):
    raise Timeout()


def mesh(n):
    g = nx.DiGraph()
    acct = "111111111111"
    sink = admin_sink(acct)
    g.add_node(sink, type="admin_access", label="AdministratorAccess", account_id=acct, account_name="", issue_codes=[])
    ids = [node_id("iam_role", f"r{i}", acct) for i in range(n)]
    for x in ids:
        g.add_node(x, type="iam_role", label=x, account_id=acct, account_name="", issue_codes=[])
    for a in ids:
        for b in ids:
            if a != b:
                g.add_edge(a, b, relation="can_assume_cross_account")
    g.add_edge(ids[-1], sink, relation="can_escalate_to_admin")
    return g


def main():
    signal.signal(signal.SIGALRM, _alarm)
    rows = []
    for n in (6, 7, 8, 9, 10, 11, 12):
        g = mesh(n)
        for label, hops in (("hop_limit_4", 4), ("hop_limit_6", 6), ("unbounded", 10_000)):
            signal.alarm(TIMEOUT_S)
            t0 = time.perf_counter()
            try:
                paths = find_escalation_paths(g, {}, max_hops=hops)
                signal.alarm(0)
                rows.append({"identities": n, "search": label, "seconds": round(time.perf_counter() - t0, 4),
                             "paths": len(paths), "status": "ok"})
            except Timeout:
                signal.alarm(0)
                rows.append({"identities": n, "search": label, "seconds": "", "paths": "",
                             "status": f"timeout>{TIMEOUT_S}s"})
            print(rows[-1], flush=True)
    out = os.path.join(os.path.dirname(__file__), "results", "stress_hop_limit.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


if __name__ == "__main__":
    main()
