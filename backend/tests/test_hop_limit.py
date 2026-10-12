"""
Path search is bounded.

Simple-path enumeration is exponential in the worst case. These tests pin the
hop limit's behaviour: chains within the limit are still found, chains beyond
it are not, and a dense graph that would explode without a cutoff stays fast.
"""
import time

import networkx as nx

from app.graph import build_attack_graph, find_attack_paths, find_escalation_paths
from app.graph.attack_graph import admin_sink, node_id
from app.scanners import run_all_scanners
from app.sources import get_data_source


def _demo():
    findings = run_all_scanners(get_data_source("demo"))
    return build_attack_graph(findings)


def test_demo_chain_is_found_with_default_limit():
    g, by_resource = _demo()
    assert len(find_attack_paths(g, by_resource)) == 1


def test_demo_chain_needs_three_hops():
    g, by_resource = _demo()
    # The demo chain is bucket -> user -> role -> admin: three edges.
    assert find_attack_paths(g, by_resource, max_hops=2) == []
    assert len(find_attack_paths(g, by_resource, max_hops=3)) == 1


def test_limit_never_drops_below_one():
    g, by_resource = _demo()
    # A zero or negative limit must not silently disable path search.
    assert find_escalation_paths(g, by_resource, max_hops=0) == find_escalation_paths(
        g, by_resource, max_hops=1
    )


def test_dense_graph_stays_bounded():
    """A complete graph of identities has a factorial number of simple paths.

    Without a cutoff this would not finish; with one it must return quickly
    and every returned path must respect the limit.
    """
    g = nx.DiGraph()
    sink = admin_sink("111111111111")
    g.add_node(sink, type="admin_access", label="AdministratorAccess", account_id="111111111111",
               account_name="", issue_codes=[])
    users = [node_id("iam_user", f"u{i}", "111111111111") for i in range(14)]
    for u in users:
        g.add_node(u, type="iam_user", label=u, account_id="111111111111", account_name="",
                   issue_codes=[])
    for a in users:
        for b in users:
            if a != b:
                g.add_edge(a, b, relation="can_assume_cross_account")
    g.add_edge(users[-1], sink, relation="can_escalate_to_admin")

    start = time.perf_counter()
    paths = find_escalation_paths(g, {}, max_hops=4)
    elapsed = time.perf_counter() - start

    assert paths, "the bounded search should still find routes"
    assert all(len(p.node_ids) - 1 <= 4 for p in paths)
    assert elapsed < 10, f"bounded search took {elapsed:.1f}s"
