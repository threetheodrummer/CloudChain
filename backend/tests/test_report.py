from app.pipeline import run_scan
from app.report.generator import build_report


def _report():
    result, drift = run_scan(mode="demo", persist=False)
    return build_report(result, drift)


def test_report_includes_posture_block():
    r = _report()
    assert "posture" in r
    assert set(r["posture"]) == {"score", "grade", "auto_failed", "deductions", "total_deducted"}
    assert 0 <= r["posture"]["score"] <= 100


def test_report_includes_graph_for_the_frontend():
    r = _report()
    assert r["graph"]["nodes"], "graph nodes must be present so the UI can draw the path"
    assert r["graph"]["edges"], "graph edges must be present"
    node_ids = {n["id"] for n in r["graph"]["nodes"]}
    for e in r["graph"]["edges"]:
        assert e["source"] in node_ids
        assert e["target"] in node_ids


def test_attack_path_node_ids_resolve_against_the_graph():
    r = _report()
    node_ids = {n["id"] for n in r["graph"]["nodes"]}
    for p in r["attack_paths"]:
        assert p["node_ids"], "path must expose its node ids"
        for nid in p["node_ids"]:
            assert nid in node_ids


def test_report_has_full_findings_list_for_download():
    r = _report()
    assert len(r["findings"]) == r["summary"]["total_findings"]
    assert len(r["top_findings"]) <= 10
    assert "description" in r["findings"][0]
