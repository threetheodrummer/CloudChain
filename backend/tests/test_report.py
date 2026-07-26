from app.pipeline import run_scan
from app.report.generator import build_report


def _report():
    result, drift = run_scan(mode="demo", persist=False)
    return build_report(result, drift)


def test_report_includes_posture_block():
    r = _report()
    assert "posture" in r
    assert set(r["posture"]) == {
        "score",
        "grade",
        "auto_failed",
        "total_deducted",
        "components",
        "explanation",
    }
    assert 0 <= r["posture"]["score"] <= 100


def test_posture_components_carry_their_own_derivation():
    """The frontend renders these directly -- if a component ever ships without
    its method or factors, the drill-down silently becomes an empty panel."""
    r = _report()
    for c in r["posture"]["components"]:
        assert {
            "key", "name", "weight", "raw", "points_lost", "headline", "method", "factors",
        } <= set(c)
        for f in c["factors"]:
            assert set(f) == {"label", "detail", "contribution"}


def test_findings_carry_their_score_breakdown():
    r = _report()
    top = r["top_findings"][0]
    assert top["score_breakdown"], "every scored finding must explain its own number"
    assert top["score_breakdown"][0]["label"].startswith("Base severity")


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
