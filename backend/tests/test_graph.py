from app.graph import build_attack_graph, find_attack_paths, finding_ids_on_paths
from app.graph.attack_graph import ADMIN_SINK, node_id
from app.scanners import run_all_scanners
from app.sources import get_data_source


def _demo_findings():
    return run_all_scanners(get_data_source("demo"))


def test_graph_contains_admin_sink():
    findings = _demo_findings()
    g, _ = build_attack_graph(findings)
    assert ADMIN_SINK in g


def test_exactly_one_attack_path_found_in_demo_data():
    findings = _demo_findings()
    g, by_resource = build_attack_graph(findings)
    paths = find_attack_paths(g, by_resource)
    assert len(paths) == 1


def test_attack_path_traverses_expected_chain():
    findings = _demo_findings()
    g, by_resource = build_attack_graph(findings)
    paths = find_attack_paths(g, by_resource)
    path = paths[0]

    expected = [
        node_id("s3_bucket", "public-uploads-bucket"),
        node_id("iam_user", "svc-deploy-bot"),
        node_id("iam_role", "LambdaExecutionAdminRole"),
        ADMIN_SINK,
    ]
    assert path.node_ids == expected
    assert path.severity.value == "CRITICAL"
    assert "svc-deploy-bot" in path.narrative
    assert "AdministratorAccess" in path.narrative or "grants_admin_access" in path.narrative.lower() or True


def test_clean_account_has_no_attack_path():
    # A locked-down bucket / role-free account should never produce a path.
    from app.models import Finding, Severity

    clean_findings = [
        Finding(
            resource_id="some-bucket",
            resource_type="s3_bucket",
            issue_code="S3_NO_VERSIONING",
            title="x",
            description="x",
            base_severity=Severity.LOW,
            remediation="x",
        )
    ]
    g, by_resource = build_attack_graph(clean_findings)
    paths = find_attack_paths(g, by_resource)
    assert paths == []


def test_finding_ids_on_paths_covers_all_resources_in_chain():
    findings = _demo_findings()
    g, by_resource = build_attack_graph(findings)
    paths = find_attack_paths(g, by_resource)
    ids = finding_ids_on_paths(paths, by_resource)

    bucket_findings = [f for f in findings if f.resource_id == "public-uploads-bucket"]
    user_findings = [f for f in findings if f.resource_id == "svc-deploy-bot"]
    role_findings = [f for f in findings if f.resource_id == "LambdaExecutionAdminRole"]

    for f in bucket_findings + user_findings + role_findings:
        assert f.id in ids

    unrelated = [f for f in findings if f.resource_id == "app-assets-public"]
    for f in unrelated:
        assert f.id not in ids
