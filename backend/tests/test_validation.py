"""
Tests for attack path validation.

Two things are being protected here. First, that verdicts are correct --
a live chain confirms, a fixed one refutes. Second, and more important, that
validation can never mutate the account it is auditing. That guarantee is
enforced structurally (validation is written against the read-only
AWSDataSource) and asserted here, so it can't rot.
"""
import pytest

from app.demo import mock_aws
from app.graph import build_attack_graph, find_attack_paths, to_scan_graph
from app.models import VerdictStatus
from app.pipeline import run_scan
from app.sources import AWSDataSource, DemoAWSDataSource
from app.validation import READ_ONLY_METHODS, validate_path, validate_paths


@pytest.fixture
def demo_scan():
    result, _ = run_scan(mode="demo", persist=False)
    return result


# ------------------------------------------------------------------- safety


class _TripwireSource(DemoAWSDataSource):
    """Records every data-source method validation touches."""

    def __init__(self):
        super().__init__()
        self.touched = []

    def __getattribute__(self, name):
        if not name.startswith("_") and name != "touched":
            try:
                object.__getattribute__(self, "touched").append(name)
            except AttributeError:
                pass
        return object.__getattribute__(self, name)


def test_validation_only_calls_read_only_methods(demo_scan):
    """The safety claim, asserted rather than asserted-in-a-docstring.

    If someone later adds a mutating call to a verifier, this fails.
    """
    source = _TripwireSource()
    validate_paths(demo_scan.attack_paths, source, demo_scan.graph)

    touched = {m for m in source.touched if callable(getattr(DemoAWSDataSource, m, None))}
    assert touched, "validation should have called something"
    assert touched <= READ_ONLY_METHODS, (
        f"validation called non-allowlisted method(s): {sorted(touched - READ_ONLY_METHODS)}"
    )


def test_allowlist_only_contains_real_data_source_methods():
    """Guards against the allowlist drifting away from the interface."""
    for name in READ_ONLY_METHODS:
        assert hasattr(AWSDataSource, name), f"{name} is not on AWSDataSource"


def test_no_object_contents_are_ever_read(demo_scan):
    """The S3 hop confirms a key is listable; it must never fetch the body."""
    source = _TripwireSource()
    validate_paths(demo_scan.attack_paths, source, demo_scan.graph)
    assert "get_object" not in source.touched
    assert not any("download" in m for m in source.touched)


# ------------------------------------------------------------------ verdicts


def test_demo_path_is_fully_confirmed(demo_scan):
    assert demo_scan.attack_paths, "demo account should produce a path"
    v = validate_path(demo_scan.attack_paths[0], DemoAWSDataSource(), demo_scan.graph)

    assert v.status is VerdictStatus.CONFIRMED
    assert v.read_only is True
    assert all(h.status is VerdictStatus.CONFIRMED for h in v.hops)
    assert len(v.hops) == len(demo_scan.attack_paths[0].node_ids) - 1


def test_every_hop_ships_the_api_calls_behind_it(demo_scan):
    """A verdict with no evidence is just another assertion."""
    v = validate_path(demo_scan.attack_paths[0], DemoAWSDataSource(), demo_scan.graph)
    for hop in v.hops:
        assert hop.calls, f"hop {hop.index} produced a verdict with no evidence"
        for call in hop.calls:
            assert ":" in call.api, "api should be namespaced like s3:GetBucketAcl"
            assert call.observed, "every call must record what came back"


def test_confirmed_summary_does_not_claim_exploitation(demo_scan):
    v = validate_path(demo_scan.attack_paths[0], DemoAWSDataSource(), demo_scan.graph)
    lowered = v.summary.lower()
    assert "no escalation was performed" in lowered
    for overclaim in ("exploited", "we ran", "took over"):
        assert overclaim not in lowered


def test_path_is_refuted_once_the_bucket_is_locked_down(demo_scan, monkeypatch):
    """Remediate the entry point; the same path must now come back REFUTED.

    This is the behaviour that makes validation worth having -- a stale path
    should be provably stale, not quietly kept on the dashboard.
    """
    path = demo_scan.attack_paths[0]

    class Fixed(DemoAWSDataSource):
        def is_bucket_acl_public(self, bucket):
            return False

        def is_bucket_policy_public(self, bucket):
            return False

    v = validate_path(path, Fixed(), demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED
    assert "no longer" in v.summary or "broken at hop" in v.summary


def test_path_is_refuted_when_passrole_is_revoked(demo_scan):
    class NoPassRole(DemoAWSDataSource):
        def get_policy_statements(self, policy_name):
            return [
                (a, r)
                for a, r in super().get_policy_statements(policy_name)
                if a != "iam:PassRole"
            ]

    v = validate_path(demo_scan.attack_paths[0], NoPassRole(), demo_scan.graph)
    assert v.status is VerdictStatus.REFUTED


def test_unresolvable_policies_are_unverifiable_not_confirmed(demo_scan):
    """Missing information must never be read as a passing verdict."""

    class Blind(DemoAWSDataSource):
        def get_policy_statements(self, policy_name):
            return []  # e.g. AccessDenied in a real account

    v = validate_path(demo_scan.attack_paths[0], Blind(), demo_scan.graph)
    assert v.status is VerdictStatus.UNVERIFIABLE
    assert "unproven" in v.summary


def test_missing_graph_degrades_to_unverifiable_not_confirmed(demo_scan):
    """Without edge relations there is nothing to verify against."""
    v = validate_path(demo_scan.attack_paths[0], DemoAWSDataSource(), None)
    assert v.status is VerdictStatus.UNVERIFIABLE


def test_validation_is_reproducible_by_hand(demo_scan):
    """Each call carries the aws-cli equivalent so a reviewer can re-run it."""
    v = validate_path(demo_scan.attack_paths[0], DemoAWSDataSource(), demo_scan.graph)
    cli = [c.cli for hop in v.hops for c in hop.calls if c.cli]
    assert cli, "at least some calls should be reproducible from the CLI"
    assert all(c.startswith("aws ") for c in cli)


def test_validate_paths_handles_an_account_with_no_paths():
    graph, by_resource = build_attack_graph([])
    paths = find_attack_paths(graph, by_resource)
    assert validate_paths(paths, DemoAWSDataSource(), to_scan_graph(graph)) == []
