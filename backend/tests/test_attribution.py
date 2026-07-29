"""
CloudTrail attribution.

Attribution is inference, and the risk in shipping it is that it sounds more
certain than it is. So most of these tests are about the honest cases: not
naming a culprit when there isn't one, admitting when several events could
explain a finding, and never letting a missing trail read as "nobody did this".
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.attribution import CAUSING_EVENTS, LOOKBACK_DAYS, attribute_finding, attribute_findings
from app.demo import mock_aws
from app.models import AttributionConfidence, Finding, Severity
from app.pipeline import run_scan
from app.sources import AWSDataSource, DemoAWSDataSource, get_data_sources


@pytest.fixture(scope="module")
def scan():
    result, _ = run_scan(mode="demo", persist=False)
    return result


@pytest.fixture
def sources():
    return get_data_sources("demo")


def _finding(**overrides):
    base = dict(
        account_id=mock_aws.PROD,
        account_name="prod",
        resource_id="public-uploads-bucket",
        resource_type="s3_bucket",
        issue_code="S3_PUBLIC_ACCESS",
        title="t",
        description="d",
        base_severity=Severity.HIGH,
        remediation="fix",
    )
    base.update(overrides)
    return Finding(**base)


def _by_code(attributions, code):
    return next(a for a in attributions if a.issue_code == code)


# ------------------------------------------------------------------ mapping


def test_every_issue_code_the_scanners_emit_has_an_event_mapping(scan):
    """A finding with no mapping can never be attributed, so the gap should be
    deliberate rather than discovered later on a live account."""
    emitted = {f.issue_code for f in scan.findings}
    unmapped = emitted - set(CAUSING_EVENTS)
    assert not unmapped, f"no CloudTrail events mapped for: {sorted(unmapped)}"


def test_lookup_is_filtered_to_the_events_that_could_cause_the_finding(sources):
    """Attribution must not point at whoever merely created the resource."""
    src = DemoAWSDataSource(account_id=mock_aws.SANDBOX)
    creation_only = src.lookup_events("sandbox-scratch", CAUSING_EVENTS["S3_NO_ENCRYPTION"])
    assert creation_only == []

    everything = src.lookup_events("sandbox-scratch", [])
    assert [e["event_name"] for e in everything] == ["CreateBucket"]


# ----------------------------------------------------------------- verdicts


def test_a_single_matching_event_is_exact(sources):
    attribution = attribute_finding(
        _finding(resource_id="sg-0demo0webserver", resource_type="security_group",
                 issue_code="SG_OPEN_TO_INTERNET"),
        sources,
    )
    assert attribution.confidence is AttributionConfidence.EXACT
    assert attribution.event.event_name == "AuthorizeSecurityGroupIngress"
    assert "legacy-ci-user" in attribution.summary
    assert attribution.other_candidates == []


def test_several_matching_events_are_likely_and_all_are_returned(sources):
    """Picking the most recent is a judgement call the reader can check."""
    attribution = attribute_finding(_finding(issue_code="S3_PUBLIC_ACCESS"), sources)

    assert attribution.confidence is AttributionConfidence.LIKELY
    assert attribution.other_candidates, "the alternatives must be shown, not hidden"
    assert attribution.event.event_time > attribution.other_candidates[0].event_time
    assert "other event" in attribution.summary


def test_no_matching_event_is_unattributed_not_guessed(sources):
    attribution = attribute_finding(
        _finding(resource_id="svc-deploy-bot", resource_type="iam_user",
                 issue_code="IAM_USER_NO_MFA"),
        sources,
    )
    assert attribution.confidence is AttributionConfidence.UNATTRIBUTED
    assert attribution.event is None
    assert str(LOOKBACK_DAYS) in attribution.summary


def test_events_outside_the_retention_window_are_not_reported(sources):
    """CloudTrail LookupEvents only reaches back 90 days. Beyond that the
    honest answer is "unknown", not the oldest event we happen to have."""
    recent = attribute_finding(_finding(issue_code="S3_NO_ENCRYPTION"), sources)
    assert recent.confidence is AttributionConfidence.EXACT

    narrow = attribute_finding(_finding(issue_code="S3_NO_ENCRYPTION"), sources, lookback_days=1)
    assert narrow.confidence is AttributionConfidence.UNATTRIBUTED
    assert narrow.lookback_days == 1


def test_a_source_with_no_trail_degrades_to_unattributed():
    """No CloudTrail, or no permission to read it, must not break a scan."""

    class NoTrail(DemoAWSDataSource):
        def lookup_events(self, resource_name, event_names, lookback_days=90):
            return []

    attribution = attribute_finding(_finding(), [NoTrail(account_id=mock_aws.PROD)])
    assert attribution.confidence is AttributionConfidence.UNATTRIBUTED


def test_unmapped_issue_code_says_so_rather_than_searching(sources):
    attribution = attribute_finding(_finding(issue_code="SOME_FUTURE_CHECK"), sources)
    assert attribution.confidence is AttributionConfidence.UNATTRIBUTED
    assert "SOME_FUTURE_CHECK" in attribution.summary


# ------------------------------------------------------------------- actors


def test_assumed_role_sessions_are_named_not_just_the_role(sources):
    """'TerraformDeployRole/ci-run-8821' identifies a pipeline run; the bare
    role name would not."""
    attribution = attribute_finding(
        _finding(resource_id="svc-deploy-bot", resource_type="iam_user",
                 issue_code="IAM_PRIVILEGE_ESCALATION_RISK"),
        sources,
    )
    assert attribution.confidence is AttributionConfidence.EXACT
    assert "TerraformDeployRole/ci-run-8821" in attribution.summary
    assert attribution.event.actor_type == "AssumedRole"


def test_attribution_records_the_full_forensic_detail(sources):
    attribution = attribute_finding(_finding(issue_code="S3_NO_ENCRYPTION"), sources)
    event = attribution.event

    assert event.event_id
    assert event.source_ip == "203.0.113.47"
    assert event.user_agent
    assert event.request_parameters.get("bucketName") == "public-uploads-bucket"


# ------------------------------------------------------------- multi-account


def test_each_finding_is_attributed_against_its_own_account(sources):
    """The cross-account trust was opened in shared-services, by an identity
    in shared-services -- not by anyone in prod."""
    attribution = attribute_finding(
        _finding(
            account_id=mock_aws.SHARED,
            account_name="shared-services",
            resource_id="OrgDeploymentRole",
            resource_type="iam_role",
            issue_code="IAM_CROSS_ACCOUNT_TRUST",
        ),
        sources,
    )
    assert attribution.confidence is AttributionConfidence.EXACT
    assert attribution.event.event_name == "UpdateAssumeRolePolicy"
    assert mock_aws.SHARED in attribution.event.actor_arn


def test_events_do_not_leak_between_accounts():
    """A resource name in one account must never match a trail in another."""
    sandbox_only = [DemoAWSDataSource(account_id=mock_aws.SANDBOX)]
    attribution = attribute_finding(
        _finding(account_id=mock_aws.SANDBOX, resource_id="public-uploads-bucket"),
        sandbox_only,
    )
    assert attribution.confidence is AttributionConfidence.UNATTRIBUTED


# -------------------------------------------------------------- end to end


def test_the_demo_scan_attributes_most_of_its_findings(scan, sources):
    attributions = attribute_findings(scan.findings, sources)
    traced = [a for a in attributions if a.confidence is not AttributionConfidence.UNATTRIBUTED]
    assert len(traced) >= 6

    for a in attributions:
        assert a.summary
        assert a.finding_id
        if a.confidence is AttributionConfidence.UNATTRIBUTED:
            assert a.event is None
        else:
            assert a.event is not None


def test_the_bucket_that_starts_the_attack_path_names_its_culprit(scan, sources):
    """The single most useful sentence the tool produces."""
    attributions = attribute_findings(scan.findings, sources)
    entry = _by_code(attributions, "S3_SENSITIVE_OBJECT_EXPOSED")

    assert entry.confidence is not AttributionConfidence.UNATTRIBUTED
    assert "public-uploads-bucket" in entry.summary
    assert entry.event.actor_arn
