"""
Attribution: who changed this, and when.

Drift tells you a finding is new. The next question everyone asks -- and that
no CSPM answers -- is *who did it*. "This bucket became public at 14:22 on
Tuesday via PutBucketAcl by legacy-ci-user from 203.0.113.47" is a different
kind of output from "this bucket is public". One is a fact about your
infrastructure; the other is the start of a conversation with a person.

This matters more than finding counts to anyone running a security programme,
because it's what turns posture management into something with a feedback loop:
you can see which team, pipeline or individual keeps reopening the same hole,
and mean-time-to-detect becomes measurable.

How it works
------------
Each issue code maps to the set of CloudTrail management events that could have
produced it. For a given finding, CloudChain looks those events up against the
resource and reports the most recent one.

Why attribution is labelled, not asserted
-----------------------------------------
This is inference. CloudTrail records that an API call happened, not that this
particular call produced this particular finding state. A bucket might have
been made public, made private, and made public again; a role's policy might
have been attached by one actor and later modified by another. So every result
carries a confidence:

    EXACT         one candidate event touches this resource -- unambiguous
    LIKELY        several candidates; the most recent is reported, the rest
                  are returned alongside it so the reader can judge
    UNATTRIBUTED  nothing found

UNATTRIBUTED is common and is not a failure. CloudTrail's LookupEvents API
reads the 90-day event history, not a trail's S3 archive, so anything older is
genuinely unanswerable this way. Reporting "no event found" is correct; naming
a plausible culprit would not be.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from app.models import (
    AttributionConfidence,
    Finding,
    FindingAttribution,
    TrailEvent,
)
from app.sources import AWSDataSource

# CloudTrail's LookupEvents reads the 90-day event history. Anything older
# needs the trail's S3 archive and Athena, which is out of scope here.
LOOKBACK_DAYS = 90

# Issue code -> the management events that could have produced it.
#
# Deliberately narrow. Including every vaguely related event (CreateBucket for
# every S3 finding, say) would raise confidence artificially while pointing at
# whoever happened to create the resource rather than whoever broke it.
CAUSING_EVENTS: Dict[str, tuple] = {
    "S3_PUBLIC_ACCESS": (
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeletePublicAccessBlock",
        "PutPublicAccessBlock",
    ),
    "S3_SENSITIVE_OBJECT_EXPOSED": (
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeletePublicAccessBlock",
        "PutObject",
    ),
    "S3_NO_ENCRYPTION": ("DeleteBucketEncryption", "PutBucketEncryption"),
    "S3_NO_VERSIONING": ("PutBucketVersioning",),
    "IAM_OVERPERMISSIVE_POLICY": (
        "AttachUserPolicy",
        "PutUserPolicy",
        "AttachRolePolicy",
        "PutRolePolicy",
        "CreatePolicyVersion",
    ),
    "IAM_ROLE_ADMIN_ACCESS": (
        "AttachRolePolicy",
        "PutRolePolicy",
        "CreatePolicyVersion",
    ),
    "IAM_PRIVILEGE_ESCALATION_RISK": (
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreatePolicyVersion",
    ),
    "IAM_CROSS_ACCOUNT_TRUST": ("UpdateAssumeRolePolicy", "CreateRole"),
    "IAM_USER_NO_MFA": ("DeactivateMFADevice", "CreateUser"),
    "IAM_STALE_ACCESS_KEY": ("CreateAccessKey",),
    "IAM_WEAK_PASSWORD_POLICY": ("UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"),
    "SG_OPEN_TO_INTERNET": ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"),
}

Sources = Union[AWSDataSource, Mapping[str, AWSDataSource], Sequence[AWSDataSource]]


def _index_sources(sources: Sources) -> Dict[str, AWSDataSource]:
    if isinstance(sources, Mapping):
        return dict(sources)
    if isinstance(sources, AWSDataSource):
        return {sources.account_id: sources}
    return {s.account_id: s for s in sources}


def _to_event(raw: Dict[str, Any]) -> TrailEvent:
    when = raw.get("event_time")
    if isinstance(when, str):
        when = datetime.fromisoformat(when)
    if when is not None and when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)

    return TrailEvent(
        event_id=raw.get("event_id", ""),
        event_name=raw.get("event_name", ""),
        event_time=when or datetime.now(timezone.utc),
        actor_arn=raw.get("actor_arn", "unknown"),
        actor_type=raw.get("actor_type", "Unknown"),
        source_ip=raw.get("source_ip", ""),
        user_agent=raw.get("user_agent", ""),
        request_parameters=raw.get("request_parameters", {}) or {},
    )


def _actor_label(event: TrailEvent) -> str:
    """A readable name for whoever made the call.

    An assumed-role ARN carries the session name, which is usually far more
    useful than the role itself -- 'TerraformDeployRole/ci-run-8821' identifies
    a pipeline run, not just a role.
    """
    arn = event.actor_arn
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1]
    if ":user/" in arn:
        return arn.split(":user/", 1)[1]
    if arn.endswith(":root"):
        return "the account root user"
    return arn


def attribute_finding(
    finding: Finding,
    sources: Sources,
    lookback_days: int = LOOKBACK_DAYS,
) -> FindingAttribution:
    """Find the API call that most likely produced this finding."""
    by_account = _index_sources(sources)
    source = by_account.get(finding.account_id) or next(iter(by_account.values()), None)
    event_names = CAUSING_EVENTS.get(finding.issue_code, ())

    base = dict(
        finding_id=finding.id,
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        issue_code=finding.issue_code,
        lookback_days=lookback_days,
    )

    if source is None:
        return FindingAttribution(
            **base,
            confidence=AttributionConfidence.UNATTRIBUTED,
            summary=f"No data source available for account {finding.account_id or 'unknown'}.",
        )

    if not event_names:
        return FindingAttribution(
            **base,
            confidence=AttributionConfidence.UNATTRIBUTED,
            summary=(
                f"No CloudTrail events are mapped to {finding.issue_code}, so this "
                f"finding cannot be attributed to a specific API call."
            ),
        )

    raw_events = source.lookup_events(finding.resource_id, event_names, lookback_days)
    if not raw_events:
        return FindingAttribution(
            **base,
            confidence=AttributionConfidence.UNATTRIBUTED,
            summary=(
                f"No {' / '.join(event_names)} event touching '{finding.resource_id}' "
                f"appears in the last {lookback_days} days. The change predates "
                f"CloudTrail's lookup window, or the trail doesn't cover it."
            ),
        )

    events = [_to_event(e) for e in raw_events]
    events.sort(key=lambda e: e.event_time, reverse=True)
    primary, others = events[0], events[1:]

    confidence = (
        AttributionConfidence.EXACT if not others else AttributionConfidence.LIKELY
    )

    when = primary.event_time.strftime("%d %b %Y at %H:%M UTC")
    origin = f" from {primary.source_ip}" if primary.source_ip else ""
    summary = (
        f"{primary.event_name} on '{finding.resource_id}' by "
        f"{_actor_label(primary)}{origin} on {when}."
    )
    if others:
        summary += (
            f" {len(others)} other event(s) could also explain this finding; the most "
            f"recent is reported."
        )

    return FindingAttribution(
        **base,
        confidence=confidence,
        summary=summary,
        event=primary,
        other_candidates=others,
    )


def attribute_findings(
    findings: Sequence[Finding],
    sources: Sources,
    lookback_days: int = LOOKBACK_DAYS,
) -> List[FindingAttribution]:
    return [attribute_finding(f, sources, lookback_days) for f in findings]
