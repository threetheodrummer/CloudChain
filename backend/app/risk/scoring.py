"""
Contextual risk scoring.

Prowler/ScoutSuite assign each check a fixed severity label regardless of
context -- a public-but-empty static website bucket and a public bucket
leaking admin credentials both just say "HIGH". CloudChain instead scores
findings using the context available from this scan:

    score = base_severity_weight
          * (1.5 if internet_facing else 1)
          * (1.5 if sensitive else 1)
          * (2.5 if the finding sits on a confirmed attack path else 1)

The attack-path multiplier is intentionally the largest factor: a finding
that's part of a chain proven (by the graph engine) to reach
AdministratorAccess is a fundamentally different risk than the same
finding in isolation, and the score should reflect that rather than
capping out at a shared "HIGH"/"CRITICAL" label.
"""
from __future__ import annotations

from typing import List, Set

from app.models import Finding, ScoredFinding, Severity

BASE_SEVERITY_WEIGHTS = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 6.0,
    Severity.CRITICAL: 10.0,
}

INTERNET_FACING_MULTIPLIER = 1.5
SENSITIVE_MULTIPLIER = 1.5
ATTACK_PATH_MULTIPLIER = 2.5


def score_finding(finding: Finding, in_attack_path: bool) -> float:
    score = BASE_SEVERITY_WEIGHTS[finding.base_severity]
    if finding.internet_facing:
        score *= INTERNET_FACING_MULTIPLIER
    if finding.sensitive:
        score *= SENSITIVE_MULTIPLIER
    if in_attack_path:
        score *= ATTACK_PATH_MULTIPLIER
    return round(score, 2)


def score_findings(findings: List[Finding], finding_ids_in_path: Set[str]) -> List[ScoredFinding]:
    scored: List[ScoredFinding] = []
    for f in findings:
        in_path = f.id in finding_ids_in_path
        scored.append(
            ScoredFinding(
                **f.model_dump(),
                risk_score=score_finding(f, in_path),
                in_attack_path=in_path,
            )
        )

    scored.sort(key=lambda sf: sf.risk_score, reverse=True)
    for i, sf in enumerate(scored, start=1):
        sf.rank = i
    return scored
