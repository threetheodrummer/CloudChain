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

Each score is returned alongside a breakdown -- the ordered list of
multipliers that produced it, with the running total after each step -- so
the UI can justify why one finding outranks another. Replacing a severity
label with a computed number is only an improvement if the number can be
questioned; otherwise it's just a different opaque ordering.
"""
from __future__ import annotations

from typing import List, Set, Tuple

from app.models import Finding, ScoredFinding, ScoreFactor, Severity

BASE_SEVERITY_WEIGHTS = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 6.0,
    Severity.CRITICAL: 10.0,
}

INTERNET_FACING_MULTIPLIER = 1.5
SENSITIVE_MULTIPLIER = 1.5
ATTACK_PATH_MULTIPLIER = 2.5


def explain_finding(finding: Finding, in_attack_path: bool) -> Tuple[float, List[ScoreFactor]]:
    """Score a finding and return the arithmetic that produced the score."""
    base = BASE_SEVERITY_WEIGHTS[finding.base_severity]
    score = base
    factors: List[ScoreFactor] = [
        ScoreFactor(
            label=f"Base severity: {finding.base_severity.value}",
            detail=f"starting weight {base:g}",
            contribution=base,
        )
    ]

    if finding.internet_facing:
        before = score
        score *= INTERNET_FACING_MULTIPLIER
        factors.append(
            ScoreFactor(
                label=f"Internet-facing x{INTERNET_FACING_MULTIPLIER}",
                detail=f"{before:g} -> {score:g}: reachable without a foothold",
                contribution=round(score - before, 2),
            )
        )

    if finding.sensitive:
        before = score
        score *= SENSITIVE_MULTIPLIER
        factors.append(
            ScoreFactor(
                label=f"Sensitive resource x{SENSITIVE_MULTIPLIER}",
                detail=f"{before:g} -> {score:g}: credentials or regulated data at risk",
                contribution=round(score - before, 2),
            )
        )

    if in_attack_path:
        before = score
        score *= ATTACK_PATH_MULTIPLIER
        factors.append(
            ScoreFactor(
                label=f"On a confirmed attack path x{ATTACK_PATH_MULTIPLIER}",
                detail=(
                    f"{before:g} -> {score:g}: this resource sits on a chain reaching "
                    f"AdministratorAccess"
                ),
                contribution=round(score - before, 2),
            )
        )

    return round(score, 2), factors


def score_finding(finding: Finding, in_attack_path: bool) -> float:
    score, _ = explain_finding(finding, in_attack_path)
    return score


def score_findings(findings: List[Finding], finding_ids_in_path: Set[str]) -> List[ScoredFinding]:
    scored: List[ScoredFinding] = []
    for f in findings:
        in_path = f.id in finding_ids_in_path
        value, breakdown = explain_finding(f, in_path)
        scored.append(
            ScoredFinding(
                **f.model_dump(),
                risk_score=value,
                in_attack_path=in_path,
                score_breakdown=breakdown,
            )
        )

    scored.sort(key=lambda sf: sf.risk_score, reverse=True)
    for i, sf in enumerate(scored, start=1):
        sf.rank = i
    return scored
