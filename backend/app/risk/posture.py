"""
Account-level posture score.

The per-finding risk scores in scoring.py answer "which finding matters most".
This module answers the other question a reader asks first: "how bad is this
account overall?"

The model is a deliberate deduction ladder rather than a black box, so every
point lost can be pointed at a specific cause:

    start at 100 (clean)
      - 10.0 per CRITICAL finding
      -  4.0 per HIGH finding
      -  1.5 per MEDIUM finding
      -  0.5 per LOW finding
      - 20.0 per confirmed attack path to AdministratorAccess
    floor at 0

Attack paths carry the heaviest single penalty on purpose: one proven chain to
admin is a worse outcome than a long list of unconnected issues. On top of the
points penalty, any confirmed attack path also caps the grade at F -- if an
attacker can demonstrably reach AdministratorAccess, the arithmetic shouldn't
be able to average that away into a passing grade. The numeric score still
conveys magnitude; the grade conveys "this account is compromised-by-design".
"""
from __future__ import annotations

from typing import Any, Dict, List

from app.models import AttackPath, ScoredFinding, Severity

SEVERITY_PENALTY = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 1.5,
    Severity.LOW: 0.5,
}

ATTACK_PATH_PENALTY = 20.0

# (minimum score, grade) checked in order, best first.
GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (20, "E"), (0, "F")]


def grade_for(score: float) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def compute_posture(findings: List[ScoredFinding], attack_paths: List[AttackPath]) -> Dict[str, Any]:
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.base_severity] += 1

    deductions = []
    total_deducted = 0.0

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = counts[sev]
        if not count:
            continue
        amount = count * SEVERITY_PENALTY[sev]
        total_deducted += amount
        deductions.append(
            {
                "reason": f"{count} {sev.value} finding{'s' if count != 1 else ''}",
                "points": round(amount, 1),
            }
        )

    if attack_paths:
        amount = len(attack_paths) * ATTACK_PATH_PENALTY
        total_deducted += amount
        deductions.append(
            {
                "reason": (
                    f"{len(attack_paths)} attack path"
                    f"{'s' if len(attack_paths) != 1 else ''} reaching AdministratorAccess"
                ),
                "points": round(amount, 1),
            }
        )

    score = max(0.0, 100.0 - total_deducted)

    # A confirmed route to AdministratorAccess is an automatic fail, regardless
    # of how few other findings the account has.
    grade = "F" if attack_paths else grade_for(score)

    return {
        "score": int(round(score)),
        "grade": grade,
        "auto_failed": bool(attack_paths),
        "deductions": deductions,
        "total_deducted": round(min(total_deducted, 100.0), 1),
    }
