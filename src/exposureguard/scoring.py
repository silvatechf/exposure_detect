"""Posture score: 100 minus weighted findings, mapped to a letter grade."""

from __future__ import annotations

from exposureguard.domain.models import Finding, Severity

WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 40,
}


def compute(findings: list[Finding]) -> tuple[int, str]:
    penalty = sum(WEIGHTS[f.severity] for f in findings)
    score = max(0, 100 - penalty)
    if any(f.severity == Severity.CRITICAL for f in findings):
        score = min(score, 40)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else (
        "D" if score >= 40 else "F"
    )
    return score, grade
