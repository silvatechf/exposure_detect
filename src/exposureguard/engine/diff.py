"""Compare two scans by finding fingerprint (new / resolved / unchanged)."""

from __future__ import annotations

from dataclasses import dataclass

from exposureguard.domain.models import Finding, ScanResult


@dataclass
class Diff:
    new: list[Finding]
    resolved: list[Finding]
    unchanged: list[Finding]


def compare(old: ScanResult, new: ScanResult) -> Diff:
    old_fp = {f.fingerprint: f for f in old.findings}
    new_fp = {f.fingerprint: f for f in new.findings}
    return Diff(
        new=[f for k, f in new_fp.items() if k not in old_fp],
        resolved=[f for k, f in old_fp.items() if k not in new_fp],
        unchanged=[f for k, f in new_fp.items() if k in old_fp],
    )
