from __future__ import annotations

from exposureguard.domain.models import ScanResult


def render(result: ScanResult) -> str:
    lines = [
        f"# ExposureGuard report `{result.id}`",
        "",
        f"- Posture score: **{result.score}/100 (grade {result.grade})**",
        f"- Targets: {', '.join(t.host for t in result.targets)}",
        f"- Findings: {len(result.findings)}",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
    for f in sorted(result.findings, key=lambda x: (-int(x.severity), x.host, x.port or 0)):
        where = f"{f.host}:{f.port}" if f.port else f.host
        lines += [
            f"## [{f.severity.name}] {f.title}",
            f"- Where: `{where}` (check `{f.check_id}`)",
            f"- Why it matters: {f.description}",
            f"- Fix: {f.remediation}",
        ]
        if f.confidence != "high":
            lines.append(f"- Confidence: {f.confidence}")
        if f.standards:
            lines.append(f"- Baselines (indicative): {'; '.join(f.standards)}")
        lines.append("")
    if result.errors:
        lines += ["## Check errors", *[f"- {e}" for e in result.errors], ""]
    return "\n".join(lines)
