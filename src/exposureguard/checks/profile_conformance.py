"""Check: open ports that a device profile does not expect (e.g. a camera listening on 3306)."""

from __future__ import annotations

from exposureguard.checks.exposed_services import RISKY
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register


@register
class ProfileConformanceCheck(Check):
    id = "profile_conformance"
    title = "Open ports not expected for the device profile"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        if ctx.profile is None:
            return []
        findings = []
        for port in sorted(ctx.open_ports.get(target.host, set())):
            if port in ctx.profile.allowed_ports or str(port) in RISKY:
                continue  # allowed, or already reported by exposed_services
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Unexpected open port {port} for profile '{ctx.profile.name}'",
                    severity=Severity.LOW,
                    host=target.host,
                    port=port,
                    description=f"Port {port} is not in the expected set for: {ctx.profile.description or ctx.profile.name}.",
                    remediation="Disable the service if unneeded, or extend the profile if it is intentional.",
                    evidence={"profile": ctx.profile.name},
                    confidence="medium",
                    tags=["attack-surface", "profile"],
                )
            )
        return findings
