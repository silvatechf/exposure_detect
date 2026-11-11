"""Check: which risky services answer on the network? Also feeds open ports to other checks."""

from __future__ import annotations

import asyncio
import json
from importlib import resources

from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register
from exposureguard.networking.resolution import ResolvedTarget, open_pinned_connection

RISKY: dict[str, dict[str, str]] = json.loads(
    resources.files("exposureguard.data").joinpath("risky_services.json").read_text()
)
DEFAULT_PORTS = sorted({int(p) for p in RISKY} | {22, 80, 443, 8080, 8443, 8883})


async def _is_open(
    target: ResolvedTarget, port: int, timeout: float, semaphore: asyncio.Semaphore
) -> bool:
    async with semaphore:
        try:
            _, writer = await open_pinned_connection(target, port, timeout)
        except (OSError, TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True


@register
class ExposedServicesCheck(Check):
    id = "exposed_services"
    title = "Risky services reachable on the network"
    depends_on_ports = False

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        ports = target.ports or DEFAULT_PORTS
        resolved = ctx.resolved_targets[target.host]
        results = await asyncio.gather(
            *(_is_open(resolved, p, ctx.timeout, ctx.network_semaphore) for p in ports)
        )
        open_ports = {p for p, ok in zip(ports, results, strict=True) if ok}
        ctx.open_ports[target.host] = open_ports

        findings: list[Finding] = []
        for port in sorted(open_ports):
            info = RISKY.get(str(port))
            if not info:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"{info['name']} exposed on port {port}",
                    severity=Severity.parse(info["severity"]),
                    host=target.host,
                    port=port,
                    description=info["why"],
                    remediation=info["fix"],
                    evidence={"state": "open", "service": info["name"]},
                    tags=["exposure", "attack-surface"],
                )
            )
        return findings
