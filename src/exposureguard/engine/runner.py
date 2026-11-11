"""Scan orchestration: scope check, port discovery first, then dependent checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from exposureguard import scoring
from exposureguard.domain.controls import standards_for
from exposureguard.domain.models import ScanResult, Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.registry import all_checks
from exposureguard.networking.resolution import ResolvedTarget, resolve_target
from exposureguard.scope import Scope


def _opted_in(check, ctx: ScanContext) -> bool:
    """Fail closed: unknown opt-in categories never run."""
    if check.opt_in is None:
        return True
    if check.opt_in == "credentials":
        return ctx.allow_credential_checks
    if check.opt_in == "industrial":
        return ctx.allow_industrial_probes
    return False


async def run_scan(
    targets: list[Target],
    scope: Scope,
    ctx: ScanContext | None = None,
    concurrency: int = 10,
) -> ScanResult:
    ctx = ctx or ScanContext()
    # A ScanContext may be reused by a caller, but DNS snapshots must never cross scans.
    ctx.resolved_targets.clear()

    # Complete authorization and DNS preflight for every target before any probe starts.
    for target in targets:
        scope.check(target.host)

    snapshots: dict[str, tuple[str, ...]] = {}
    for target in targets:
        key = target.host.rstrip(".").lower()
        if key not in snapshots:
            resolved = await resolve_target(target.host, timeout=ctx.timeout)
            for address in resolved.addresses:
                scope.check_resolved_address(address)
            snapshots[key] = resolved.addresses
        ctx.resolved_targets[target.host] = ResolvedTarget(
            host=target.host,
            addresses=snapshots[key],
        )

    result = ScanResult(targets=targets)
    checks = {cid: cls() for cid, cls in all_checks().items()}
    sem = asyncio.Semaphore(concurrency)

    async def run_one(check, target: Target) -> None:
        if not _opted_in(check, ctx):
            return
        async with sem:
            try:
                found = await check.run(target, ctx)
                for f in found:
                    f.standards = standards_for(f.tags)
                result.findings.extend(found)
            except Exception as exc:  # noqa: BLE001  one failing check must not abort the scan
                result.errors.append(f"{check.id} on {target.host}: {type(exc).__name__}")

    discovery = [c for c in checks.values() if not c.depends_on_ports]
    dependent = [c for c in checks.values() if c.depends_on_ports]

    await asyncio.gather(*(run_one(c, t) for c in discovery for t in targets))
    await asyncio.gather(*(run_one(c, t) for c in dependent for t in targets))

    result.finished_at = datetime.now(UTC)
    result.score, result.grade = scoring.compute(result.findings)
    return result
