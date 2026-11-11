"""Industrial protocol confirmation. Opt-in, read-only, one request per port."""

from __future__ import annotations

from exposureguard.checks._net import exchange
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register
from exposureguard.protocols import modbus


@register
class ModbusUnauthenticatedCheck(Check):
    id = "modbus_unauth"
    title = "Modbus/TCP device answering unauthenticated requests"
    opt_in = "industrial"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings = []
        ports = sorted(ctx.open_ports.get(target.host, set()) & ctx.service_ports.get("modbus", set()))
        for port in ports:
            resp = await exchange(target.host, port, modbus.build_read_device_id(), ctx.timeout)
            kind = modbus.parse_response(resp, 1) if resp else None
            if kind is None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Modbus/TCP answers unauthenticated requests (port {port})",
                    severity=Severity.HIGH,
                    host=target.host,
                    port=port,
                    description="Modbus has no authentication: anyone who reaches this port can talk to the device.",
                    remediation="Remove it from untrusted networks; segment OT and put a protocol-aware gateway or firewall in front.",
                    evidence={"request": "read device identification (FC 0x2B, read-only)", "reply": kind},
                    tags=["unauthenticated", "attack-surface", "modbus", "industrial"],
                )
            )
        return findings
