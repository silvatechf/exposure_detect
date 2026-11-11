"""Check: SNMP agent answering the default 'public' community (UDP). Opt-in."""

from __future__ import annotations

from exposureguard.checks._net import udp_exchange
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register
from exposureguard.protocols import snmp

COMMUNITY = b"public"


@register
class SnmpDefaultCommunityCheck(Check):
    id = "snmp_default"
    title = "SNMP agent accepting the default community string"
    opt_in = "credentials"
    depends_on_ports = False  # UDP: cannot be discovered with a TCP connect

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings = []
        for port in sorted(ctx.service_ports.get("snmp", set())):
            resp = await udp_exchange(
                ctx.resolved_targets[target.host], port, snmp.build_get_request(COMMUNITY), ctx.timeout
            )
            if not resp:
                continue  # no answer: closed or filtered, which is unknown, not safe
            try:
                version, community, pdu_tag = snmp.parse_message(resp)
            except ValueError:
                continue
            if pdu_tag == snmp.GET_RESPONSE and community == COMMUNITY:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"SNMP accepts default community 'public' (UDP {port})",
                        severity=Severity.HIGH,
                        host=target.host,
                        port=port,
                        description="Device details and configuration can be read by anyone on the network.",
                        remediation="Disable SNMPv1/v2c or change communities; prefer SNMPv3 with authentication and encryption.",
                        evidence={"community": "public", "protocol": "udp", "snmp_version": version},
                        references=["https://cwe.mitre.org/data/definitions/1392.html"],
                        tags=["default-credentials", "snmp"],
                    )
                )
        return findings
