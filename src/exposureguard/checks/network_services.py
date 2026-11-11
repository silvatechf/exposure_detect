"""Protocol-level checks: services that answer without authentication (MQTT, Redis, RTSP)."""

from __future__ import annotations

from exposureguard.checks._net import exchange, url_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register

# MQTT 3.1.1 CONNECT, clean session, no username/password, client id "eg-probe".
_MQTT_CONNECT = bytes.fromhex("101400044d5154540402003c0008") + b"eg-probe"


def _ports(ctx: ScanContext, target: Target, service: str) -> list[int]:
    return sorted(ctx.open_ports.get(target.host, set()) & ctx.service_ports.get(service, set()))


@register
class MqttAnonymousCheck(Check):
    id = "mqtt_anonymous"
    title = "MQTT broker accepting anonymous connections"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings = []
        for port in _ports(ctx, target, "mqtt"):
            resp = await exchange(ctx.resolved_targets[target.host], port, _MQTT_CONNECT, ctx.timeout)
            if resp and len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"MQTT broker accepts anonymous connections (port {port})",
                        severity=Severity.HIGH,
                        host=target.host,
                        port=port,
                        description="Anyone on the network can connect, and likely publish or subscribe to device topics.",
                        remediation="Disable anonymous access; require credentials or client certificates and ACLs.",
                        evidence={"connack_return_code": 0},
                        tags=["unauthenticated", "attack-surface", "mqtt"],
                    )
                )
        return findings


@register
class RedisUnauthenticatedCheck(Check):
    id = "redis_unauth"
    title = "Redis answering without authentication"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings = []
        for port in _ports(ctx, target, "redis"):
            resp = await exchange(ctx.resolved_targets[target.host], port, b"PING\r\n", ctx.timeout)
            if resp and resp.startswith(b"+PONG"):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"Redis responds without authentication (port {port})",
                        severity=Severity.CRITICAL,
                        host=target.host,
                        port=port,
                        description="An unauthenticated Redis lets anyone read or overwrite data, and is a known path to code execution.",
                        remediation="Bind to a private interface, enable ACLs/requirepass and firewall the port.",
                        evidence={"reply": "+PONG"},
                        tags=["unauthenticated", "attack-surface", "redis"],
                    )
                )
        return findings


RTSP_PATHS = [
    "/",
    "/live",
    "/live.sdp",
    "/stream1",
    "/stream",
    "/h264",
    "/ch0",
    "/11",
    "/Streaming/Channels/101",  # Hikvision-style
    "/cam/realmonitor?channel=1&subtype=0",  # Dahua-style
    "/axis-media/media.amp",  # Axis-style
]


@register
class RtspUnauthenticatedCheck(Check):
    id = "rtsp_unauth"
    title = "RTSP stream description available without authentication"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings = []
        for port in _ports(ctx, target, "rtsp"):
            open_paths = []
            for path in RTSP_PATHS:  # sequential on purpose: embedded cameras are fragile
                req = (
                    f"DESCRIBE rtsp://{url_host(target.host)}:{port}{path} RTSP/1.0\r\n"
                    "CSeq: 1\r\nAccept: application/sdp\r\n\r\n"
                ).encode()
                resp = await exchange(ctx.resolved_targets[target.host], port, req, ctx.timeout)
                if resp and resp.startswith(b"RTSP/1.0 200"):
                    open_paths.append(path)
            if open_paths:
                specific = [p for p in open_paths if p != "/"]
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"RTSP answers 200 without authentication (port {port})",
                        severity=Severity.HIGH,
                        host=target.host,
                        port=port,
                        description="Video streams may be viewable by anyone who can reach the device.",
                        remediation="Require authentication on every stream path and restrict to the VMS network.",
                        evidence={"paths": open_paths},
                        confidence="high" if specific else "medium",
                        tags=["unauthenticated", "attack-surface", "rtsp", "camera"],
                    )
                )
        return findings
