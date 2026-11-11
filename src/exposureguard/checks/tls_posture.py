"""Check: TLS trust and legacy protocol acceptance on HTTPS ports."""

from __future__ import annotations

import asyncio
import ssl

from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register


def _legacy_context() -> ssl.SSLContext | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # noqa: S504  # probing protocol support, not trusting
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        return ctx
    except (ValueError, ssl.SSLError):
        return None  # this OpenSSL build cannot speak legacy TLS: nothing to probe


async def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> None:
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout
    )
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


@register
class TlsPostureCheck(Check):
    id = "tls_posture"
    title = "TLS certificate trust and protocol versions"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        ports = sorted(ctx.open_ports.get(target.host, set()) & ctx.https_ports)
        findings: list[Finding] = []
        for port in ports:
            try:
                await _handshake(target.host, port, ssl.create_default_context(), ctx.timeout)
            except ssl.SSLCertVerificationError as exc:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"TLS certificate not trusted (port {port})",
                        severity=Severity.MEDIUM,
                        host=target.host,
                        port=port,
                        description="Clients cannot verify the device identity; users learn to click through warnings.",
                        remediation="Install a certificate from a trusted CA or a managed private CA.",
                        evidence={"reason": exc.verify_message},
                        tags=["tls", "secure-by-default"],
                    )
                )
            except (OSError, ssl.SSLError, TimeoutError):
                pass

            legacy = _legacy_context()
            if legacy is None:
                continue
            try:
                await _handshake(target.host, port, legacy, ctx.timeout)
            except (OSError, ssl.SSLError, TimeoutError):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Legacy TLS 1.0/1.1 accepted (port {port})",
                    severity=Severity.MEDIUM,
                    host=target.host,
                    port=port,
                    description="Deprecated protocol versions are enabled.",
                    remediation="Disable TLS 1.0 and 1.1; require TLS 1.2 or newer.",
                    evidence={"accepted": "TLSv1/TLSv1.1"},
                    tags=["tls", "legacy-protocol"],
                )
            )
        return findings
