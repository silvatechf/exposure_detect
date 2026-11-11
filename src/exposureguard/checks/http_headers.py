"""Check: secure-by-default HTTP posture (headers, cleartext admin UI, version disclosure)."""

from __future__ import annotations

import re
from datetime import date

import httpx

from exposureguard.checks._net import url_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register
from exposureguard.runtime_eol import php_status

VERSION_RE = re.compile(r"\d+\.\d+")


@register
class HttpHeadersCheck(Check):
    id = "http_posture"
    title = "HTTP secure-by-default posture"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        open_ports = ctx.open_ports.get(target.host, set())
        web_ports = sorted(open_ports & (ctx.http_ports | ctx.https_ports))
        findings: list[Finding] = []
        # Posture check, not a trust decision: certificate validity is covered by tls_posture.
        async with httpx.AsyncClient(
            trust_env=False,
            verify=False, timeout=ctx.timeout, follow_redirects=False  # noqa: S501
        ) as client:
            for port in web_ports:
                https = port in ctx.https_ports
                scheme = "https" if https else "http"
                try:
                    resp = await client.get(f"{scheme}://{url_host(target.host)}:{port}/")
                except httpx.HTTPError:
                    continue
                findings.extend(self._analyse(target.host, port, https, resp))
        return findings

    def _analyse(
        self, host: str, port: int, https: bool, resp: httpx.Response, today: date | None = None
    ) -> list[Finding]:
        out: list[Finding] = []
        h = {k.lower(): v for k, v in resp.headers.items()}

        if not https:
            location = h.get("location", "")
            if not (300 <= resp.status_code < 400 and location.startswith("https://")):
                out.append(
                    Finding(
                        check_id=self.id,
                        title=f"Web interface served over cleartext HTTP (port {port})",
                        severity=Severity.MEDIUM,
                        host=host,
                        port=port,
                        description="Traffic, including any login, can be read or altered in transit.",
                        remediation="Serve the interface over HTTPS and redirect HTTP to HTTPS.",
                        evidence={"status": resp.status_code},
                        tags=["secure-by-default", "cleartext"],
                    )
                )

        missing = []
        if https and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options")
        csp = h.get("content-security-policy", "")
        if not csp:
            missing.append("Content-Security-Policy")
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            missing.append("X-Frame-Options")
        if missing:
            out.append(
                Finding(
                    check_id=self.id,
                    title=f"Missing security headers (port {port})",
                    severity=Severity.LOW,
                    host=host,
                    port=port,
                    description="Browser-side protections are not enabled by default.",
                    remediation="Add the missing headers in the device web server configuration.",
                    evidence={"missing": missing},
                    tags=["secure-by-default", "headers"],
                )
            )

        server = h.get("server", "")
        if server and VERSION_RE.search(server):
            out.append(
                Finding(
                    check_id=self.id,
                    title=f"Server banner discloses software version (port {port})",
                    severity=Severity.LOW,
                    host=host,
                    port=port,
                    description="Version banners help attackers match the device to known exploits.",
                    remediation="Suppress or genericise the Server header.",
                    evidence={"server": server},
                    tags=["information-disclosure"],
                )
            )

        powered = h.get("x-powered-by", "")
        if powered:
            out.append(
                Finding(
                    check_id=self.id,
                    title=f"X-Powered-By header discloses runtime (port {port})",
                    severity=Severity.LOW,
                    host=host,
                    port=port,
                    description="Runtime names and versions help attackers pick matching exploits.",
                    remediation="Remove the X-Powered-By header (for PHP: expose_php = Off).",
                    evidence={"x_powered_by": powered},
                    tags=["information-disclosure"],
                )
            )
            status = php_status(powered, today)
            if status:
                version, kind, eol = status
                eol_txt = f" (security support ended {eol})" if kind == "eol" and eol else ""
                out.append(
                    Finding(
                        check_id=self.id,
                        title=(
                            f"End-of-life PHP runtime {version} (port {port})"
                            if kind == "eol"
                            else f"PHP {version} approaching end of security support (port {port})"
                        ),
                        severity=Severity.HIGH if kind == "eol" else Severity.LOW,
                        host=host,
                        port=port,
                        description=(
                            f"This PHP version no longer receives security fixes{eol_txt}."
                            if kind == "eol"
                            else f"Security support for PHP {version} ends on {eol}."
                        ),
                        remediation="Upgrade to a supported PHP release. If the vendor backports fixes, confirm the patch level.",
                        evidence={"version": version, "status": kind, "eol_date": str(eol) if eol else None},
                        confidence="medium",  # distributions may backport security fixes
                        tags=["outdated-runtime", "php"],
                    )
                )
        return out
