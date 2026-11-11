"""Camera-oriented checks: ONVIF exposure and web-interface fingerprinting (CCTV/DVR/NVR)."""

from __future__ import annotations

import re

import httpx

from exposureguard.checks._net import url_host
from exposureguard.checks.http_form_login import _get_same_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register

_SOAP = (
    '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body><{op} xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
)
_VENDORS = re.compile(
    r"hikvision|dahua|axis communications|foscam|reolink|uniview|vivotek|amcrest|hanwha|\bdvr\b|\bnvr\b|ip camera|network camera|netcam",
    re.I,
)


def _web_ports(ctx: ScanContext, target: Target) -> list[int]:
    return sorted(ctx.open_ports.get(target.host, set()) & (ctx.http_ports | ctx.https_ports))


@register
class OnvifCheck(Check):
    id = "onvif_exposed"
    title = "ONVIF device service exposed or disclosing information"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        headers = {"Content-Type": "application/soap+xml"}
        async with httpx.AsyncClient(
            trust_env=False,
            verify=False, timeout=ctx.timeout, follow_redirects=False  # noqa: S501
        ) as client:
            for port in _web_ports(ctx, target):
                scheme = "https" if port in ctx.https_ports else "http"
                url = f"{scheme}://{url_host(target.host)}:{port}/onvif/device_service"

                async def call(op: str, _url=url) -> str:
                    try:
                        r = await client.post(_url, content=_SOAP.format(op=op), headers=headers)
                    except httpx.HTTPError:
                        return ""
                    return r.text if r.status_code == 200 else ""

                if "GetSystemDateAndTimeResponse" not in await call("GetSystemDateAndTime"):
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"ONVIF device service reachable (port {port})",
                        severity=Severity.INFO,
                        host=target.host,
                        port=port,
                        description="The camera management API answers on the network. Time queries are unauthenticated by design in ONVIF.",
                        remediation="Restrict ONVIF to the management/VMS network.",
                        tags=["exposure", "camera", "onvif"],
                    )
                )
                info = await call("GetDeviceInformation")
                if "GetDeviceInformationResponse" in info:
                    fields = [f for f in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber") if f in info]
                    findings.append(
                        Finding(
                            check_id=self.id,
                            title=f"ONVIF discloses device information without authentication (port {port})",
                            severity=Severity.MEDIUM,
                            host=target.host,
                            port=port,
                            description="Model and firmware details help match the camera to known exploits.",
                            remediation="Require authentication for all ONVIF calls except those mandated by the spec; restrict network access.",
                            evidence={"fields_disclosed": fields},
                            tags=["unauthenticated", "camera", "onvif", "information-disclosure"],
                        )
                    )
        return findings


@register
class CameraFingerprintCheck(Check):
    id = "camera_fingerprint"
    title = "Camera / DVR / NVR web interface identified"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        async with httpx.AsyncClient(
            trust_env=False,
            verify=False, timeout=ctx.timeout, follow_redirects=False  # noqa: S501
        ) as client:
            for port in _web_ports(ctx, target):
                scheme = "https" if port in ctx.https_ports else "http"
                resp = await _get_same_host(client, f"{scheme}://{url_host(target.host)}:{port}/", target.host)
                if resp is None or resp.status_code not in (200, 401):
                    continue
                haystack = resp.headers.get("server", "") + " " + resp.text[:16384]
                m = _VENDORS.search(haystack)
                if m:
                    findings.append(
                        Finding(
                            check_id=self.id,
                            title=f"Camera/recorder web interface exposed (port {port})",
                            severity=Severity.INFO,
                            host=target.host,
                            port=port,
                            description="A surveillance device interface is reachable. Verify it is meant to be reachable from this network.",
                            remediation="Keep cameras and recorders on an isolated network; expose only through a VPN or an authenticated gateway.",
                            evidence={"hint": m.group(0).lower()},
                            confidence="medium",
                            tags=["exposure", "camera"],
                        )
                    )
        return findings
