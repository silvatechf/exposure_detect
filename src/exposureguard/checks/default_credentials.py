"""Check: HTTP Basic endpoints that accept generic default credentials.

Opt-in only, in-scope targets only, a tiny list and a hard attempt cap to avoid lockouts.
This is a posture check, not a password-guessing tool. Passwords are never stored.
"""

from __future__ import annotations

import asyncio
import json
from importlib import resources

import httpx

from exposureguard.checks._net import url_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register
from exposureguard.networking.http import pinned_client

PAIRS: list[dict[str, str]] = json.loads(
    resources.files("exposureguard.data").joinpath("default_credentials.json").read_text()
)["pairs"]


@register
class DefaultCredentialsCheck(Check):
    id = "default_credentials"
    title = "HTTP Basic endpoints accepting default credentials"
    opt_in = "credentials"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        open_ports = ctx.open_ports.get(target.host, set())
        findings: list[Finding] = []
        async with pinned_client(
            target.host,
            ctx.resolved_targets[target.host].addresses,
            timeout=ctx.timeout,
            verify=False,
        ) as client:
            for port in sorted(open_ports & (ctx.http_ports | ctx.https_ports)):
                scheme = "https" if port in ctx.https_ports else "http"
                url = f"{scheme}://{url_host(target.host)}:{port}/"
                try:
                    probe = await client.get(url)
                except httpx.HTTPError:
                    continue
                if probe.status_code != 401 or "basic" not in probe.headers.get(
                    "www-authenticate", ""
                ).lower():
                    continue
                for pair in PAIRS[: ctx.max_credential_attempts]:
                    await asyncio.sleep(ctx.credential_delay)
                    try:
                        resp = await client.get(url, auth=(pair["username"], pair["password"]))
                    except httpx.HTTPError:
                        break
                    if resp.status_code == 200:
                        findings.append(self._finding(target.host, port, pair))
                        break
        return findings

    def _finding(self, host: str, port: int, pair: dict[str, str]) -> Finding:
        return Finding(
            check_id=self.id,
            title=f"Default credentials accepted (port {port})",
            severity=Severity.CRITICAL,
            host=host,
            port=port,
            description="The interface accepts a generic factory-default login.",
            remediation="Force a unique password at first use; disable the default account.",
            evidence={"credential_pair": pair["id"], "username": pair["username"]},
            references=["https://cwe.mitre.org/data/definitions/1392.html"],
            tags=["default-credentials", "secure-by-default"],
        )
