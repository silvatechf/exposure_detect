"""Check: web login forms accepting generic default credentials. Opt-in, heuristic.

Safety rules: only same-host URLs are ever requested (no redirect to other hosts), the attempt cap
applies, and a control probe with random credentials guards against sites that accept anything.
Findings are reported with medium confidence because success detection is heuristic.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from html.parser import HTMLParser
from importlib import resources
from urllib.parse import urljoin, urlparse

import httpx

from exposureguard.checks._net import url_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register

PAIRS: list[dict[str, str]] = json.loads(
    resources.files("exposureguard.data").joinpath("default_credentials.json").read_text()
)["pairs"]
FAIL_WORDS = ("invalid", "incorrect", "failed", "wrong", "denied", "error", "try again")
LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "error", "fail")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append(a)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_login_form(html: str) -> dict | None:
    parser = _FormParser()
    parser.feed(html)
    for form in parser.forms:
        pw = next((i for i in form["inputs"] if (i.get("type") or "").lower() == "password"), None)
        if pw is None or form["method"] != "post":
            continue
        user = next(
            (i for i in form["inputs"] if (i.get("type") or "text").lower() in ("text", "email") and i.get("name")),
            None,
        )
        hidden = {
            i["name"]: i.get("value", "")
            for i in form["inputs"]
            if (i.get("type") or "").lower() == "hidden" and i.get("name")
        }
        return {
            "action": form["action"],
            "user_field": user["name"] if user else "username",
            "pass_field": pw.get("name") or "password",
            "hidden": hidden,
        }
    return None


def looks_success(resp: httpx.Response) -> bool:
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.headers.get("location", "").lower()
        return bool(loc) and not any(h in loc for h in LOGIN_HINTS)
    if resp.status_code == 200:
        body = resp.text.lower()
        return "type=\"password\"" not in body and "type='password'" not in body and not any(
            w in body for w in FAIL_WORDS
        )
    return False


async def _get_same_host(client: httpx.AsyncClient, url: str, host: str, hops: int = 3) -> httpx.Response | None:
    for _ in range(hops + 1):
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return None
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
            url = urljoin(str(resp.url), resp.headers["location"])
            if urlparse(url).hostname != host:
                return None  # never leave the authorised host
            continue
        return resp
    return None


@register
class HttpFormLoginCheck(Check):
    id = "http_form_login"
    title = "Web login forms accepting default credentials"
    opt_in = "credentials"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        ports = sorted(ctx.open_ports.get(target.host, set()) & (ctx.http_ports | ctx.https_ports))
        findings: list[Finding] = []
        async with httpx.AsyncClient(
            trust_env=False,
            verify=False, timeout=ctx.timeout, follow_redirects=False  # noqa: S501
        ) as client:
            for port in ports:
                scheme = "https" if port in ctx.https_ports else "http"
                page = await _get_same_host(client, f"{scheme}://{url_host(target.host)}:{port}/", target.host)
                if page is None or page.status_code != 200:
                    continue
                form = parse_login_form(page.text)
                if form is None:
                    continue
                action = urljoin(str(page.url), form["action"])
                if urlparse(action).hostname != target.host:
                    continue

                async def attempt(user: str, pw: str, _form=form, _action=action) -> bool:
                    data = {**_form["hidden"], _form["user_field"]: user, _form["pass_field"]: pw}
                    try:
                        return looks_success(await client.post(_action, data=data))
                    except httpx.HTTPError:
                        return False

                if await attempt("eg-" + secrets.token_hex(4), secrets.token_urlsafe(12)):
                    continue  # control probe "succeeded": the site accepts anything, no signal
                for pair in PAIRS[: ctx.max_credential_attempts]:
                    await asyncio.sleep(ctx.credential_delay)
                    if await attempt(pair["username"], pair["password"]):
                        findings.append(
                            Finding(
                                check_id=self.id,
                                title=f"Login form likely accepts default credentials (port {port})",
                                severity=Severity.CRITICAL,
                                host=target.host,
                                port=port,
                                description="The web login accepted a generic factory-default pair while rejecting a random one.",
                                remediation="Force a unique password at first use; disable the default account.",
                                evidence={"credential_pair": pair["id"], "username": pair["username"], "method": "form"},
                                confidence="medium",
                                references=["https://cwe.mitre.org/data/definitions/1392.html"],
                                tags=["default-credentials", "secure-by-default"],
                            )
                        )
                        break
        return findings
