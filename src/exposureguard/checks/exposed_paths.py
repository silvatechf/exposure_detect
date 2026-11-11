"""Check: sensitive files and debug endpoints reachable over HTTP, verified by content signature.

Signature-based on purpose: a 200 status alone is not evidence (soft-404 pages are common).
Response bodies are never stored, only the fact that the signature matched.
"""

from __future__ import annotations

import re

import httpx

from exposureguard.checks._net import url_host
from exposureguard.domain.models import Finding, Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.registry import register

PATHS: list[tuple[str, Severity, re.Pattern[str], str, str]] = [
    ("/.env", Severity.HIGH, re.compile(r"^[A-Z][A-Z0-9_]*=", re.M),
     "Environment file exposed", "Remove it from the web root and rotate every secret it contained."),
    ("/.git/config", Severity.HIGH, re.compile(r"\[core\]"),
     "Git repository metadata exposed", "Remove .git from the deployed tree; rotate any leaked secrets."),
    ("/actuator/env", Severity.HIGH, re.compile(r"propertySources|activeProfiles"),
     "Spring Boot actuator environment exposed", "Disable or authenticate actuator endpoints."),
    ("/phpinfo.php", Severity.MEDIUM, re.compile(r"PHP Version"),
     "phpinfo() page exposed", "Delete the diagnostic page from production."),
    ("/server-status", Severity.MEDIUM, re.compile(r"Apache Server Status"),
     "Apache server-status exposed", "Restrict mod_status to localhost or management addresses."),
    ("/debug/pprof/", Severity.MEDIUM, re.compile(r"Types of profiles available"),
     "Go pprof debug endpoint exposed", "Do not expose profiling endpoints; bind them to localhost."),
    ("/phpmyadmin/", Severity.MEDIUM, re.compile(r"phpMyAdmin"),
     "phpMyAdmin exposed", "Remove it from production or restrict by network and strong authentication."),
    ("/adminer.php", Severity.MEDIUM, re.compile(r"Adminer"),
     "Adminer database tool exposed", "Delete it from production or restrict access."),
    ("/backup.sql", Severity.HIGH, re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I),
     "Database dump exposed", "Remove the dump from the web root and treat its contents as leaked."),
    ("/dump.sql", Severity.HIGH, re.compile(r"CREATE TABLE|INSERT INTO|DROP TABLE", re.I),
     "Database dump exposed", "Remove the dump from the web root and treat its contents as leaked."),
    ("/config.php.bak", Severity.HIGH, re.compile(r"<\?php"),
     "PHP configuration backup exposed", "Remove backup files from the web root; rotate credentials they contain."),
    ("/wp-config.php.bak", Severity.HIGH, re.compile(r"DB_PASSWORD"),
     "WordPress configuration backup exposed", "Remove it and rotate the database credentials."),
    ("/.htpasswd", Severity.HIGH, re.compile(r"^[^:\s]+:(\$|\{)", re.M),
     "Password file (.htpasswd) exposed", "Block dotfiles in the web server and rotate the listed passwords."),
    ("/WEB-INF/web.xml", Severity.HIGH, re.compile(r"<web-app"),
     "Java WEB-INF configuration exposed", "Block access to WEB-INF; fix the servlet container mapping."),
    ("/uploads/", Severity.MEDIUM, re.compile(r"<title>Index of /", re.I),
     "Directory listing enabled on /uploads/", "Disable directory listing (Options -Indexes / autoindex off)."),
    ("/backup/", Severity.MEDIUM, re.compile(r"<title>Index of /", re.I),
     "Directory listing enabled on /backup/", "Disable directory listing and remove backups from the web root."),
]


@register
class ExposedPathsCheck(Check):
    id = "exposed_paths"
    title = "Sensitive files and debug endpoints reachable over HTTP"

    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        ports = sorted(ctx.open_ports.get(target.host, set()) & (ctx.http_ports | ctx.https_ports))
        findings: list[Finding] = []
        async with httpx.AsyncClient(
            trust_env=False,
            verify=False, timeout=ctx.timeout, follow_redirects=False  # noqa: S501
        ) as client:
            for port in ports:
                scheme = "https" if port in ctx.https_ports else "http"
                for path, severity, signature, title, fix in PATHS:
                    try:
                        resp = await client.get(f"{scheme}://{url_host(target.host)}:{port}{path}")
                    except httpx.HTTPError:
                        continue
                    if resp.status_code == 200 and signature.search(resp.text[:65536]):
                        findings.append(
                            Finding(
                                check_id=self.id,
                                title=f"{title} (port {port})",
                                severity=severity,
                                host=target.host,
                                port=port,
                                description=f"{path} is served without authentication and matches a known signature.",
                                remediation=fix,
                                evidence={"path": path, "status": 200, "signature": "matched"},
                                tags=["information-disclosure", "exposure"],
                            )
                        )
        return findings
