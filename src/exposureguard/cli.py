"""Command line interface: scan, diff, checks, lab, serve."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from exposureguard.domain.models import ScanResult, Severity, Target
from exposureguard.engine import diff as diff_engine
from exposureguard.engine.base import ScanContext
from exposureguard.engine.registry import all_checks
from exposureguard.engine.runner import run_scan
from exposureguard.profiles import load_profile
from exposureguard.reporting import json_report, markdown_report, sarif
from exposureguard.scope import Scope, ScopeError

app = typer.Typer(help="ExposureGuard: exposure-posture scanner for authorised targets.")


def _parse_service_ports(items: list[str]) -> dict[str, set[int]]:
    ports = ScanContext().service_ports
    seen: set[str] = set()
    for item in items:
        name, _, value = item.partition("=")
        if name not in ports or not value.isdigit():
            raise ValueError(f"--service-port must look like NAME=PORT with NAME in {sorted(ports)}")
        if name not in seen:  # first override replaces the default, repeats add more ports
            ports[name] = set()
            seen.add(name)
        ports[name].add(int(value))
    return ports


@app.command()
def scan(
    target: list[str] = typer.Option(..., "--target", "-t", help="Host or IP (repeatable)."),
    scope: Path = typer.Option(Path("scope.yaml"), help="Scope file with your authorisation."),
    ports: str | None = typer.Option(None, help="Comma-separated TCP ports (default: curated list)."),
    allow_credential_checks: bool = typer.Option(
        False, help="Enable opt-in default-credential checks (HTTP Basic, web form, SNMP)."
    ),
    allow_industrial_probes: bool = typer.Option(
        False, help="Enable opt-in read-only industrial protocol probes (Modbus). Never on live plants without approval."
    ),
    profile: str | None = typer.Option(None, help="Device profile name or YAML file (camera, sensor, plc, ...)."),
    fmt: str = typer.Option("md", "--format", help="md, json or sarif."),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str = typer.Option("high", help="Exit 1 if a finding at or above this severity exists."),
    baseline: Path | None = typer.Option(None, help="Previous JSON report: only NEW findings fail the gate."),
    sarif_artifact: str = typer.Option("README.md", help="Repo file SARIF results are anchored to."),
    service_port: list[str] = typer.Option([], help="Override a service port, e.g. mqtt=18830."),
    http_port: list[int] = typer.Option([], help="Extra port to treat as HTTP (repeatable)."),
    timeout: float = typer.Option(3.0),
) -> None:
    try:
        threshold = Severity.parse(fail_on)
        port_list = [int(p) for p in ports.split(",")] if ports else None
        ctx = ScanContext(
            timeout=timeout,
            allow_credential_checks=allow_credential_checks,
            allow_industrial_probes=allow_industrial_probes,
            profile=load_profile(profile) if profile else None,
            service_ports=_parse_service_ports(service_port),
        )
        ctx.http_ports |= set(http_port)
        old = ScanResult.model_validate_json(baseline.read_text()) if baseline else None
        result = asyncio.run(
            run_scan([Target(host=h, ports=port_list) for h in target], Scope.load(scope), ctx)
        )
    except (ScopeError, ValueError, OSError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    if fmt == "json":
        text = json_report.render(result)
    elif fmt == "sarif":
        text = sarif.render(result, sarif_artifact)
    else:
        text = markdown_report.render(result)
    if output:
        output.write_text(text)
    else:
        typer.echo(text)

    gated = result.findings
    if old is not None:
        d = diff_engine.compare(old, result)
        gated = d.new
        typer.echo(
            f"baseline: {len(d.new)} new, {len(d.resolved)} resolved, {len(d.unchanged)} unchanged",
            err=True,
        )
    if any(f.severity >= threshold for f in gated):
        raise typer.Exit(1)


@app.command()
def diff(old: Path, new: Path) -> None:
    """Compare two JSON reports and list new and resolved findings."""
    d = diff_engine.compare(
        ScanResult.model_validate_json(old.read_text()),
        ScanResult.model_validate_json(new.read_text()),
    )
    for label, items in (("NEW", d.new), ("RESOLVED", d.resolved)):
        for f in items:
            typer.echo(f"{label:9} [{f.severity.name}] {f.host}:{f.port or '-'} {f.title}")
    typer.echo(f"{len(d.new)} new, {len(d.resolved)} resolved, {len(d.unchanged)} unchanged")


@app.command()
def checks() -> None:
    """List available checks."""
    for cid, cls in sorted(all_checks().items()):
        flag = f" (opt-in: {cls.opt_in})" if cls.opt_in else ""
        typer.echo(f"{cid}{flag}: {cls.title}")


@app.command()
def lab(base_port: int = 18800) -> None:
    """Start deliberately insecure fake devices on localhost to try the scanner against."""
    from exposureguard.lab.fake_devices import start_all

    async def main() -> None:
        handle = await start_all("127.0.0.1", base_port)
        p = handle.ports
        tcp = [v for k, v in p.items() if k != "snmp"]
        web = [v for k, v in p.items() if k.startswith("web_")]
        svc = {"redis": ["redis"], "mqtt": ["mqtt"], "rtsp": ["rtsp", "rtsp_vendor"], "modbus": ["modbus"], "snmp": ["snmp"]}
        flags = " ".join(f"--service-port {n}={p[k]}" for n, ks in svc.items() for k in ks)
        typer.echo("Fake devices running on 127.0.0.1 (Ctrl+C to stop). Try:\n")
        typer.echo(
            "  eg scan -t 127.0.0.1 --scope scope.example.yaml --allow-credential-checks "
            f"--allow-industrial-probes --ports {','.join(map(str, tcp))} {flags} "
            + " ".join(f"--http-port {v}" for v in web)
            + "\n\n(Use a scope file that allows 127.0.0.0/8.)"
        )
        try:
            await asyncio.Event().wait()
        finally:
            await handle.stop()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the HTTP API (requires EG_API_KEYS or EG_API_KEY)."""
    import uvicorn

    uvicorn.run("exposureguard.api.main:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    app()
