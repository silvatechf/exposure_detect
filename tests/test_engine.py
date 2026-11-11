import asyncio

import pytest

from exposureguard.checks import exposed_services
from exposureguard.domain.models import Severity, Target
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.networking.resolution import ResolvedTarget
from exposureguard.scope import ScopeError


async def _listen():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_out_of_scope_target_is_blocked_before_scanning(scope):
    with pytest.raises(ScopeError):
        await run_scan([Target(host="198.51.100.9")], scope)


async def test_open_risky_port_is_reported(scope, monkeypatch):
    server, port = await _listen()
    monkeypatch.setitem(
        exposed_services.RISKY,
        str(port),
        {"name": "FakeTelnet", "severity": "CRITICAL", "why": "w", "fix": "f"},
    )
    async with server:
        result = await run_scan([Target(host="127.0.0.1", ports=[port])], scope)
    assert any(f.severity == Severity.CRITICAL and f.port == port for f in result.findings)
    assert result.score <= 40


async def test_closed_port_gives_no_findings(scope):
    result = await run_scan([Target(host="127.0.0.1", ports=[1])], scope, ScanContext(timeout=0.5))
    assert result.findings == [] and result.grade == "A"


async def test_dns_preflight_rejects_explicitly_denied_answer(scope, monkeypatch):
    from exposureguard.engine import runner

    scope.allowed = ["*.lab.example.com"]
    scope.denied = ["203.0.113.9"]

    async def fake_resolve(host, timeout):
        return ResolvedTarget(host=host, addresses=("203.0.113.9",))

    monkeypatch.setattr(runner, "resolve_target", fake_resolve)
    with pytest.raises(ScopeError, match="resolved address explicitly denied"):
        await run_scan([Target(host="gateway.lab.example.com", ports=[443])], scope)


async def test_mixed_dns_answer_with_denied_address_fails_before_any_probe(scope, monkeypatch):
    from exposureguard.engine import runner

    scope.allowed = ["*.lab.example.com"]
    scope.denied = ["203.0.113.9"]
    probes_started = False

    class Probe(Check):
        id = "probe"
        title = "probe"
        depends_on_ports = False

        async def run(self, target, ctx):
            nonlocal probes_started
            probes_started = True
            return []

    async def fake_resolve(host, timeout):
        return ResolvedTarget(
            host=host, addresses=("192.0.2.10", "203.0.113.9")
        )

    monkeypatch.setattr(runner, "resolve_target", fake_resolve)
    monkeypatch.setattr(runner, "all_checks", lambda: {"probe": Probe})
    with pytest.raises(ScopeError, match="resolved address explicitly denied"):
        await run_scan([Target(host="gateway.lab.example.com")], scope)
    assert probes_started is False


async def test_every_target_is_preflighted_before_first_probe(scope, monkeypatch):
    from exposureguard.engine import runner

    scope.allowed = ["*.lab.example.com"]
    resolved_hosts = []
    probes_started = False

    class Probe(Check):
        id = "probe"
        title = "probe"
        depends_on_ports = False

        async def run(self, target, ctx):
            nonlocal probes_started
            probes_started = True
            assert resolved_hosts == ["first.lab.example.com", "second.lab.example.com"]
            return []

    async def fake_resolve(host, timeout):
        resolved_hosts.append(host)
        return ResolvedTarget(host=host, addresses=("192.0.2.10",))

    monkeypatch.setattr(runner, "resolve_target", fake_resolve)
    monkeypatch.setattr(runner, "all_checks", lambda: {"probe": Probe})
    await run_scan(
        [Target(host="first.lab.example.com"), Target(host="second.lab.example.com")],
        scope,
    )
    assert probes_started is True
