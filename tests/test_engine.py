import asyncio

import pytest

from exposureguard.checks import exposed_services
from exposureguard.domain.models import Severity, Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.scope import ScopeError
from exposureguard.networking.resolution import ResolvedTarget


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
