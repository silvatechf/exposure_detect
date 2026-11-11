from exposureguard.checks.default_credentials import DefaultCredentialsCheck
from exposureguard.domain.models import Severity, Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.networking.resolution import ResolvedTarget

from .helpers import make_basic_handler, serve


def _ctx(port):
    ctx = ScanContext(http_ports={port}, credential_delay=0, allow_credential_checks=True)
    ctx.open_ports["127.0.0.1"] = {port}
    ctx.resolved_targets["127.0.0.1"] = ResolvedTarget("127.0.0.1", ("127.0.0.1",))
    return ctx


async def test_default_credentials_detected_and_password_not_stored():
    server, port = serve(make_basic_handler("admin", "admin"))
    try:
        findings = await DefaultCredentialsCheck().run(Target(host="127.0.0.1"), _ctx(port))
    finally:
        server.shutdown()
    assert len(findings) == 1 and findings[0].severity == Severity.CRITICAL
    assert "password" not in findings[0].evidence


async def test_strong_password_not_flagged():
    server, port = serve(make_basic_handler("admin", "Xk9!long-unique-pass"))
    try:
        findings = await DefaultCredentialsCheck().run(Target(host="127.0.0.1"), _ctx(port))
    finally:
        server.shutdown()
    assert findings == []


async def test_check_is_skipped_without_opt_in(scope):
    server, port = serve(make_basic_handler("admin", "admin"))
    try:
        ctx = ScanContext(http_ports={port}, credential_delay=0)  # opt-in NOT enabled
        result = await run_scan([Target(host="127.0.0.1", ports=[port])], scope, ctx)
    finally:
        server.shutdown()
    assert all(f.check_id != "default_credentials" for f in result.findings)
