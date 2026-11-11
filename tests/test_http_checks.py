from exposureguard.checks.http_headers import HttpHeadersCheck
from exposureguard.domain.models import Target
from exposureguard.engine.base import ScanContext

from .helpers import PlainHandler, serve


async def test_plain_http_reports_cleartext_headers_and_banner():
    server, port = serve(PlainHandler)
    try:
        ctx = ScanContext(http_ports={port})
        ctx.open_ports["127.0.0.1"] = {port}
        findings = await HttpHeadersCheck().run(Target(host="127.0.0.1"), ctx)
    finally:
        server.shutdown()
    titles = " | ".join(f.title for f in findings)
    assert "cleartext HTTP" in titles
    assert "Missing security headers" in titles
    assert "discloses software version" in titles
