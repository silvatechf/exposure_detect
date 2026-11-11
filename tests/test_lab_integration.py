"""End-to-end: every check against deliberately insecure fake devices on localhost."""

import pytest

from exposureguard.domain.models import Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.lab.fake_devices import start_all


@pytest.fixture
async def lab():
    handle = await start_all()
    yield handle
    await handle.stop()


def _ctx(p, allow=True):
    web = {p[k] for k in ("web_basic", "web_form", "web_form_open", "web_leaky")}
    return ScanContext(
        timeout=2,
        allow_credential_checks=allow,
        credential_delay=0,
        service_ports={"mqtt": {p["mqtt"]}, "redis": {p["redis"]}, "rtsp": {p["rtsp"]}, "snmp": {p["snmp"]}},
        http_ports=web,
    )


def _tcp_ports(p):
    return [p[k] for k in ("redis", "mqtt", "rtsp", "web_basic", "web_form", "web_form_open", "web_leaky")]


def _by_check(result):
    out = {}
    for f in result.findings:
        out.setdefault(f.check_id, []).append(f)
    return out


async def test_all_checks_fire_against_lab(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p))
    found = _by_check(result)
    for expected in (
        "mqtt_anonymous", "redis_unauth", "rtsp_unauth", "snmp_default",
        "default_credentials", "http_form_login", "exposed_paths", "http_posture",
    ):
        assert expected in found, f"{expected} did not fire; errors={result.errors}"
    assert result.errors == []
    assert result.grade in {"D", "F"}


async def test_form_login_only_flags_the_discriminating_site(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p))
    ports = {f.port for f in _by_check(result)["http_form_login"]}
    assert ports == {p["web_form"]}  # web_form_open accepts anything -> control probe suppresses it
    assert _by_check(result)["http_form_login"][0].confidence == "medium"


async def test_basic_creds_flagged_without_password_in_evidence(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p))
    f = _by_check(result)["default_credentials"][0]
    assert f.port == p["web_basic"] and "password" not in f.evidence


async def test_exposed_paths_never_store_bodies(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p))
    paths = _by_check(result)["exposed_paths"]
    assert {f.evidence["path"] for f in paths} == {"/.env", "/.git/config", "/phpinfo.php"}
    assert all("hunter2" not in str(f.model_dump()) for f in paths)


async def test_opt_in_checks_silent_without_flag(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p, allow=False))
    found = _by_check(result)
    for opt_in in ("snmp_default", "default_credentials", "http_form_login"):
        assert opt_in not in found
    assert "mqtt_anonymous" in found  # non-credential checks still run


async def test_findings_carry_indicative_standards(lab, scope):
    p = lab.ports
    result = await run_scan([Target(host="127.0.0.1", ports=_tcp_ports(p))], scope, _ctx(p))
    cred = _by_check(result)["default_credentials"][0]
    assert any("5.1" in s for s in cred.standards)
