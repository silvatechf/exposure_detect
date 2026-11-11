"""v0.3 checks end to end against the fake devices (cameras, PHP site, Modbus, profiles)."""

import pytest

from exposureguard.domain.models import Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.lab.fake_devices import start_all
from exposureguard.profiles import BUILTIN

WEB = ("web_basic", "web_form", "web_form_open", "web_leaky", "web_php", "web_camera")


@pytest.fixture
async def lab():
    handle = await start_all()
    yield handle
    await handle.stop()


def _ctx(p, **kw):
    return ScanContext(
        timeout=2,
        credential_delay=0,
        service_ports={
            "mqtt": {p["mqtt"]}, "redis": {p["redis"]}, "snmp": {p["snmp"]},
            "rtsp": {p["rtsp"], p["rtsp_vendor"]}, "modbus": {p["modbus"]},
        },
        http_ports={p[k] for k in WEB},
        **kw,
    )


async def _scan(lab, scope, **kw):
    p = lab.ports
    ports = [v for k, v in p.items() if k != "snmp"]
    result = await run_scan([Target(host="127.0.0.1", ports=ports)], scope, _ctx(p, **kw))
    assert result.errors == []
    out = {}
    for f in result.findings:
        out.setdefault(f.check_id, []).append(f)
    return result, out


async def test_php_site_findings(lab, scope):
    p = lab.ports
    _, found = await _scan(lab, scope)
    http = [f for f in found["http_posture"] if f.port == p["web_php"]]
    assert any("End-of-life PHP runtime 7.4.33" in f.title for f in http)
    paths = {f.evidence["path"] for f in found["exposed_paths"] if f.port == p["web_php"]}
    assert {"/uploads/", "/phpmyadmin/", "/backup.sql", "/.htpasswd"} <= paths
    assert all("CREATE TABLE" not in str(f.model_dump()) for f in found["exposed_paths"])


async def test_camera_fingerprint_and_onvif(lab, scope):
    p = lab.ports
    _, found = await _scan(lab, scope)
    cam = [f for f in found["camera_fingerprint"]]
    assert [f.port for f in cam] == [p["web_camera"]] and cam[0].evidence["hint"] == "nvr"
    onvif = {f.severity.name: f for f in found["onvif_exposed"]}
    assert set(onvif) == {"INFO", "MEDIUM"} and all(f.port == p["web_camera"] for f in onvif.values())
    assert {"Manufacturer", "Model", "FirmwareVersion"} <= set(onvif["MEDIUM"].evidence["fields_disclosed"])


async def test_rtsp_vendor_path_detection(lab, scope):
    p = lab.ports
    _, found = await _scan(lab, scope)
    by_port = {f.port: f for f in found["rtsp_unauth"]}
    vendor = by_port[p["rtsp_vendor"]]
    assert vendor.evidence["paths"] == ["/Streaming/Channels/101"] and vendor.confidence == "high"
    assert "/" in by_port[p["rtsp"]].evidence["paths"]


async def test_modbus_requires_industrial_opt_in(lab, scope):
    p = lab.ports
    _, without = await _scan(lab, scope)
    assert "modbus_unauth" not in without
    _, with_flag = await _scan(lab, scope, allow_industrial_probes=True)
    f = with_flag["modbus_unauth"][0]
    assert f.port == p["modbus"] and f.evidence["reply"] == "device_id"
    assert "FC 0x2B" in f.evidence["request"]
    assert "default_credentials" not in with_flag  # credential opt-in stays independent


async def test_non_camera_sites_are_not_fingerprinted(lab, scope):
    p = lab.ports
    _, found = await _scan(lab, scope)
    flagged = {f.port for f in found["camera_fingerprint"]} | {f.port for f in found["onvif_exposed"]}
    assert not flagged & {p["web_leaky"], p["web_php"], p["web_basic"], p["web_form"]}


async def test_profile_conformance_flags_unexpected_ports(lab, scope):
    _, none = await _scan(lab, scope)
    assert "profile_conformance" not in none  # no profile selected -> silent
    _, found = await _scan(lab, scope, profile=BUILTIN["camera"])
    assert len(found["profile_conformance"]) >= 5
    assert all(f.evidence["profile"] == "camera" for f in found["profile_conformance"])
