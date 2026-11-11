from datetime import date

import httpx
import pytest

from exposureguard import cli
from exposureguard.checks.http_headers import HttpHeadersCheck
from exposureguard.engine.base import Check, ScanContext
from exposureguard.engine.runner import _opted_in
from exposureguard.profiles import BUILTIN, load_profile
from exposureguard.protocols import modbus
from exposureguard.runtime_eol import php_status

TODAY = date(2026, 11, 11)


def test_php_eol_classification():
    assert php_status("PHP/5.6.40", TODAY)[1] == "eol"
    assert php_status("PHP/7.4.33", TODAY)[1] == "eol"
    assert php_status("PHP/8.1.20", TODAY)[1] == "eol"
    assert php_status("PHP/8.2.10", TODAY)[1] == "approaching"
    assert php_status("PHP/8.3.1", TODAY) is None
    assert php_status("PHP/9.9.0", TODAY) is None  # newer than our table: never guess
    assert php_status("nginx/1.25", TODAY) is None


def test_headers_check_flags_eol_php_with_medium_confidence():
    resp = httpx.Response(200, headers={"X-Powered-By": "PHP/7.4.33"})
    findings = HttpHeadersCheck()._analyse("h", 80, False, resp, TODAY)
    eol = [f for f in findings if "End-of-life PHP" in f.title]
    assert len(eol) == 1 and eol[0].confidence == "medium" and eol[0].severity.name == "HIGH"
    assert any("X-Powered-By" in f.title for f in findings)


def test_modbus_request_is_read_only_device_identification():
    req = modbus.build_read_device_id()
    assert req[7] == 0x2B                      # function code
    assert req[7] not in (0x05, 0x06, 0x0F, 0x10)  # no coil/register writes
    assert int.from_bytes(req[4:6], "big") == len(req) - 6


def test_modbus_response_parsing():
    ok = bytes.fromhex("000100000005012b0e0100")  # MBAP(len=5) + unit 1 + FC 0x2B reply
    assert modbus.parse_response(ok) == "device_id"
    exc = bytes.fromhex("000100000003" + "01" + "ab02")
    assert modbus.parse_response(exc) == "exception"
    assert modbus.parse_response(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert modbus.parse_response(ok[:4]) is None
    assert modbus.parse_response(bytes.fromhex("00990000000501" + "2b0e0100")) is None  # wrong transaction id


def test_builtin_and_file_profiles(tmp_path):
    assert load_profile("camera") is BUILTIN["camera"]
    f = tmp_path / "p.yaml"
    f.write_text("name: my-gw\nallowed_ports: [22, 443]\n")
    assert load_profile(str(f)).allowed_ports == frozenset({22, 443})


@pytest.mark.parametrize("content", ["name: x\n", "name: x\nallowed_ports: [a]\n", "allowed_ports: [1]\n"])
def test_bad_profile_files_rejected(tmp_path, content):
    f = tmp_path / "p.yaml"
    f.write_text(content)
    with pytest.raises(ValueError):
        load_profile(str(f))
    with pytest.raises(ValueError):
        load_profile("does-not-exist")


def test_unknown_opt_in_category_fails_closed():
    class Weird(Check):
        id, title, opt_in = "w", "w", "bogus"

        async def run(self, target, ctx):
            return []

    ctx = ScanContext(allow_credential_checks=True, allow_industrial_probes=True)
    assert _opted_in(Weird(), ctx) is False


def test_service_port_flags_accumulate_for_same_name():
    ports = cli._parse_service_ports(["rtsp=1000", "rtsp=2000", "mqtt=3000"])
    assert ports["rtsp"] == {1000, 2000} and ports["mqtt"] == {3000}
    with pytest.raises(ValueError):
        cli._parse_service_ports(["nope=1"])
