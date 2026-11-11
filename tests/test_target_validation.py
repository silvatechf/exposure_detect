import pytest
from pydantic import ValidationError

from exposureguard.domain.models import Target


@pytest.mark.parametrize("host", ["https://example.com", "example.com/path", "user@example.com", "bad host", "example.com?x=1"])
def test_target_rejects_url_syntax_and_invalid_hosts(host):
    with pytest.raises(ValidationError):
        Target(host=host)


def test_target_normalizes_hostname():
    assert Target(host="GW.LAB.EXAMPLE.COM").host == "gw.lab.example.com"


def test_target_accepts_ipv4_and_ipv6():
    assert Target(host="192.0.2.10").host == "192.0.2.10"
    assert Target(host="2001:db8::1").host == "2001:db8::1"


def test_target_rejects_duplicate_or_invalid_ports():
    with pytest.raises(ValidationError):
        Target(host="device.lab", ports=[80, 80])
    with pytest.raises(ValidationError):
        Target(host="device.lab", ports=[0, 80])


def test_target_rejects_excessive_port_lists():
    with pytest.raises(ValidationError):
        Target(host="device.lab", ports=list(range(1, 258)))


def test_target_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        Target(host="device.lab", unexpected="value")
