import pytest

from exposureguard.checks.http_form_login import _origin


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://device.example/", ("http", "device.example", 80)),
        ("http://device.example:80/login", ("http", "device.example", 80)),
        ("https://device.example/", ("https", "device.example", 443)),
        ("https://device.example:8443/login", ("https", "device.example", 8443)),
        ("http://[2001:db8::1]:8080/", ("http", "2001:db8::1", 8080)),
    ],
)
def test_origin_normalizes_default_ports_and_ipv6(url, expected):
    assert _origin(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "ftp://device.example/",
        "http://user:pass@device.example/",
        "http://device.example:not-a-port/",
        "http:///missing-host/",
        "http://[invalid-ipv6/",
    ],
)
def test_origin_rejects_unsafe_or_malformed_urls(url):
    assert _origin(url) is None


def test_origin_distinguishes_scheme_host_and_port():
    origin = _origin("https://device.example/login")
    assert _origin("http://device.example/login") != origin
    assert _origin("https://other.example/login") != origin
    assert _origin("https://device.example:8443/login") != origin
