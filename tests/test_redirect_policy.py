import httpx
import pytest

from exposureguard.checks.http_form_login import _get_same_host, _origin


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



@pytest.mark.asyncio
async def test_redirect_to_different_port_is_not_followed():
    requested = []

    async def handler(request):
        requested.append(str(request.url))
        return httpx.Response(
            302, headers={"location": "http://device.example:8080/admin"}, request=request
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        response = await _get_same_host(client, "http://device.example/", "device.example")

    assert response is None
    assert requested == ["http://device.example/"]


@pytest.mark.asyncio
async def test_same_origin_redirect_is_followed_within_hop_limit():
    requested = []

    async def handler(request):
        requested.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/login"}, request=request)
        return httpx.Response(200, text="login", request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        response = await _get_same_host(client, "http://device.example/", "device.example")

    assert response is not None and response.status_code == 200
    assert requested == ["http://device.example/", "http://device.example/login"]
