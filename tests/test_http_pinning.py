import asyncio

import httpx
import pytest

from exposureguard.networking.http import pinned_client

from .helpers import PlainHandler, serve


async def test_http_transport_connects_to_snapshot_ip_without_resolving_origin_hostname(monkeypatch):
    server, port = serve(PlainHandler)
    loop = asyncio.get_running_loop()
    original_getaddrinfo = loop.getaddrinfo
    queried_hosts = []

    async def guarded_getaddrinfo(host, *args, **kwargs):
        queried_hosts.append(host)
        assert host != "localhost"
        return await original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", guarded_getaddrinfo)
    try:
        async with pinned_client(
            "localhost", ("127.0.0.1",), timeout=2.0, verify=False
        ) as client:
            response = await client.get(f"http://localhost:{port}/")
        assert response.status_code == 200
        assert "127.0.0.1" in queried_hosts
    finally:
        server.shutdown()


async def test_http_transport_rejects_origin_outside_snapshot():
    async with pinned_client(
        "device.lab.example", ("192.0.2.10",), timeout=1.0, verify=False
    ) as client:
        with pytest.raises(httpx.NetworkError, match="origin does not match"):
            await client.get("http://other.lab.example/")
