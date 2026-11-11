import asyncio
import socket
import ssl

import pytest

from exposureguard.networking.resolution import (
    ResolutionError,
    ResolvedTarget,
    open_pinned_connection,
    resolve_target,
)


async def test_ip_literal_bypasses_dns(monkeypatch):
    loop = asyncio.get_running_loop()

    async def forbidden(*args, **kwargs):
        raise AssertionError("DNS must not be called for an IP literal")

    monkeypatch.setattr(loop, "getaddrinfo", forbidden)
    result = await resolve_target("192.0.2.10")
    assert result.addresses == ("192.0.2.10",)


async def test_resolution_deduplicates_and_orders(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::2", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 0)),
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    result = await resolve_target("device.example")
    assert result.addresses == ("192.0.2.2", "2001:db8::2")


async def test_empty_dns_answer_fails_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        return []

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ResolutionError):
        await resolve_target("empty.example")


async def test_dns_timeout_fails_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        await asyncio.sleep(0.05)
        return []

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ResolutionError):
        await resolve_target("slow.example", timeout=0.001)


async def test_oversized_answer_fails_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{i}", 0))
            for i in range(1, 5)
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ResolutionError):
        await resolve_target("many.example", max_addresses=3)


async def test_pinned_connection_uses_numeric_address_and_original_tls_name(monkeypatch):
    from exposureguard.networking import resolution

    observed = {}

    async def fake_open_connection(host, port, **kwargs):
        observed.update(host=host, port=port, **kwargs)
        return object(), object()

    monkeypatch.setattr(resolution.asyncio, "open_connection", fake_open_connection)
    target = ResolvedTarget("camera.lab.example", ("192.0.2.10",))
    context = ssl.create_default_context()

    await open_pinned_connection(target, 443, 1.0, ssl_context=context)

    assert observed["host"] == "192.0.2.10"
    assert observed["port"] == 443
    assert observed["ssl"] is context
    assert observed["server_hostname"] == "camera.lab.example"


def test_resolved_target_rejects_noncanonical_and_duplicate_addresses():
    with pytest.raises(ValueError):
        ResolvedTarget("device.example", ("192.0.2.1", "192.0.2.1"))
    with pytest.raises(ValueError):
        ResolvedTarget("device.example", ("device.example",))


async def test_ipv6_literal_bypasses_dns(monkeypatch):
    loop = asyncio.get_running_loop()

    async def forbidden(*args, **kwargs):
        raise AssertionError("DNS must not be called for an IPv6 literal")

    monkeypatch.setattr(loop, "getaddrinfo", forbidden)
    result = await resolve_target("2001:db8::10")
    assert result.addresses == ("2001:db8::10",)


async def test_malformed_dns_socket_address_fails_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ())]

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ResolutionError, match="malformed"):
        await resolve_target("malformed.example")


async def test_malformed_dns_record_fails_closed(monkeypatch):
    loop = asyncio.get_running_loop()

    async def fake(*args, **kwargs):
        return [("incomplete",)]

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ResolutionError, match="malformed"):
        await resolve_target("malformed.example")
