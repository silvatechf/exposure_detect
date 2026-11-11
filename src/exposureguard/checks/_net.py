"""Small network helpers shared by checks."""

from __future__ import annotations

import asyncio
import ipaddress

from exposureguard.networking.resolution import ResolvedTarget, open_pinned_connection


def url_host(host: str) -> str:
    """Return a host literal safe for use in an HTTP/RTSP URL authority."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if address.version == 6 else host


async def exchange(
    target: ResolvedTarget, port: int, payload: bytes, timeout: float, nbytes: int = 512
) -> bytes | None:
    """Open a TCP connection, send payload, return the first bytes read (None on any failure)."""
    try:
        reader, writer = await open_pinned_connection(target, port, timeout)
    except (OSError, TimeoutError):
        return None
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.read(nbytes), timeout)
    except (OSError, TimeoutError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


class _FirstDatagram(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def udp_exchange(
    target: ResolvedTarget, port: int, payload: bytes, timeout: float
) -> bytes | None:
    """Probe only pinned addresses under one total deadline, regardless of answer count."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    for address in target.addresses:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return None
        transport = None
        try:
            transport, proto = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    _FirstDatagram, remote_addr=(address, port)
                ),
                timeout=remaining,
            )
            transport.sendto(payload)
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            return await asyncio.wait_for(proto.future, remaining)
        except (OSError, TimeoutError):
            continue
        finally:
            if transport is not None:
                transport.close()
    return None
