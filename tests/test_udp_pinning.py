import asyncio

from exposureguard.checks._net import udp_exchange
from exposureguard.networking.resolution import ResolvedTarget


class EchoDatagram(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(b"echo:" + data, addr)


async def test_udp_exchange_uses_snapshot_ip_without_hostname_resolution(monkeypatch):
    loop = asyncio.get_running_loop()
    server_transport, _ = await loop.create_datagram_endpoint(
        EchoDatagram, local_addr=("127.0.0.1", 0)
    )
    port = server_transport.get_extra_info("sockname")[1]
    original_getaddrinfo = loop.getaddrinfo
    queried_hosts = []

    async def guarded_getaddrinfo(host, *args, **kwargs):
        queried_hosts.append(host)
        assert host != "camera.lab.example"
        return await original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", guarded_getaddrinfo)
    try:
        result = await udp_exchange(
            ResolvedTarget("camera.lab.example", ("127.0.0.1",)),
            port,
            b"probe",
            timeout=1.0,
        )
        assert result == b"echo:probe"
        assert "camera.lab.example" not in queried_hosts
    finally:
        server_transport.close()


async def test_raw_tcp_protocol_exchange_uses_snapshot_ip_without_hostname_resolution(
    monkeypatch,
):
    from exposureguard.checks._net import exchange

    loop = asyncio.get_running_loop()
    received = asyncio.Event()

    async def handle(reader, writer):
        try:
            payload = await reader.read(128)
            assert payload.startswith(b"DESCRIBE rtsp://camera.lab.example/")
            writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
            await writer.drain()
            received.set()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    original_getaddrinfo = loop.getaddrinfo

    async def guarded_getaddrinfo(host, *args, **kwargs):
        assert host != "camera.lab.example"
        return await original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(loop, "getaddrinfo", guarded_getaddrinfo)
    try:
        response = await exchange(
            ResolvedTarget("camera.lab.example", ("127.0.0.1",)),
            port,
            b"DESCRIBE rtsp://camera.lab.example/ RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            timeout=1.0,
        )
        assert response is not None and response.startswith(b"RTSP/1.0 200")
        assert received.is_set()
    finally:
        server.close()
        await server.wait_closed()
