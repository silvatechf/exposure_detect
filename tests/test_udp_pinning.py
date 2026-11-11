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
