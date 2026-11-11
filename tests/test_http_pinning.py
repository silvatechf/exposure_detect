import asyncio

import httpx
import pytest

from exposureguard.networking.http import pinned_client

from .helpers import PlainHandler, serve


class HostEchoHandler(PlainHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.headers.get("Host", "").encode())


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
        assert "localhost" not in queried_hosts
    finally:
        server.shutdown()


async def test_http_host_header_keeps_original_hostname_and_port():
    server, port = serve(HostEchoHandler)
    try:
        async with pinned_client(
            "device.lab.example", ("127.0.0.1",), timeout=2.0, verify=False
        ) as client:
            response = await client.get(f"http://device.lab.example:{port}/")
        assert response.text == f"device.lab.example:{port}"
    finally:
        server.shutdown()


async def test_http_transport_rejects_origin_outside_snapshot():
    async with pinned_client(
        "device.lab.example", ("192.0.2.10",), timeout=1.0, verify=False
    ) as client:
        with pytest.raises(httpx.NetworkError, match="origin does not match"):
            await client.get("http://other.lab.example/")


async def test_https_transport_preserves_original_sni_and_certificate_hostname(tmp_path):
    import shutil
    import ssl
    import subprocess

    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL executable is required for the local TLS fixture")
    certificate = tmp_path / "server.crt"
    private_key = tmp_path / "server.key"
    subprocess.run(  # noqa: S603
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "2",
            "-subj",
            "/CN=camera.lab.example",
            "-addext",
            "subjectAltName=DNS:camera.lab.example",
        ],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=certificate, keyfile=private_key)
    observed_sni = []

    def capture_sni(ssl_object, server_name, initial_context):
        observed_sni.append(server_name)

    server_context.set_servername_callback(capture_sni)

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nok"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(
        handle, "127.0.0.1", 0, ssl=server_context
    )
    port = server.sockets[0].getsockname()[1]
    client_context = ssl.create_default_context(cafile=str(certificate))
    try:
        async with pinned_client(
            "camera.lab.example",
            ("127.0.0.1",),
            timeout=2.0,
            verify=client_context,
        ) as client:
            response = await client.get(f"https://camera.lab.example:{port}/")
        assert response.status_code == 200
        assert observed_sni == ["camera.lab.example"]

        async with pinned_client(
            "wrong.lab.example",
            ("127.0.0.1",),
            timeout=2.0,
            verify=client_context,
        ) as client:
            with pytest.raises(httpx.NetworkError):
                await client.get(f"https://wrong.lab.example:{port}/")
        assert observed_sni == ["camera.lab.example", "wrong.lab.example"]
    finally:
        server.close()
        await server.wait_closed()
