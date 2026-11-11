"""Deliberately insecure fake devices, bound to localhost, for demos and integration tests.

Never expose these to a real network. They exist so every check can be validated end to end
without touching real equipment.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from exposureguard.protocols import snmp

LOGIN_PAGE = (
    b"<html><body><form method='post' action='/login'>"
    b"<input type='hidden' name='csrf' value='abc123'>"
    b"<input type='text' name='user'><input type='password' name='pass'>"
    b"<input type='submit'></form></body></html>"
)


async def _redis(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), 5)
        if data.upper().startswith(b"PING"):
            writer.write(b"+PONG\r\n")
            await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def _rtsp_vendor(reader, writer):
    """Only the Hikvision-style path is open; everything else asks for credentials."""
    try:
        data = await asyncio.wait_for(reader.read(1024), 5)
        ok = b"/Streaming/Channels/101" in data
        writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n" if ok else b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n")
        await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def _modbus(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), 5)
        if len(data) >= 8 and data[7] == 0x2B:
            pdu = b"\x2b\x0e\x01\x01\x00\x00\x00"
            writer.write(data[0:2] + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + data[6:7] + pdu)
            await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def _mqtt(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(1024), 5)
        if data[:1] == b"\x10":
            writer.write(b"\x20\x02\x00\x00")  # CONNACK, accepted
            await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


async def _rtsp(reader, writer):
    try:
        await asyncio.wait_for(reader.read(1024), 5)
        writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
        await writer.drain()
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()


class _SnmpFake(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            _, community, tag = snmp.parse_message(data)
        except ValueError:
            return
        if tag == snmp.GET_REQUEST and community == b"public":
            self.transport.sendto(snmp.build_get_response(community), addr)


def _http_handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if mode == "basic":
                import base64

                ok = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:admin").decode()
                if ok:
                    self._send(200, b"ok")
                else:
                    self._send(401, b"", {"WWW-Authenticate": 'Basic realm="device"'})
            elif mode in ("form", "form_open"):
                if self.path == "/":
                    self._send(302, b"", {"Location": "/login"})
                elif self.path.startswith("/login"):
                    self._send(200, LOGIN_PAGE)
                elif self.path == "/dashboard":
                    self._send(200, b"Welcome")
                else:
                    self._send(404)
            elif mode == "php":
                files = {
                    "/": (b"<html>app</html>", {}),
                    "/uploads/": (b"<html><title>Index of /uploads</title></html>", {}),
                    "/phpmyadmin/": (b"<title>phpMyAdmin</title>", {}),
                    "/backup.sql": (b"CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);", {}),
                    "/.htpasswd": (b"admin:$apr1$abc$xyz\n", {}),
                }
                body, _ = files.get(self.path, (None, {}))
                self._send(
                    200 if body else 404,
                    body or b"nope",
                    {"Server": "Apache/2.4.7", "X-Powered-By": "PHP/7.4.33"},
                )
            elif mode == "camera":
                if self.path == "/":
                    self._send(200, b"<html><title>Network Video Recorder NVR Web Client</title></html>", {"Server": "App-webs"})
                else:
                    self._send(404)
            elif mode == "leaky":
                files = {
                    "/.env": b"DB_PASSWORD=hunter2\nSECRET_KEY=abc\n",
                    "/.git/config": b"[core]\n\trepositoryformatversion = 0\n",
                    "/phpinfo.php": b"<title>phpinfo()</title><h1>PHP Version 8.1.2</h1>",
                }
                body = files.get(self.path)
                self._send(200 if body else 404, body or b"nope", {"Server": "FakeHTTPd/2.4"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode()
            form = parse_qs(raw)
            if mode == "camera" and self.path == "/onvif/device_service":
                if "GetSystemDateAndTime" in raw:
                    self._send(200, b"<s:Envelope><GetSystemDateAndTimeResponse/></s:Envelope>")
                elif "GetDeviceInformation" in raw:
                    self._send(
                        200,
                        b"<s:Envelope><GetDeviceInformationResponse><Manufacturer>Acme</Manufacturer>"
                        b"<Model>X1</Model><FirmwareVersion>1.0</FirmwareVersion></GetDeviceInformationResponse></s:Envelope>",
                    )
                else:
                    self._send(400)
            elif mode == "form_open":
                self._send(302, b"", {"Location": "/dashboard", "Set-Cookie": "sid=1"})
            elif mode == "form":
                if form.get("user") == ["admin"] and form.get("pass") == ["admin"]:
                    self._send(302, b"", {"Location": "/dashboard", "Set-Cookie": "sid=1"})
                else:
                    self._send(200, LOGIN_PAGE + b"<p>Invalid credentials</p>")
            else:
                self._send(405)

    return Handler


@dataclass
class LabHandle:
    ports: dict[str, int] = field(default_factory=dict)
    _servers: list = field(default_factory=list)
    _http: list = field(default_factory=list)
    _udp: list = field(default_factory=list)

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
            await s.wait_closed()
        for t in self._udp:
            t.close()
        for h in self._http:
            h.shutdown()
            h.server_close()


async def start_all(host: str = "127.0.0.1", base_port: int | None = None) -> LabHandle:
    """Start all fake devices. base_port=None uses ephemeral ports (tests); otherwise sequential."""
    handle = LabHandle()
    counter = 0

    def next_port() -> int:
        nonlocal counter
        counter += 1
        return 0 if base_port is None else base_port + counter - 1

    loop = asyncio.get_running_loop()
    for name, cb in (
        ("redis", _redis),
        ("mqtt", _mqtt),
        ("rtsp", _rtsp),
        ("rtsp_vendor", _rtsp_vendor),
        ("modbus", _modbus),
    ):
        server = await asyncio.start_server(cb, host, next_port())
        handle._servers.append(server)
        handle.ports[name] = server.sockets[0].getsockname()[1]

    transport, _ = await loop.create_datagram_endpoint(_SnmpFake, local_addr=(host, next_port()))
    handle._udp.append(transport)
    handle.ports["snmp"] = transport.get_extra_info("sockname")[1]

    for name, mode in (
        ("web_basic", "basic"),
        ("web_form", "form"),
        ("web_form_open", "form_open"),
        ("web_leaky", "leaky"),
        ("web_php", "php"),
        ("web_camera", "camera"),
    ):
        httpd = ThreadingHTTPServer((host, next_port()), _http_handler(mode))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        handle._http.append(httpd)
        handle.ports[name] = httpd.server_address[1]
    return handle
