"""Tiny local servers used as scan targets (127.0.0.1 only)."""

from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class PlainHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Server", "FakeDevice/1.2")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args) -> None:
        pass


def make_basic_handler(user: str, password: str):
    expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    class BasicHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Authorization") == expected:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="device"')
                self.end_headers()

        def log_message(self, *args) -> None:
            pass

    return BasicHandler


def serve(handler) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]
