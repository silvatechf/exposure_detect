"""HTTPX transport that connects only to a pre-authorized DNS snapshot."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator
from typing import Any

import httpcore
import httpx


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, host: str, addresses: tuple[str, ...]) -> None:
        self._host = host.rstrip(".").lower()
        self._addresses = addresses
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        requested_host = host.rstrip(".").lower()
        if requested_host != self._host:
            raise httpcore.ConnectError("HTTP origin does not match the pinned target")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + (timeout if timeout is not None else 10.0)
        last_error: Exception | None = None
        for address in self._addresses:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise httpcore.ConnectTimeout("pinned HTTP connection deadline exceeded")
            try:
                return await asyncio.wait_for(
                    self._backend.connect_tcp(
                        address,
                        port,
                        timeout=remaining,
                        local_address=local_address,
                        socket_options=socket_options,
                    ),
                    timeout=remaining,
                )
            except (OSError, TimeoutError, httpcore.NetworkError) as exc:
                last_error = exc
        if isinstance(last_error, TimeoutError):
            raise httpcore.ConnectTimeout("pinned HTTP connection timed out") from last_error
        raise httpcore.ConnectError("unable to connect to any pinned address") from last_error

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix sockets are not supported for scoped HTTP targets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _HTTPXResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class PinnedHTTPTransport(httpx.AsyncBaseTransport):
    """Public HTTPX transport backed by httpcore's public network backend API."""

    def __init__(
        self, host: str, addresses: tuple[str, ...], *, verify: bool = False
    ) -> None:
        if verify:
            ssl_context = ssl.create_default_context()
        else:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=10,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            network_backend=_PinnedNetworkBackend(host, addresses),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = await self._pool.handle_async_request(core_request)
        except (\n            httpcore.NetworkError,\n            httpcore.TimeoutException,\n            httpcore.ProtocolError,\n            httpcore.UnsupportedProtocol,\n            httpcore.ConnectionNotAvailable,\n        ) as exc:
            raise httpx.NetworkError(
                f"pinned HTTP transport failed: {exc}", request=request
            ) from exc

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_HTTPXResponseStream(response.stream),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def pinned_client(
    host: str, addresses: tuple[str, ...], *, timeout: float, verify: bool = False
) -> httpx.AsyncClient:
    """Build a no-proxy, no-redirect client pinned to the scan's DNS snapshot."""
    transport = PinnedHTTPTransport(host, addresses, verify=verify)
    return httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        timeout=timeout,
        follow_redirects=False,
    )
