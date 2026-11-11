"""Per-scan DNS snapshots and pinned socket connection helpers."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from dataclasses import dataclass

MAX_DNS_ADDRESSES = 16


class ResolutionError(RuntimeError):
    """Raised when a target cannot be resolved and validated safely."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    host: str
    addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.addresses:
            raise ValueError("a resolved target must contain at least one address")
        normalized = tuple(str(ipaddress.ip_address(item)) for item in self.addresses)
        if normalized != self.addresses or len(set(normalized)) != len(normalized):
            raise ValueError("resolved addresses must be unique canonical IP literals")


async def resolve_target(
    host: str, timeout: float = 3.0, max_addresses: int = MAX_DNS_ADDRESSES
) -> ResolvedTarget:
    """Resolve A/AAAA once with a bounded timeout and deterministic address ordering."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                timeout=timeout,
            )
        except (OSError, TimeoutError) as exc:
            raise ResolutionError(
                f"DNS resolution failed for {host}: {type(exc).__name__}"
            ) from exc
        values: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for family, _, _, _, sockaddr in records:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                values.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError as exc:
                raise ResolutionError("resolver returned a malformed address") from exc
        if not values:
            raise ResolutionError(f"DNS returned no usable addresses for {host}")
        if len(values) > max_addresses:
            raise ResolutionError(f"DNS answer set exceeds {max_addresses} addresses")
        addresses = tuple(str(item) for item in sorted(values, key=lambda ip: (ip.version, ip.packed)))
    else:
        addresses = (str(literal),)
    return ResolvedTarget(host=host, addresses=addresses)


async def open_pinned_connection(
    target: ResolvedTarget,
    port: int,
    timeout: float,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect only to snapshot IPs; retain the original hostname for TLS SNI."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    last_error: OSError | TimeoutError | None = None
    for address in target.addresses:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("pinned connection deadline exceeded") from last_error
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    port,
                    ssl=ssl_context,
                    server_hostname=target.host if ssl_context is not None else None,
                ),
                timeout=remaining,
            )
        except (OSError, TimeoutError) as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("no pinned address was available")
