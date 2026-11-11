"""Check contract and the shared context passed to every check."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from exposureguard.domain.models import Finding, Target
from exposureguard.profiles import Profile
from exposureguard.networking.resolution import ResolvedTarget


@dataclass
class ScanContext:
    timeout: float = 3.0
    allow_credential_checks: bool = False
    allow_industrial_probes: bool = False
    profile: Profile | None = None
    max_credential_attempts: int = 3
    credential_delay: float = 0.5
    http_ports: set[int] = field(default_factory=lambda: {80, 8080})
    https_ports: set[int] = field(default_factory=lambda: {443, 8443})
    service_ports: dict[str, set[int]] = field(
        default_factory=lambda: {"mqtt": {1883}, "redis": {6379}, "rtsp": {554}, "snmp": {161}, "modbus": {502}}
    )
    open_ports: dict[str, set[int]] = field(default_factory=dict)
    resolved_targets: dict[str, ResolvedTarget] = field(default_factory=dict)
    network_semaphore: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(64), repr=False
    )


class Check(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    opt_in: ClassVar[str | None] = None  # None, "credentials" or "industrial"
    depends_on_ports: ClassVar[bool] = True

    @abstractmethod
    async def run(self, target: Target, ctx: ScanContext) -> list[Finding]:
        """Inspect one target and return findings. Must never raise for network errors."""
