"""Domain models shared by the engine, storage, API and reports."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value}") from exc


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=255)
    ports: list[int] | None = Field(default=None, max_length=256)

    @field_validator("host")
    @classmethod
    def _valid_host(cls, value: str) -> str:
        host = value.strip()
        if host != value or any(char in host for char in ("/", "\\", "@", "#", "?")):
            raise ValueError("host must be a hostname or IP address, not a URL")
        if not host or any(char.isspace() for char in host) or "%" in host:
            raise ValueError("host contains invalid characters")
        try:
            ipaddress.ip_address(host)
            return host.lower()
        except ValueError:
            pass
        hostname = host[:-1] if host.endswith(".") else host
        if len(hostname) > 253 or not hostname:
            raise ValueError("invalid hostname length")
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid internationalised hostname") from exc
        labels = ascii_host.split(".")
        label_pattern = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
        if any(not label_pattern.fullmatch(label) for label in labels):
            raise ValueError("host must be a valid hostname or IP address")
        return ascii_host.lower()

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, v: list[int] | None) -> list[int] | None:
        if v is not None:
            if any(p < 1 or p > 65535 for p in v):
                raise ValueError("ports must be between 1 and 65535")
            if len(v) != len(set(v)):
                raise ValueError("ports must not contain duplicates")
        return v


class Finding(BaseModel):
    check_id: str
    title: str
    severity: Severity
    host: str
    port: int | None = None
    description: str
    remediation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    confidence: str = "high"
    standards: list[str] = Field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.check_id}|{self.host}|{self.port}|{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, v: Any) -> Any:
        return Severity.parse(v) if isinstance(v, str) else v

    @field_serializer("severity")
    def _serialize_severity(self, v: Severity) -> str:
        return v.name


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    targets: list[Target]
    findings: list[Finding] = Field(default_factory=list)
    score: int = 100
    grade: str = "A"
    errors: list[str] = Field(default_factory=list)
