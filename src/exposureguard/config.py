"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

ROLES = ("viewer", "scanner", "admin")
MIN_KEY_LENGTH = 16


@dataclass(frozen=True)
class ApiKey:
    name: str
    role: str
    key: str


@dataclass(frozen=True)
class Settings:
    api_keys: tuple[ApiKey, ...] = ()
    scope_file: str = "./scope.yaml"
    database_url: str = "sqlite:///./exposureguard.db"
    scan_rate_limit_per_minute: int = 10

    @classmethod
    def from_env(cls) -> Settings:
        """EG_API_KEYS="name:role:key,..." (roles: viewer, scanner, admin). EG_API_KEY = one admin."""
        keys: list[ApiKey] = []
        for item in filter(None, (os.environ.get("EG_API_KEYS") or "").split(",")):
            try:
                name, role, key = item.strip().split(":", 2)
            except ValueError as exc:
                raise ValueError("EG_API_KEYS entries must look like name:role:key") from exc
            keys.append(ApiKey(name, role, key))
        legacy = os.environ.get("EG_API_KEY")
        if legacy:
            keys.append(ApiKey("default", "admin", legacy))
        names: set[str] = set()
        secrets: set[str] = set()
        for k in keys:
            if not k.name or len(k.name) > 64 or k.name.strip() != k.name:
                raise ValueError("API key names must be 1-64 characters with no surrounding whitespace")
            if k.name in names:
                raise ValueError(f"duplicate API key name: {k.name}")
            names.add(k.name)
            if k.role not in ROLES:
                raise ValueError(f"unknown role '{k.role}' for key '{k.name}' (use {ROLES})")
            if len(k.key) < MIN_KEY_LENGTH:
                raise ValueError(f"API key '{k.name}' is shorter than {MIN_KEY_LENGTH} characters")
            if k.key in secrets:
                raise ValueError("API key values must be unique")
            secrets.add(k.key)

        try:
            rate_limit = int(os.environ.get("EG_SCAN_RATE_LIMIT", "10"))
        except ValueError as exc:
            raise ValueError("EG_SCAN_RATE_LIMIT must be a positive integer") from exc
        if rate_limit < 1:
            raise ValueError("EG_SCAN_RATE_LIMIT must be a positive integer")

        return cls(
            api_keys=tuple(keys),
            scope_file=os.environ.get("EG_SCOPE_FILE", "./scope.yaml"),
            database_url=os.environ.get("EG_DATABASE_URL", "sqlite:///./exposureguard.db"),
            scan_rate_limit_per_minute=rate_limit,
        )
