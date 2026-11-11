"""Scope enforcement: ExposureGuard only scans what the owner has declared."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml


class ScopeError(Exception):
    """Raised when a target is outside the authorised scope or the scope is invalid."""


@dataclass
class Scope:
    owner: str
    authorized_by: str
    valid_until: date | None
    allowed: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> Scope:
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}. Copy scope.example.yaml and edit it.")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ScopeError(f"cannot read scope file: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise ScopeError("scope file must contain a YAML mapping")

        for key in ("owner", "authorized_by"):
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ScopeError(f"scope field '{key}' must be a non-empty string")

        allowed = data.get("allowed")
        denied = data.get("denied", [])
        if not isinstance(allowed, list) or not allowed:
            raise ScopeError("scope field 'allowed' must be a non-empty list")
        if not isinstance(denied, list):
            raise ScopeError("scope field 'denied' must be a list")
        for field_name, entries in (("allowed", allowed), ("denied", denied)):
            if any(not isinstance(item, str) or not item.strip() for item in entries):
                raise ScopeError(f"every entry in '{field_name}' must be a non-empty string")

        raw_valid = data.get("valid_until")
        try:
            valid_until = date.fromisoformat(str(raw_valid)) if raw_valid else None
        except ValueError as exc:
            raise ScopeError("scope field 'valid_until' must use YYYY-MM-DD") from exc

        return cls(
            owner=data["owner"].strip(),
            authorized_by=data["authorized_by"].strip(),
            valid_until=valid_until,
            allowed=[item.strip() for item in allowed],
            denied=[item.strip() for item in denied],
        )

    @staticmethod
    def _matches(host: str, rule: str) -> bool:
        host = host.lower().strip()
        rule = rule.lower().strip()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            try:
                return ip in ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return False
        if rule.startswith("*."):
            return host.endswith(rule[1:])
        return host == rule

    def check(self, host: str, today: date | None = None) -> None:
        today = today or date.today()
        if self.valid_until and today > self.valid_until:
            raise ScopeError(f"scope expired on {self.valid_until}")
        if any(self._matches(host, r) for r in self.denied):
            raise ScopeError(f"target explicitly denied by scope: {host}")
        if not any(self._matches(host, r) for r in self.allowed):
            raise ScopeError(f"target not in authorised scope: {host}")
