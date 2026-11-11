"""Check registry: add a check by decorating its class."""

from __future__ import annotations

from exposureguard.engine.base import Check

_REGISTRY: dict[str, type[Check]] = {}


def register(cls: type[Check]) -> type[Check]:
    _REGISTRY[cls.id] = cls
    return cls


def all_checks() -> dict[str, type[Check]]:
    from exposureguard import checks  # noqa: F401  (import side effect: registration)

    return dict(_REGISTRY)
