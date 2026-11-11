"""API authentication and role checks. Secure by default: no keys configured means no API."""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request

from exposureguard.config import ROLES


@dataclass(frozen=True)
class Actor:
    name: str
    role: str


def require_role(minimum: str):
    rank = {r: i for i, r in enumerate(ROLES)}

    def dependency(request: Request, x_api_key: str | None = Header(default=None)) -> Actor:
        keys = request.app.state.settings.api_keys
        if not keys:
            raise HTTPException(503, "API disabled: no API keys configured")
        if not x_api_key:
            raise HTTPException(401, "invalid or missing API key")
        matched = None
        for k in keys:  # compare against every key to keep timing independent of position
            if hmac.compare_digest(x_api_key, k.key):
                matched = k
        if matched is None:
            raise HTTPException(401, "invalid or missing API key")
        if rank[matched.role] < rank[minimum]:
            raise HTTPException(403, f"role '{matched.role}' cannot perform this action")
        return Actor(matched.name, matched.role)

    return dependency


viewer = Depends(require_role("viewer"))
scanner = Depends(require_role("scanner"))
admin = Depends(require_role("admin"))
