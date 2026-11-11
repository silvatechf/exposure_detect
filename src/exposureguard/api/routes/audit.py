from __future__ import annotations

from fastapi import APIRouter, Request

from exposureguard.api.deps import Actor, admin

router = APIRouter(prefix="/audit")


@router.get("")
def list_audit(request: Request, limit: int = 100, actor: Actor = admin) -> list[dict]:
    return request.app.state.repo.list_audit(min(max(limit, 1), 500))
