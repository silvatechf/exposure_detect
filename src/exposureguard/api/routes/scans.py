from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from exposureguard.api.deps import Actor, scanner, viewer
from exposureguard.domain.models import ScanResult, Target
from exposureguard.engine.base import ScanContext
from exposureguard.engine.runner import run_scan
from exposureguard.reporting import json_report, markdown_report, sarif
from exposureguard.scope import Scope, ScopeError

router = APIRouter(prefix="/scans")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[Target] = Field(min_length=1, max_length=16)
    allow_credential_checks: bool = False
    allow_industrial_probes: bool = False


@router.post("", response_model=ScanResult)
async def create_scan(body: ScanRequest, request: Request, actor: Actor = scanner) -> ScanResult:
    state = request.app.state
    detail = {
        "targets": [t.host for t in body.targets],
        "allow_credential_checks": body.allow_credential_checks,
        "allow_industrial_probes": body.allow_industrial_probes,
    }
    if (body.allow_credential_checks or body.allow_industrial_probes) and actor.role != "admin":
        state.repo.add_audit(actor.name, "scan.privileged_probe_denied", detail)
        raise HTTPException(403, "privileged probes require an admin API key")
    if not state.limiter.allow(actor.name):
        state.repo.add_audit(actor.name, "scan.rate_limited", detail)
        raise HTTPException(429, "scan rate limit exceeded")
    try:
        scope = Scope.load(state.settings.scope_file)  # re-read: edits apply immediately
        result = await run_scan(
            body.targets,
            scope,
            ScanContext(
                allow_credential_checks=body.allow_credential_checks,
                allow_industrial_probes=body.allow_industrial_probes,
            ),
        )
    except ScopeError as exc:
        state.repo.add_audit(actor.name, "scan.denied", {**detail, "reason": str(exc)})
        raise HTTPException(403, str(exc)) from exc
    state.repo.save_scan(result)
    state.repo.add_audit(actor.name, "scan.create", {**detail, "scan_id": result.id})
    return result


@router.get("")
def list_scans(request: Request, actor: Actor = viewer) -> list[dict]:
    return request.app.state.repo.list_scans()


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str, request: Request, actor: Actor = viewer) -> ScanResult:
    result = request.app.state.repo.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "scan not found")
    return result


@router.get("/{scan_id}/report", response_class=PlainTextResponse)
def get_report(
    scan_id: str,
    request: Request,
    fmt: Literal["md", "json", "sarif"] = "md",
    actor: Actor = viewer,
) -> PlainTextResponse:
    result = request.app.state.repo.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "scan not found")
    render = {"md": markdown_report.render, "json": json_report.render, "sarif": sarif.render}[fmt]
    return PlainTextResponse(render(result))
