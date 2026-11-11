from __future__ import annotations

from exposureguard.domain.models import ScanResult


def render(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
