"""Persistence boundary: the rest of the app never touches SQLAlchemy directly."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from exposureguard.domain.models import ScanResult
from exposureguard.storage.db import AuditRow, Base, FindingRow, ScanRow


class Repository:
    def __init__(self, url: str) -> None:
        kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, **kwargs)
        Base.metadata.create_all(self.engine)

    def save_scan(self, result: ScanResult) -> None:
        with Session(self.engine) as s, s.begin():
            s.add(
                ScanRow(
                    id=result.id,
                    started_at=result.started_at,
                    finished_at=result.finished_at,
                    score=result.score,
                    grade=result.grade,
                    payload=result.model_dump_json(),
                )
            )
            s.add_all(
                FindingRow(
                    scan_id=result.id,
                    check_id=f.check_id,
                    severity=int(f.severity),
                    host=f.host,
                    port=f.port,
                )
                for f in result.findings
            )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            return ScanResult.model_validate_json(row.payload) if row else None

    def list_scans(self, limit: int = 50) -> list[dict]:
        with Session(self.engine) as s:
            rows = s.scalars(select(ScanRow).order_by(ScanRow.started_at.desc()).limit(limit))
            return [
                {"id": r.id, "started_at": r.started_at, "score": r.score, "grade": r.grade}
                for r in rows
            ]

    def add_audit(self, actor: str, action: str, detail: dict) -> None:
        with Session(self.engine) as s, s.begin():
            s.add(
                AuditRow(ts=datetime.now(UTC), actor=actor, action=action, detail=json.dumps(detail))
            )

    def list_audit(self, limit: int = 100) -> list[dict]:
        with Session(self.engine) as s:
            rows = s.scalars(select(AuditRow).order_by(AuditRow.id.desc()).limit(limit))
            return [
                {"ts": r.ts, "actor": r.actor, "action": r.action, "detail": json.loads(r.detail)}
                for r in rows
            ]
