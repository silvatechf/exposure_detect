"""SQLAlchemy tables. Summary columns are indexed; the full result is kept as JSON."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(1))
    payload: Mapped[str] = mapped_column(Text)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    check_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[int] = mapped_column(Integer, index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    port: Mapped[int | None]


class AuditRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime]
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(Text)
