"""Optional PostgreSQL integration test; CI supplies an ephemeral PostgreSQL service."""

from __future__ import annotations

import os
import uuid

import pytest

from exposureguard.domain.models import ScanResult, Target
from exposureguard.storage.repository import Repository


def test_postgresql_repository_roundtrip() -> None:
    url = os.environ.get("EG_TEST_DATABASE_URL")
    if not url:
        pytest.skip("EG_TEST_DATABASE_URL is not configured")

    repository = Repository(url)
    scan = ScanResult(targets=[Target(host="127.0.0.1")])
    actor = f"ci-{uuid.uuid4().hex[:12]}"

    try:
        repository.save_scan(scan)
        restored = repository.get_scan(scan.id)
        assert restored is not None
        assert restored.id == scan.id
        assert restored.targets[0].host == "127.0.0.1"

        repository.add_audit(actor, "test.postgres_roundtrip", {"scan_id": scan.id})
        events = repository.list_audit(limit=500)
        assert any(
            event["actor"] == actor
            and event["action"] == "test.postgres_roundtrip"
            and event["detail"]["scan_id"] == scan.id
            for event in events
        )
    finally:
        repository.engine.dispose()
