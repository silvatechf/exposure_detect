from __future__ import annotations

import pytest

from exposureguard.scope import Scope


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        "owner: Test Owner\nauthorized_by: Tester\nallowed:\n  - 127.0.0.0/8\n"
    )
    return p


@pytest.fixture
def scope(scope_file):
    return Scope.load(scope_file)
