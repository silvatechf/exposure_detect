"""Detect end-of-life language runtimes disclosed in HTTP headers (PHP for now)."""

from __future__ import annotations

import json
import re
from datetime import date
from importlib import resources

_DATA = json.loads(resources.files("exposureguard.data").joinpath("runtime_eol.json").read_text())
_PHP_RE = re.compile(r"PHP/(\d+)\.(\d+)(?:\.(\d+))?", re.I)
APPROACHING_DAYS = 120


def php_status(header: str, today: date | None = None) -> tuple[str, str, date | None] | None:
    """Return (version, status, eol_date) with status in {"eol", "approaching"}; None if fine/unknown."""
    m = _PHP_RE.search(header or "")
    if not m:
        return None
    today = today or date.today()
    major, minor = int(m.group(1)), int(m.group(2))
    version = ".".join(x for x in m.groups() if x is not None)
    if (major, minor) < (7, 4):
        return version, "eol", None  # 5.x, 7.0-7.3 are all long out of support
    raw = _DATA["php"].get(f"{major}.{minor}")
    if raw is None:
        return None  # newer than our table: do not guess
    eol = date.fromisoformat(raw)
    if today > eol:
        return version, "eol", eol
    if (eol - today).days <= APPROACHING_DAYS:
        return version, "approaching", eol
    return None
