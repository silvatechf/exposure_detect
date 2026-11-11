"""SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers.

Network findings have no source file, so each result is anchored to a configurable repository file
(`artifact_uri`, default README.md). The real target is kept in the message and logicalLocations.
"""

from __future__ import annotations

import json

from exposureguard import __version__
from exposureguard.domain.models import ScanResult, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.5",
}


def render(result: ScanResult, artifact_uri: str = "README.md") -> str:
    from exposureguard.engine.registry import all_checks

    titles = {cid: cls.title for cid, cls in all_checks().items()}
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rule = rules.setdefault(
            f.check_id,
            {
                "id": f.check_id,
                "name": f.check_id,
                "shortDescription": {"text": titles.get(f.check_id, f.check_id)},
                "properties": {
                    "tags": ["security", "exposure"],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            },
        )
        rule["properties"]["security-severity"] = max(
            rule["properties"]["security-severity"], _SECURITY_SEVERITY[f.severity], key=float
        )
        where = f"{f.host}:{f.port}" if f.port else f.host
        results.append(
            {
                "ruleId": f.check_id,
                "level": _LEVEL[f.severity],
                "message": {"text": f"{f.title} on {where}. {f.description} Fix: {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": artifact_uri}},
                        "logicalLocations": [{"name": where, "kind": "resource"}],
                    }
                ],
                "partialFingerprints": {"exposureguard/v1": f.fingerprint},
                "properties": {"confidence": f.confidence, "standards": f.standards},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ExposureGuard",
                        "version": __version__,
                        "informationUri": "https://example.invalid/exposureguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
