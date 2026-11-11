"""Indicative mapping from finding tags to security baselines.

These are supporting references, not a compliance claim or a certification.
"""

from __future__ import annotations

ETSI_5_1 = "ETSI EN 303 645 §5.1 No universal default passwords"
ETSI_5_5 = "ETSI EN 303 645 §5.5 Communicate securely"
ETSI_5_6 = "ETSI EN 303 645 §5.6 Minimize exposed attack surfaces"
OWASP_I1 = "OWASP IoT Top 10 (2018) I1 Weak, guessable, or hardcoded passwords"
OWASP_I2 = "OWASP IoT Top 10 (2018) I2 Insecure network services"
OWASP_I7 = "OWASP IoT Top 10 (2018) I7 Insecure data transfer and storage"

BY_TAG: dict[str, list[str]] = {
    "default-credentials": [ETSI_5_1, OWASP_I1],
    "attack-surface": [ETSI_5_6, OWASP_I2],
    "unauthenticated": [ETSI_5_6, OWASP_I2],
    "exposure": [ETSI_5_6, OWASP_I2],
    "cleartext": [ETSI_5_5, OWASP_I7],
    "tls": [ETSI_5_5, OWASP_I7],
}


def standards_for(tags: list[str]) -> list[str]:
    out: list[str] = []
    for tag in tags:
        for ref in BY_TAG.get(tag, []):
            if ref not in out:
                out.append(ref)
    return out
