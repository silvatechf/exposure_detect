"""Device profiles: which TCP ports are expected on a given kind of device.

Built-ins are conservative starting points, not authority. Tune them with --profile-file.
A profile only adds "unexpected port" findings; risky services are already reported by
exposed_services, so those ports are not reported twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    allowed_ports: frozenset[int] = field(default_factory=frozenset)


BUILTIN: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile("camera", "IP camera / DVR / NVR", frozenset({80, 443, 554, 8554, 8000, 8080, 8443, 37777})),
        Profile("sensor", "Telemetry sensor", frozenset({80, 443, 8883})),
        Profile("industrial-gateway", "Industrial gateway", frozenset({22, 80, 443, 4840, 8883})),
        Profile("plc", "Programmable logic controller", frozenset({80, 102, 443, 502, 44818})),
        Profile("generic-web", "Device with only a web interface", frozenset({80, 443})),
    )
}


def load_profile(name_or_path: str) -> Profile:
    if name_or_path in BUILTIN:
        return BUILTIN[name_or_path]
    path = Path(name_or_path)
    if not path.exists():
        raise ValueError(f"unknown profile '{name_or_path}' (built-in: {', '.join(sorted(BUILTIN))}) or file not found")
    data = yaml.safe_load(path.read_text()) or {}
    ports = data.get("allowed_ports")
    if not data.get("name") or not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
        raise ValueError("profile file needs 'name' and a list of integer 'allowed_ports'")
    return Profile(str(data["name"]), str(data.get("description", "")), frozenset(ports))
