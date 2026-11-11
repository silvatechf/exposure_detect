# Roadmap

**Delivered in v0.3:** PHP/runtime disclosure and EOL checks, signature-verified exposed paths, RTSP vendor paths, ONVIF, camera fingerprinting, read-only Modbus identification, and device profiles.

## v0.4 — Security and validation
- [x] Resolve DNS once per scan, pin validated addresses, and revalidate scope at connection time to mitigate DNS rebinding (integrated via PR #10).
- [x] Exercise the SQLAlchemy repository against PostgreSQL 16 in CI on Python 3.11 and 3.12 (PR #12).
- [x] Add baseline container hardening and guard SARIF upload when no report was produced (PR #12).
- Validate the complete Docker Compose lifecycle and API/PostgreSQL integration on a local Docker host.
- Validate the GitHub Action and SARIF upload in a real caller workflow.
- Exercise the scanner against an isolated hardware lab (router, IP camera, and PLC simulator).
- Record reproducible false-positive cases and add sanitized fixtures from authorized test devices.

## v0.5 — Detection depth
- Add opt-in SSH/Telnet authentication posture checks with strict attempt limits.
- Add UPnP/SSDP and CoAP discovery with explicit scope and conservative timeouts.
- Add read-only protocol identification for S7comm and EtherNet/IP only after protocol safety review.
- Expand runtime lifecycle data (Node.js, Python, OpenSSL) with maintained source references.

## v0.6 — Operational maturity
- Add OIDC/SSO only where a concrete deployment requires it.
- Add tamper-evident audit integrity and documented retention controls.
- Add scheduled scans, cancellation, webhook delivery, and durable execution only after defining operational requirements.
- Define tenant isolation and authorization boundaries before offering multi-tenant operation.

## Release principles
- Prioritize authorization correctness, DNS/egress safety, reproducibility, and false-positive quality over adding more checks.
- Keep optional integrations loosely coupled; the scanner must remain fully useful as a standalone CLI, API, and CI component.
- Do not claim compliance, certification, or production readiness without independent evidence.
