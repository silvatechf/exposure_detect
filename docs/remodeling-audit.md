# ExposureDetect — v0.3.1 hardening review

## Scope

This review was performed against the supplied `exposure_device.zip` archive. The archive does not include Git metadata, so branch history, remote state, protected-branch rules and existing pull requests could not be inspected.

## Preserved capabilities

- Modular asynchronous check registry and two-phase discovery/inspection runner.
- CLI, FastAPI API, SQLite/PostgreSQL repository boundary and role-based API keys.
- Scope-file enforcement, opt-in credential and industrial checks.
- HTTP/TLS, exposed-service, MQTT, Redis, RTSP, ONVIF, SNMP and read-only Modbus checks.
- JSON, Markdown and SARIF reporting, baseline comparison and GitHub Action definition.
- Local fake-device lab and existing integration test suite.

## Changes in 0.3.1

- Target host validation rejects URL syntax, whitespace and malformed hostnames; hostnames are normalized and duplicate/invalid ports are rejected.
- IPv6 literals are formatted correctly when used in HTTP and RTSP URL authorities.
- Scope loading validates YAML shape, required strings, allow/deny lists and ISO dates. Read/parse/validation errors fail closed through `ScopeError`.
- Swagger, ReDoc and the OpenAPI schema endpoint are disabled by default.
- API key names and key values must be unique; names must be non-empty; scan rate limit must be a positive integer.
- TCP service discovery now shares a bounded semaphore (64 simultaneous connection attempts) across the scan context.
- Regression tests cover the new input, configuration, API and URL-formatting boundaries.

## Validation evidence

- `PYTHONPATH=src python -m pytest -q`: **81 passed**.
- `PYTHONPATH=src python -m exposureguard.cli checks`: passed; all registered checks listed.
- `PYTHONPATH=src python -m compileall -q src`: passed.
- Ruff was not available in the execution environment; lint status is therefore unverified.
- Docker, PostgreSQL/Compose and the GitHub Action were not executed in this environment.
- Validation used Python 3.13.5; the declared Python 3.11+ compatibility matrix was not exercised across all supported versions.
- The supplied tests exercise deliberately insecure local fake devices, not real IoT/industrial hardware.

## Remaining risks and next engineering priorities

1. **DNS pinning / rebinding:** domain scope checks the requested hostname, but resolved addresses are not pinned and revalidated for the entire scan. Use controlled DNS and restrictive egress until this is implemented.
2. **Audit integrity:** audit events are stored in the same database without tamper-evident chaining or external anchoring.
3. **Operational controls:** rate limiting is per process; there is no durable scan queue, cancellation API, tenant isolation or retention policy.
4. **Production validation:** PostgreSQL, Docker hardening, GitHub Action permissions/SARIF upload and real-device false-positive rates remain unverified.
5. **Standards mapping:** ETSI/OWASP references remain indicative and must not be presented as certification or compliance evidence.

## Release assessment

`0.3.1` is a tested hardening update for the supplied codebase, not a production-readiness certification. The next release should prioritize DNS resolution/pinning and real-lab validation before adding more protocol checks or platform features.

## Additional hardening (0.3.2)

- HTTP checks now set `trust_env=False`. Scanner traffic therefore ignores ambient `HTTP_PROXY`, `HTTPS_PROXY` and related proxy environment settings; deployments that require an explicit proxy need a deliberate, reviewed configuration feature rather than implicit process state.
- The API now reserves credential and industrial opt-in probes for `admin` API identities. A `scanner` identity can run standard posture checks but cannot activate these higher-impact probes. Denials are recorded in the audit log.
- API scan batches are capped at 16 targets, and each target accepts at most 256 explicit ports. Unknown fields are rejected by Pydantic rather than silently ignored.
- API key identity length is bounded to the database column width (64 characters).
- Regression coverage was added for these controls.

These changes do **not** solve DNS rebinding. Domain authorization is still checked against the supplied hostname, while individual network libraries resolve names at connection time. Until connection-time IP pinning and scope revalidation are implemented, use controlled DNS, strict outbound firewall rules, and IP/CIDR scope entries for sensitive environments.
