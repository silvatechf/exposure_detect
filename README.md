# ExposureDetect

**Authorization-first exposure assessment for connected devices.**

ExposureDetect helps identify and document externally observable security exposure across explicitly scoped IoT devices, industrial gateways, cameras, and embedded web interfaces.

> **Project status:** active prototype, version 0.3.2. Automated tests cover the bundled local lab; real hardware, Docker Compose, PostgreSQL deployment, and the GitHub Action still require independent validation.

It answers one practical question:

> *What is reachable on this device that should not be, and is it secure by default?*

Python 3.11+, FastAPI, SQLAlchemy/SQLite, Typer, and HTTPX. No agents or heavyweight runtime dependencies.

## Capabilities

| Check | What it looks for | Default |
| --- | --- | --- |
| `exposed_services` | Risky reachable TCP services (Telnet, FTP, SMB, RDP, VNC, MQTT, Redis, MongoDB, Elasticsearch, Modbus, S7comm, DNP3, EtherNet/IP, Docker API, databases) | on |
| `http_posture` | Cleartext admin UI, missing security headers, `Server`/`X-Powered-By` banners, end-of-life PHP | on |
| `tls_posture` | Untrusted, expired or self-signed certificates; legacy TLS 1.0/1.1 | on |
| `mqtt_anonymous` | MQTT broker accepting anonymous connections | on |
| `redis_unauth` | Redis responding without authentication | on |
| `rtsp_unauth` | RTSP streams open without authentication, using a short list of common vendor paths | on |
| `onvif_exposed` | ONVIF service reachable and unauthenticated device information disclosure | on |
| `camera_fingerprint` | CCTV/DVR/NVR web interfaces reachable (informational) | on |
| `profile_conformance` | Ports unexpected for the selected device profile | with `--profile` |
| `exposed_paths` | Commonly exposed files and paths, verified by content signatures | on |
| `default_credentials` | HTTP Basic endpoints accepting generic factory defaults | opt-in |
| `http_form_login` | Web login forms accepting factory defaults (heuristic, medium confidence) | opt-in |
| `snmp_default` | SNMP agent answering community `public` (UDP) | opt-in |
| `modbus_unauth` | Modbus/TCP device answering one read-only identification request | opt-in (industrial) |

Findings include evidence, remediation guidance, confidence, and indicative references to ETSI EN 303 645 and OWASP IoT Top 10. These mappings are supporting references, **not compliance or certification claims**.

Outputs include a posture score (0–100, grade A–F), Markdown/JSON/SARIF reports, baseline comparison, and CI exit codes.

## Safety by design

This tool interacts with networks. It is designed around explicit authorization and conservative defaults:

- **Explicit scope is mandatory.** Target hostnames/IPs are checked against a schema-validated, optionally expiring scope before scanning. DNS A/AAAA answers are snapshotted once per scan, explicit denied addresses fail closed, and TCP/UDP/HTTP/TLS transports connect only to pinned numeric addresses. The implementation is under final review in [PR #10](https://github.com/silvatechf/exposure_detect/pull/10); see [security issue #3](https://github.com/silvatechf/exposure_detect/issues/3).
- **Only scan assets you own or are explicitly authorized to assess.** The scope file is a technical boundary, not a substitute for legal authorization.
- **Credential checks are opt-in.** They use a deliberately tiny set of generic defaults, cap attempts per endpoint, and never store passwords.
- **Industrial probes require a separate opt-in.** The Modbus check sends one read-only identification request; do not run it against live industrial equipment without specific approval.
- **API access is disabled until keys are configured.** API identities have viewer/scanner/admin roles; privileged probes require admin authorization. Actions, including denied attempts, are audited.
- **Input and resource limits are enforced.** Targets are hostnames or IP addresses, not URLs; unknown fields are rejected; API batches are capped at 16 targets and 256 explicit ports per target; TCP discovery fan-out is bounded.
- **Network destinations are pinned.** HTTPX checks preserve the original hostname for Host/SNI/certificate validation while connecting to snapshot IPs. The form-login probe follows redirects only within the exact same origin (scheme, hostname, and effective port); other web checks do not follow redirects. Scan transports do not use ambient proxies.
- These controls reduce accidental misuse; they do not replace network segmentation, least-privilege deployment, controlled DNS, or egress filtering. Pinning cannot protect against a compromised or malicious authoritative DNS answer already returned during preflight; restrictive egress controls remain necessary.

## Quickstart

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"
cp scope.example.yaml scope.yaml
```

Edit `scope.yaml` to list only the assets you are authorized to scan, then:

```bash
exposuredetect checks
exposuredetect scan -t 192.0.2.10 --scope scope.yaml --format md
exposuredetect scan -t 192.0.2.10 --allow-credential-checks --fail-on high
exposuredetect scan -t 192.0.2.20 --profile camera
```

The legacy `eg` command remains available for compatibility.

### Local lab (no real devices)

```bash
exposuredetect lab
```

The lab starts deliberately insecure fake services on `127.0.0.1` and prints a scoped scan command. Use a scope file that explicitly permits `127.0.0.0/8`. The bundled tests use local fixtures and do not require external network access.

### CI: SARIF and baseline comparison

```bash
exposuredetect scan -t 192.0.2.10 --format json -o baseline.json
exposuredetect scan -t 192.0.2.10 --format sarif -o out.sarif --baseline baseline.json
exposuredetect diff baseline.json current.json
```

The GitHub Action is defined in `action.yml`. Use a self-hosted runner inside the lab network; GitHub-hosted runners cannot reach private devices. The action definition and SARIF upload path still require validation in a real repository workflow.

### HTTP API

Set one admin key with `EG_API_KEY`, or configure named role-based keys with `EG_API_KEYS`:

```bash
export EG_API_KEYS="alice:admin:$(python -c 'import secrets; print(secrets.token_urlsafe(32))'),ci:scanner:$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
exposuredetect serve
```

The API provides `POST /scans`, `GET /scans`, `GET /scans/{id}`, report retrieval (`md`, `json`, `sarif`), and admin-only audit access. PostgreSQL support is optional: install `.[postgres]` and configure `EG_DATABASE_URL`; see `docker-compose.yml`.

## Project layout

```text
src/exposureguard/
  domain/      Finding, Target, ScanResult and Severity models
  engine/      check contract, registry and asynchronous runner
  checks/      network, HTTP, TLS, camera, credential and industrial checks
  protocols/   minimal SNMP/BER and read-only Modbus helpers
  lab/         deliberately insecure local devices for demonstrations/tests
  data/        risky-service and generic-default reference data
  scope.py     authorization-scope enforcement
  storage/     SQLAlchemy tables and repository
  reporting/   Markdown, JSON and SARIF renderers
  api/         FastAPI app factory, roles, rate limiting and routes
  cli.py       exposuredetect / eg command entry point
tests/         unit and local-server integration tests
docs/          architecture, threat model, checks catalog, roadmap and audit notes
```

### Naming and compatibility

The public project name and Python distribution are **ExposureDetect** (`exposuredetect`). The existing Python import namespace (`exposureguard`), `EG_` environment-variable prefix, and legacy `eg` command are retained in this release to avoid an unnecessary breaking migration of existing integrations.

## Honest limitations

- Network checks use TCP connect plus targeted UDP (SNMP only); Modbus is the only industrial protocol confirmed, and it is read-only. There is no full UDP discovery, OS fingerprinting, or authenticated scan.
- An open port is evidence of exposure, not proof of a vulnerability.
- RTSP checks try a short list of common stream paths, not every vendor-specific path.
- Form-login detection is heuristic (medium confidence); custom login pages, CAPTCHAs, MFA, and JavaScript-only forms are not handled. Telnet/SSH default logins are not tested.
- `exposed_paths` checks known leak signatures; it is not a webshell hunter or malware detector.
- PHP end-of-life dates are hand-curated in `data/runtime_eol.json`; verify them and account for distribution backports.
- There is no Shodan-style internet-index integration and no per-vendor default-credential dictionary.
- Device profiles are starting points and need tuning for each environment.
- End-to-end validation has used bundled fake devices, **not real IoT or industrial hardware**.
- The standards mapping is indicative; verify current standard text before citing it.
- DNS pinning is implemented in the current feature branch and is undergoing final CI/review; it does not validate the trustworthiness of authoritative DNS answers received during preflight. Rate limiting is per process. Docker Compose/PostgreSQL and the GitHub Action are not yet validated for production deployment.
- ExposureDetect does not replace Nmap, Nuclei, EDR, or a dedicated vulnerability scanner. It focuses on exposure posture and secure-by-default evidence.
