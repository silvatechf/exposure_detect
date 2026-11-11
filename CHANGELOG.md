# Changelog

## 0.3.1
- Harden target input validation: reject URL syntax, malformed hostnames, whitespace and duplicate/invalid ports.
- Harden scope loading: validate YAML structure and required fields; malformed or unreadable scope files fail closed with actionable errors.
- Disable the public OpenAPI schema endpoint alongside Swagger UI and ReDoc.
- Validate API key names and uniqueness, reject duplicate key material, and require a positive scan rate limit.
- Bound TCP service-discovery fan-out with a shared network semaphore to prevent target/port combinations from creating unbounded connection bursts.
- Add regression tests for the above security and configuration boundaries.


## 0.3.0
- Web/PHP: `X-Powered-By` disclosure and end-of-life PHP detection (date-driven, medium confidence); 11 more signature-verified paths (phpMyAdmin, Adminer, SQL dumps, `.htpasswd`, config backups, WEB-INF, directory listings).
- Cameras: RTSP probing of common vendor stream paths, `onvif_exposed` (service reachable / unauthenticated device information), `camera_fingerprint` (CCTV/DVR/NVR web interfaces).
- Industrial: `modbus_unauth` with a **single read-only request** (Read Device Identification), behind a separate `--allow-industrial-probes` opt-in.
- Device profiles (`--profile camera|sensor|industrial-gateway|plc|generic-web` or a YAML file) report unexpected open ports.
- Opt-in model generalised (`credentials`, `industrial`); unknown categories fail closed.
- Lab gains a vendor-path RTSP camera, ONVIF NVR, PHP site and Modbus device.

## 0.2.0
- New checks: `mqtt_anonymous`, `redis_unauth`, `rtsp_unauth`, `exposed_paths` (signature-verified), and opt-in `snmp_default` (UDP) and `http_form_login`.
- Wider service catalogue (S7comm, DNP3, EtherNet/IP, Docker API, memcached, CouchDB, MySQL, PostgreSQL).
- SARIF 2.1.0 output, GitHub Action (`action.yml`), baseline mode and `eg diff` (only new findings fail the gate).
- Indicative mapping to ETSI EN 303 645 and OWASP IoT Top 10 on every finding; `confidence` field.
- `eg lab`: deliberately insecure fake devices on localhost for demos and end-to-end tests.
- API: named keys with roles (viewer/scanner/admin), audit log, scan rate limit, minimum key length.
- PostgreSQL support (`.[postgres]`) and `docker-compose.yml`.

## 0.1.0
- Initial release: exposed services, HTTP posture, TLS posture, HTTP Basic default credentials, API, CLI.

## 0.3.2 - 2026-11-11

### Security and reliability
- Disable ambient proxy configuration for all HTTP probes (`trust_env=False`) so scan traffic is not silently rerouted through environment-configured proxies.
- Require an admin API key to enable credential or industrial probes; denied attempts are audited.
- Bound API scan batches to 16 targets and per-target port lists to 256 entries.
- Reject unknown fields in target and API scan request models to fail closed on malformed or misspelled input.
- Enforce the storage-compatible 64-character limit for API key identities.
- Add regression tests for privileged probe authorization and input bounds.
