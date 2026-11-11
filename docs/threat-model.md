# Threat model (of the tool itself)

| Threat | Mitigation |
| --- | --- |
| Tool used against unauthorised systems | Mandatory scope file, expiring scope, deny list, fail-closed |
| Account lockout on target devices | Default-credential check is opt-in, tiny list, hard cap on attempts, delay between attempts |
| Secrets leaking through reports/DB | Passwords never stored; evidence holds only pair ids and usernames |
| Unauthorised API use | API disabled without `EG_API_KEY`; constant-time comparison; docs endpoints disabled |
| Scan results exposed | Reports only via authenticated API; protect database credentials, network access, and persistent volume permissions (SQLite or PostgreSQL) |
| Abuse as DoS | Concurrency semaphore, short timeouts, API batches capped at 16 targets and 256 ports per target |
| Redirect to an unauthorised origin during web checks | Form check follows redirects only within the exact same origin (scheme, hostname, effective port); other web checks never follow redirects |
| Form login false positives or lockouts | Opt-in, attempt cap, delay, control probe with random credentials, medium confidence label |
| Insider misuse of the API | Named keys with roles, audit log of every action including denied scans, per-actor rate limit |
| Weak API keys | Minimum 16 characters enforced; key names and key material must be unique |
| Unnecessary API schema disclosure | Swagger, ReDoc and the OpenAPI schema endpoint are disabled by default |
| Malformed target/scope input | Hostnames/IPs and scope YAML are validated; invalid scope fails closed |
| Connection bursts from large target/port sets | TCP discovery uses a shared bounded semaphore |
| Disrupting fragile industrial devices | Separate `--allow-industrial-probes` opt-in; exactly one read-only request (FC 0x2B); no write function codes exist in the Modbus module (tested) |
| Fragile cameras overloaded by probing | RTSP/ONVIF/path probes run sequentially, short timeouts, bounded path lists |
| Supply chain | Minimal dependencies, `pip-audit` in CI, non-root container |

## DNS rebinding / destination pinning

The implementation integrated through [PR #10](https://github.com/silvatechf/exposure_detect/pull/10) adds a bounded, immutable A/AAAA snapshot per target hostname and per scan. The runner validates every target and resolves all unique hostnames before any probe begins. Explicitly denied IP/CIDR answers reject the complete target, including mixed allow/deny answer sets.

TCP service discovery, raw TCP protocols, UDP/SNMP, TLS, and HTTPX-backed checks use only numeric addresses from the snapshot. HTTP Host, TLS SNI, and certificate hostname validation retain the original hostname. Proxies and hostname fallback are disabled. Python 3.11, 3.12, and 3.15 CI, Ruff, dependency audit, dependency consistency, and GitGuardian passed on the integrated PR head. [Issue #3](https://github.com/silvatechf/exposure_detect/issues/3) was resolved by the merge; the residual risk below remains applicable.

Residual risk: pinning prevents DNS changes after preflight from changing the connection destination. It does not establish that the authoritative DNS answer received during preflight is trustworthy. Use controlled DNS and restrictive outbound firewall rules, especially for sensitive environments.

Other deferred controls include distributed rate limiting, encrypted database storage, SSO/OIDC, and tamper-evident audit logging.
