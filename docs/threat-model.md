# Threat model (of the tool itself)

| Threat | Mitigation |
| --- | --- |
| Tool used against unauthorised systems | Mandatory scope file, expiring scope, deny list, fail-closed |
| Account lockout on target devices | Default-credential check is opt-in, tiny list, hard cap on attempts, delay between attempts |
| Secrets leaking through reports/DB | Passwords never stored; evidence holds only pair ids and usernames |
| Unauthorised API use | API disabled without `EG_API_KEY`; constant-time comparison; docs endpoints disabled |
| Scan results exposed | Reports only via authenticated API; DB is local SQLite (protect file permissions) |
| Abuse as DoS | Concurrency semaphore, short timeouts, API batches capped at 16 targets and 256 ports per target |
| Redirect to an unauthorised host during web checks | Form check only follows same-host redirects; other web checks never follow redirects |
| Form login false positives or lockouts | Opt-in, attempt cap, delay, control probe with random credentials, medium confidence label |
| Insider misuse of the API | Named keys with roles, audit log of every action including denied scans, per-actor rate limit |
| Weak API keys | Minimum 16 characters enforced; key names and key material must be unique |
| Unnecessary API schema disclosure | Swagger, ReDoc and the OpenAPI schema endpoint are disabled by default |
| Malformed target/scope input | Hostnames/IPs and scope YAML are validated; invalid scope fails closed |
| Connection bursts from large target/port sets | TCP discovery uses a shared bounded semaphore |
| Disrupting fragile industrial devices | Separate `--allow-industrial-probes` opt-in; exactly one read-only request (FC 0x2B); no write function codes exist in the Modbus module (tested) |
| Fragile cameras overloaded by probing | RTSP/ONVIF/path probes run sequentially, short timeouts, bounded path lists |
| Supply chain | Minimal dependencies, `pip-audit` in CI, non-root container |

## Known security gap: DNS rebinding

DNS pinning/rebinding protection is **not implemented**. Domain scopes currently authorize the supplied hostname, while TCP, UDP, HTTP, RTSP, and TLS clients may resolve that hostname independently at connection time. A DNS change between authorization and connection can therefore bypass the intended address boundary.

Until [issue #3](https://github.com/silvatechf/exposure_detect/issues/3) is implemented and covered by connection-level integration tests:
- Prefer IP/CIDR entries in scope for sensitive environments.
- Use controlled DNS and restrictive outbound firewall rules.
- Do not treat hostname scope as sufficient protection against DNS rebinding.

Other deferred controls include distributed rate limiting, encrypted database storage, SSO/OIDC, and tamper-evident audit logging.
