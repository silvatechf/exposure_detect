# Threat model (of the tool itself)

| Threat | Mitigation |
| --- | --- |
| Tool used against unauthorised systems | Mandatory scope file, expiring scope, deny list, fail-closed |
| Account lockout on target devices | Default-credential check is opt-in, tiny list, hard cap on attempts, delay between attempts |
| Secrets leaking through reports/DB | Passwords never stored; evidence holds only pair ids and usernames |
| Unauthorised API use | API disabled without `EG_API_KEY`; constant-time comparison; docs endpoints disabled |
| Scan results exposed | Reports only via authenticated API; DB is local SQLite (protect file permissions) |
| Abuse as DoS | Concurrency semaphore, short timeouts, bounded target count per request (64) |
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

## Out of scope for v0.1
Distributed rate limiting, encrypted database, SSO/OIDC, tamper-evident audit log, DNS pinning/rebinding protection. Domain scopes currently authorise the hostname; DNS answers are not pinned to a validated address for the full scan, so deployments should use controlled DNS and network egress restrictions.
