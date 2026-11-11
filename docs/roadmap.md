# Roadmap

**Done in v0.3:** PHP/runtime disclosure and EOL, extra signature-verified paths, RTSP vendor paths, ONVIF, camera fingerprinting, read-only Modbus confirmation, device profiles.

**v0.4 (security and validation):** implement connection-time DNS resolution pinning with scope revalidation; validate PostgreSQL, Docker Compose and the GitHub Action; run against real lab hardware (router, IP camera, PLC simulator); keep per-device false-positive notes; add replayable fixtures captured from real devices; per-vendor default-credential hints (only widely documented defaults).
**v0.5 (depth):** SSH weak auth methods and banner policy, Telnet default logins (opt-in), UPnP/SSDP and CoAP discovery, S7comm/EtherNet/IP read-only confirmation, more runtimes in the EOL table (Node, Python, OpenSSL).
**v0.6 (platform):** OIDC/SSO, hash-chained audit log with external anchoring, scheduled scans, webhook alerts, multi-tenant scopes.
**v0.7 (ecosystem):** attach findings as evidence in DeviceTrust decisions; refine the ETSI EN 303 645 / CRA secure-by-default mapping after checking the current standard text (supporting evidence only, never certification).
