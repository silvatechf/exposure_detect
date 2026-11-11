# DNS Resolution and Connection Pinning Design

**Status:** Implemented in PR #10; final CI and security review remain open  
**Security issue:** [#3 — pin DNS resolutions and enforce scope at connection time](https://github.com/silvatechf/exposure_detect/issues/3)

## Context

Before this implementation, the scan runner checked the submitted hostname but individual transports resolved it later. That time-of-check/time-of-use gap is addressed by the per-scan snapshot and pinned transport implementation in PR #10.

This is a time-of-check/time-of-use gap. Scope validation must govern the actual destination address, not merely the string supplied by the caller.

## Security invariants

1. A scan has one immutable resolution snapshot per target hostname. There is no cross-scan DNS cache.
2. Resolve A and AAAA records before any scan probe. IP literals bypass DNS.
3. Validate the hostname against the scope and validate every resolved address against explicit deny rules. A denied address rejects the target; mixed allowed/denied answers fail closed rather than silently dropping the denied answer.
4. No transport may resolve the original hostname after preflight. Every socket connects to one of the validated numeric addresses.
5. Preserve the original hostname at the application/TLS layer: HTTP Host, TLS SNI, and certificate hostname verification must use the requested hostname, not the pinned IP.
6. Redirects remain disabled by default. Any future cross-host redirect must go through a new independent scope check and resolution snapshot.
7. No ambient proxies, implicit fallback to the system resolver, or fallback to the original hostname after a pinned connection fails.
8. Bound DNS lookup time, connection time, address count, concurrent connections, and per-scan memory.

## Proposed architecture

### Scan lifecycle

- Add an immutable `ResolvedTarget` value containing the normalized original host and an ordered, de-duplicated tuple of numeric IPv4/IPv6 addresses.
- Add a resolver service used only by the runner. It uses the event loop resolver once per target, with a strict timeout and a bounded result count.
- The runner first checks the hostname scope, resolves each unique hostname once per scan, validates the complete address set against deny rules, and stores the snapshot in `ScanContext`. A reused `ScanContext` is cleared before preflight so snapshots never cross scan boundaries. No check is invoked until every target has completed this preflight.
- A resolution error, empty answer, malformed address, excessive answer set, or denied answer aborts the scan before probes begin. It must not become a normal "no findings" result.

### Raw TCP, TLS, and UDP

- Replace direct hostname-based `asyncio.open_connection` calls with a shared pinned connector that iterates only over the snapshot's numeric addresses.
- For TLS, connect to the numeric address while explicitly passing the original hostname as `server_hostname`. Keep normal certificate verification for the certificate-trust check; the legacy protocol probe remains an explicitly untrusted protocol-capability probe.
- For UDP, create the datagram endpoint with a numeric `remote_addr`. Do not call a hostname-based UDP endpoint after preflight.

### HTTPX

HTTPX retains the URL hostname so that Host and TLS SNI/certificate verification remain correct. Replacing the URL hostname with an IP and manually setting Host is insufficient because it changes TLS SNI and certificate-name validation. PR #10 implements a dedicated HTTPX async transport backed by the public HTTP Core network backend API. The backend verifies the requested origin host and connects only to numeric addresses from the immutable snapshot. HTTP Core continues to own HTTP framing, Host, TLS SNI, certificate verification, and response handling. The transport uses no proxy, disables keep-alive pooling, and maps HTTP Core network/protocol/timeout failures to HTTPX network errors.

- HTTP Core is declared as a direct dependency (`httpcore>=1.0,<2.0`) because the adapter uses its public async transport/backend interfaces.
- Proxy support is disabled for scan traffic; the transport uses a direct connection pool.
- The adapter does not mutate HTTPX private attributes or monkeypatch global socket/DNS functions.
- The integration is implemented in `exposureguard.networking.http`; all HTTPX-backed checks use the scan snapshot.

## Scope semantics

- The original hostname must match the existing hostname/CIDR scope rules.
- Explicit denied IP/CIDR entries take precedence over hostname authorization.
- If any address returned for a hostname is denied, reject the entire target before sending packets.
- IP-literal targets are checked directly against the scope and do not require DNS.
- The implementation must document that pinning prevents post-validation DNS changes from redirecting a connection; it does not protect against a compromised or malicious authoritative DNS answer that is already returned during preflight. Network egress controls remain a separate defense.

## Test plan

### Unit tests

- IPv4-only, IPv6-only, and dual-stack resolution.
- Duplicate address normalization and deterministic ordering.
- IP-literal target resolution without invoking DNS.
- DNS timeout, resolver exception, empty answer, malformed answer, and result-count overflow.
- Explicit denied IPv4/IPv6 address in a mixed answer rejects the entire target.
- Expired scope and hostname deny precedence remain fail-closed.

### Transport tests

- A fake resolver returns a local test server address for a test hostname.
- Duplicate target hostnames share one snapshot within a scan; a reused context triggers a fresh resolution on the next scan.
- TCP service discovery and UDP integration tests prove that the hostname is not resolved after preflight.
- HTTP tests prove Host preservation, SNI preservation, acceptance of a trusted matching certificate, and rejection of a hostname mismatch.
- Raw MQTT/Redis/RTSP/Modbus checks share the pinned TCP connector; the RTSP request retains the original hostname at the protocol layer.
- A pinned connection failure never retries by resolving the original hostname.
- Proxy environment variables cannot change the destination.

### Regression and CI

- Unit and local-server integration coverage includes DNS bounds, scope expiry/denials, complete preflight ordering, duplicate-host snapshot lifecycle, pinned TCP discovery, UDP destination pinning, HTTP Host preservation, HTTPS SNI/certificate validation, and hostname mismatch rejection.
- Python 3.11/3.12 CI, Ruff, dependency audit, dependency consistency and GitGuardian must pass on the latest commit.
- Final review must verify every network path and keep issue #3 open until acceptance is demonstrated.

## Rollout

1. Introduce the resolver snapshot and scope preflight, with unit tests.
2. Introduce pinned TCP/TLS/UDP primitives and migrate raw checks.
3. Introduce the HTTP transport adapter and migrate every HTTPX check.
4. Add cross-transport DNS-change integration tests.
5. Remove the known-gap warning only after all acceptance criteria pass.

## Explicit non-goals

- No global DNS cache or resolver monkeypatch.
- No internet-wide scanning or scope expansion.
- No automatic retries against unvalidated destinations.
- No claim that DNS pinning alone makes a scan safe or legally authorized.
