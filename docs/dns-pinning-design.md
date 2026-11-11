# DNS Resolution and Connection Pinning Design

**Status:** Partially implemented in PR #9; security acceptance tests and final review remain open  
**Security issue:** [#3 — pin DNS resolutions and enforce scope at connection time](https://github.com/silvatechf/exposure_detect/issues/3)

## Context

The scan runner currently checks the submitted hostname against the authorization scope, but individual transports resolve that hostname later. The current code opens connections through `asyncio.open_connection(hostname, ...)`, HTTPX clients, and UDP endpoints using a hostname. A DNS answer can therefore change after the scope preflight.

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
- The runner first checks the hostname scope, resolves it, validates the complete address set against deny rules, and stores the snapshot in `ScanContext`. No check is invoked until every target has completed this preflight.
- A resolution error, empty answer, malformed address, excessive answer set, or denied answer aborts the scan before probes begin. It must not become a normal "no findings" result.

### Raw TCP, TLS, and UDP

- Replace direct hostname-based `asyncio.open_connection` calls with a shared pinned connector that iterates only over the snapshot's numeric addresses.
- For TLS, connect to the numeric address while explicitly passing the original hostname as `server_hostname`. Keep normal certificate verification for the certificate-trust check; the legacy protocol probe remains an explicitly untrusted protocol-capability probe.
- For UDP, create the datagram endpoint with a numeric `remote_addr`. Do not call a hostname-based UDP endpoint after preflight.

### HTTPX

HTTPX retains the URL hostname so that Host and TLS SNI/certificate verification remain correct. Replacing the URL hostname with an IP and manually setting Host is insufficient because it changes TLS SNI and certificate-name validation. PR #9 implements a dedicated HTTPX async transport backed by the public HTTP Core network backend API. The backend verifies the requested origin host and connects only to numeric addresses from the immutable snapshot. HTTP Core continues to own HTTP framing, Host, TLS SNI, certificate verification, and response handling. The transport uses no proxy, disables keep-alive pooling, and maps HTTP Core network/protocol/timeout failures to HTTPX network errors.

The preferred integration is a dedicated HTTPX async transport backed by an explicit HTTP Core network backend. The backend receives the origin hostname from HTTP Core and substitutes only the socket destination with a validated address from the scan snapshot. HTTP Core continues to own HTTP framing, Host, TLS SNI, certificate verification, connection pooling, and response handling.

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
- After preflight, the fake resolver is changed to return a different address. TCP, UDP, HTTP, RTSP, and TLS must still connect only to the pinned address.
- HTTP Host and TLS SNI remain the original hostname.
- Certificate hostname validation uses the original hostname.
- A pinned connection failure never retries by resolving the original hostname.
- Proxy environment variables cannot change the destination.

### Regression and CI

- Unit coverage now checks hostname resolution bypass in the HTTP transport, origin-host mismatch rejection, DNS-deny preflight, complete multi-target preflight, and scope expiry.
- The complete Python 3.11/3.12 CI run is still being validated after the HTTP transport migration.
- Remaining acceptance work includes explicit HTTPS Host/SNI/certificate tests, UDP no-re-resolution coverage, and an end-to-end audit of every network path.
- Update README, architecture, threat model, and roadmap only after the end-to-end tests pass.

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
