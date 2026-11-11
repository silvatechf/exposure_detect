# Checks catalog

| ID | Severity range | Evidence | Remediation theme |
| --- | --- | --- | --- |
| `exposed_services` | MEDIUM-CRITICAL | Port open + service name | Disable service or restrict by firewall/VPN |
| `http_posture` | LOW-MEDIUM | Missing headers, banner, status | HTTPS everywhere, security headers, hide versions |
| `tls_posture` | MEDIUM | Verify error, legacy protocol accepted | Trusted CA, TLS 1.2+ only |
| `mqtt_anonymous` | HIGH | CONNACK return code 0 | Require credentials/certs and ACLs |
| `redis_unauth` | CRITICAL | `+PONG` reply | Bind privately, enable ACLs |
| `rtsp_unauth` | HIGH (high if a vendor stream path answers) | Paths that answered 200 | Authenticate every stream path |
| `exposed_paths` | MEDIUM-HIGH | Path + "signature matched" (never the body) | Remove file/endpoint, rotate secrets |
| `default_credentials` (opt-in) | CRITICAL | Credential pair id (no password) | Force unique password at first use |
| `http_form_login` (opt-in) | CRITICAL (medium confidence) | Pair id, method=form | Force unique password; disable default account |
| `snmp_default` (opt-in, UDP) | HIGH | Community `public` answered | Disable v1/v2c or use SNMPv3 |
| `modbus_unauth` (opt-in, industrial) | HIGH | Read Device Identification (FC 0x2B) answered | Segment OT, protocol-aware gateway |
| `onvif_exposed` | INFO-MEDIUM | Which device-info fields were disclosed (names only) | Restrict ONVIF, require auth |
| `camera_fingerprint` | INFO (medium confidence) | Vendor/category hint | Isolate cameras, expose via VPN/gateway |
| `profile_conformance` | LOW (medium confidence) | Profile name | Disable service or extend the profile |
| `http_posture` (PHP) | HIGH/LOW (medium confidence) | Version, status, EOL date | Upgrade PHP; remove `X-Powered-By` |

## Writing a new check

```python
@register
class MyCheck(Check):
    id = "my_check"
    title = "What it detects"
    async def run(self, target, ctx):
        ports = ctx.open_ports.get(target.host, set())
        return [Finding(...)]
```
Import it in `checks/__init__.py` and add a test with a local server in `tests/`.
