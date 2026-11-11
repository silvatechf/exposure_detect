from fastapi.testclient import TestClient

from exposureguard.api.main import create_app
from exposureguard.config import ApiKey, Settings

KEYS = (
    ApiKey("alice", "admin", "admin-key-0123456789"),
    ApiKey("bob", "scanner", "scanner-key-0123456789"),
    ApiKey("carol", "viewer", "viewer-key-0123456789"),
)
BODY = {"targets": [{"host": "127.0.0.1", "ports": [1]}]}


def client(tmp_path, scope_file, keys=KEYS, rate=10):
    s = Settings(
        api_keys=keys,
        scope_file=str(scope_file),
        database_url=f"sqlite:///{tmp_path}/t.db",
        scan_rate_limit_per_minute=rate,
    )
    return TestClient(create_app(s))


def h(key):
    return {"X-API-Key": key}


def test_health_is_public(tmp_path, scope_file):
    assert client(tmp_path, scope_file).get("/healthz").status_code == 200


def test_api_disabled_without_keys(tmp_path, scope_file):
    c = client(tmp_path, scope_file, keys=())
    assert c.get("/scans", headers=h("anything")).status_code == 503


def test_wrong_or_missing_key_rejected(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    assert c.get("/scans", headers=h("bad")).status_code == 401
    assert c.get("/scans").status_code == 401


def test_viewer_cannot_scan_but_can_read(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    assert c.post("/scans", json=BODY, headers=h("viewer-key-0123456789")).status_code == 403
    assert c.get("/scans", headers=h("viewer-key-0123456789")).status_code == 200


def test_out_of_scope_is_403_and_audited(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    r = c.post("/scans", json={"targets": [{"host": "198.51.100.9"}]}, headers=h("scanner-key-0123456789"))
    assert r.status_code == 403
    audit = c.get("/audit", headers=h("admin-key-0123456789")).json()
    assert audit[0]["action"] == "scan.denied" and audit[0]["actor"] == "bob"


def test_scan_roundtrip_reports_and_audit(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    r = c.post("/scans", json=BODY, headers=h("scanner-key-0123456789"))
    assert r.status_code == 200
    sid = r.json()["id"]
    v = h("viewer-key-0123456789")
    assert c.get(f"/scans/{sid}", headers=v).json()["grade"] == "A"
    assert "ExposureGuard report" in c.get(f"/scans/{sid}/report", headers=v).text
    assert '"version": "2.1.0"' in c.get(f"/scans/{sid}/report?fmt=sarif", headers=v).text
    actions = [e["action"] for e in c.get("/audit", headers=h("admin-key-0123456789")).json()]
    assert "scan.create" in actions


def test_audit_requires_admin(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    assert c.get("/audit", headers=h("scanner-key-0123456789")).status_code == 403


def test_scan_rate_limit(tmp_path, scope_file):
    c = client(tmp_path, scope_file, rate=2)
    codes = [c.post("/scans", json=BODY, headers=h("scanner-key-0123456789")).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_openapi_schema_is_disabled(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    assert c.get("/openapi.json").status_code == 404


def test_scanner_cannot_enable_privileged_probes(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    body = {**BODY, "allow_credential_checks": True}
    response = c.post("/scans", json=body, headers=h("scanner-key-0123456789"))
    assert response.status_code == 403
    audit = c.get("/audit", headers=h("admin-key-0123456789")).json()
    assert audit[0]["action"] == "scan.privileged_probe_denied"


def test_admin_can_enable_privileged_probes(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    body = {**BODY, "allow_credential_checks": True}
    response = c.post("/scans", json=body, headers=h("admin-key-0123456789"))
    assert response.status_code == 200


def test_scan_request_rejects_unknown_fields(tmp_path, scope_file):
    c = client(tmp_path, scope_file)
    body = {**BODY, "unexpected": "value"}
    response = c.post("/scans", json=body, headers=h("scanner-key-0123456789"))
    assert response.status_code == 422
