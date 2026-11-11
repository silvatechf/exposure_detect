import json

from typer.testing import CliRunner

from exposureguard import cli
from exposureguard.domain.models import Finding, ScanResult, Severity, Target
from exposureguard.engine import diff
from exposureguard.reporting import sarif


def finding(sev=Severity.HIGH, port=1883, check="mqtt_anonymous"):
    return Finding(
        check_id=check, title=f"thing {port}", severity=sev, host="10.0.0.1", port=port,
        description="d", remediation="r", tags=["unauthenticated"],
    )


def scan_with(*findings):
    return ScanResult(targets=[Target(host="10.0.0.1")], findings=list(findings))


def test_sarif_structure_and_levels():
    doc = json.loads(sarif.render(scan_with(finding(), finding(Severity.LOW, 80, "http_posture")), "docs/x.md"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert {r["ruleId"] for r in run["results"]} == {"mqtt_anonymous", "http_posture"}
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {"mqtt_anonymous": "error", "http_posture": "note"}
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docs/x.md"
    assert all("exposureguard/v1" in r["partialFingerprints"] for r in run["results"])


def test_diff_new_resolved_unchanged():
    a, b, c = finding(port=1), finding(port=2), finding(port=3)
    d = diff.compare(scan_with(a, b), scan_with(b, c))
    assert [f.port for f in d.new] == [3]
    assert [f.port for f in d.resolved] == [1]
    assert [f.port for f in d.unchanged] == [2]


def test_json_report_roundtrip_keeps_fingerprint():
    original = scan_with(finding())
    again = ScanResult.model_validate_json(original.model_dump_json())
    assert again.findings[0].fingerprint == original.findings[0].fingerprint


def _stub_scan(monkeypatch, result):
    async def fake(targets, scope, ctx=None, concurrency=10):
        return result
    monkeypatch.setattr(cli, "run_scan", fake)


def _scope(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("owner: o\nauthorized_by: a\nallowed: [10.0.0.0/8]\n")
    return p


def test_cli_scope_violation_exit_2(tmp_path):
    r = CliRunner().invoke(cli.app, ["scan", "-t", "198.51.100.1", "--scope", str(_scope(tmp_path))])
    assert r.exit_code == 2


def test_cli_baseline_gates_only_new_findings(tmp_path, monkeypatch):
    old = scan_with(finding(port=1883))
    (tmp_path / "base.json").write_text(old.model_dump_json())
    base = ["scan", "-t", "10.0.0.1", "--scope", str(_scope(tmp_path)), "--baseline", str(tmp_path / "base.json")]

    _stub_scan(monkeypatch, scan_with(finding(port=1883)))  # same finding as baseline
    assert CliRunner().invoke(cli.app, base).exit_code == 0

    _stub_scan(monkeypatch, scan_with(finding(port=1883), finding(port=6379, check="redis_unauth")))
    assert CliRunner().invoke(cli.app, base).exit_code == 1


def test_cli_sarif_output_file(tmp_path, monkeypatch):
    _stub_scan(monkeypatch, scan_with(finding()))
    out = tmp_path / "r.sarif"
    r = CliRunner().invoke(
        cli.app,
        ["scan", "-t", "10.0.0.1", "--scope", str(_scope(tmp_path)), "--format", "sarif", "-o", str(out), "--fail-on", "critical"],
    )
    assert r.exit_code == 0 and json.loads(out.read_text())["version"] == "2.1.0"
