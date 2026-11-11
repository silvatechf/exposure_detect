from exposureguard import scoring
from exposureguard.domain.models import Finding, Severity


def f(sev):
    return Finding(check_id="x", title="t", severity=sev, host="h", description="d", remediation="r")


def test_clean_is_a():
    assert scoring.compute([]) == (100, "A")


def test_critical_caps_score():
    score, grade = scoring.compute([f(Severity.CRITICAL)])
    assert score <= 40 and grade in {"D", "F"}


def test_score_never_negative():
    assert scoring.compute([f(Severity.HIGH)] * 20)[0] == 0
