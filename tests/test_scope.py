from datetime import date

import pytest

from exposureguard.scope import Scope, ScopeError


def make(**kw):
    base = dict(owner="o", authorized_by="a", valid_until=None, allowed=["192.0.2.0/24"], denied=[])
    base.update(kw)
    return Scope(**base)


def test_ip_in_cidr_allowed():
    make().check("192.0.2.10")


def test_ip_outside_scope_rejected():
    with pytest.raises(ScopeError):
        make().check("198.51.100.1")


def test_denied_wins_over_allowed():
    with pytest.raises(ScopeError):
        make(denied=["192.0.2.254"]).check("192.0.2.254")


def test_wildcard_hostname():
    s = make(allowed=["*.lab.example.com"])
    s.check("gw.lab.example.com")
    with pytest.raises(ScopeError):
        s.check("lab.example.com.evil.net")


def test_expired_scope_rejected():
    with pytest.raises(ScopeError):
        make(valid_until=date(2020, 1, 1)).check("192.0.2.10")


def test_resolved_address_denial_overrides_hostname_authorization():
    scope = make(allowed=["*.lab.example.com"], denied=["203.0.113.0/24"])
    with pytest.raises(ScopeError, match="resolved address explicitly denied"):
        scope.check_resolved_address("203.0.113.7")


def test_resolved_address_checks_scope_expiry():
    scope = make(valid_until=date(2020, 1, 1))
    with pytest.raises(ScopeError, match="scope expired"):
        scope.check_resolved_address("192.0.2.10")


def test_resolved_address_requires_ip_literal():
    with pytest.raises(ScopeError, match="not an IP address"):
        make().check_resolved_address("device.example")


def test_missing_file_fails_closed(tmp_path):
    with pytest.raises(ScopeError):
        Scope.load(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    "content",
    [
        "- not-a-mapping",
        "owner: Example\nauthorized_by: Tester\nallowed: invalid\n",
        "owner: Example\nauthorized_by: Tester\nallowed: [192.0.2.0/24]\nvalid_until: tomorrow\n",
        "owner: Example\nauthorized_by: Tester\nallowed: [192.0.2.0/24]\ndenied: invalid\n",
    ],
)
def test_invalid_scope_file_fails_closed(tmp_path, content):
    path = tmp_path / "scope.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ScopeError):
        Scope.load(path)
