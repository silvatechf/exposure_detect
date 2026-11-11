import pytest

from exposureguard.config import Settings


def test_weak_key_rejected(monkeypatch):
    monkeypatch.setenv("EG_API_KEY", "short")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_unknown_role_rejected(monkeypatch):
    monkeypatch.delenv("EG_API_KEY", raising=False)
    monkeypatch.setenv("EG_API_KEYS", "eve:root:0123456789abcdefXYZ")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_multiple_keys_parse(monkeypatch):
    monkeypatch.delenv("EG_API_KEY", raising=False)
    monkeypatch.setenv("EG_API_KEYS", "a:viewer:0123456789abcdefXYZ,b:scanner:abcdef0123456789XYZ")
    s = Settings.from_env()
    assert [(k.name, k.role) for k in s.api_keys] == [("a", "viewer"), ("b", "scanner")]


def test_duplicate_key_names_rejected(monkeypatch):
    monkeypatch.delenv("EG_API_KEY", raising=False)
    monkeypatch.setenv(
        "EG_API_KEYS",
        "worker:viewer:0123456789abcdef,worker:admin:abcdef0123456789",
    )
    with pytest.raises(ValueError, match="duplicate API key name"):
        Settings.from_env()


def test_duplicate_key_values_rejected(monkeypatch):
    monkeypatch.delenv("EG_API_KEY", raising=False)
    monkeypatch.setenv(
        "EG_API_KEYS",
        "viewer:viewer:0123456789abcdef,admin:admin:0123456789abcdef",
    )
    with pytest.raises(ValueError, match="must be unique"):
        Settings.from_env()


@pytest.mark.parametrize("value", ["0", "-1", "invalid"])
def test_invalid_rate_limit_rejected(monkeypatch, value):
    monkeypatch.delenv("EG_API_KEY", raising=False)
    monkeypatch.delenv("EG_API_KEYS", raising=False)
    monkeypatch.setenv("EG_SCAN_RATE_LIMIT", value)
    with pytest.raises(ValueError, match="positive integer"):
        Settings.from_env()
