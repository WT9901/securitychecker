from __future__ import annotations

from secure_checker.services import validation_service


class FakeHeaders:
    def __init__(self, mapping: dict[str, str], set_cookies: list[str] | None = None):
        self._mapping = mapping
        self._set_cookies = set_cookies or []

    def get(self, key: str, default: str = ""):
        return self._mapping.get(key, default)

    def get_all(self, key: str, default=None):
        if key.lower() == "set-cookie":
            return list(self._set_cookies)
        return default if default is not None else []


def test_validate_target_safety_blocks_localhost():
    ok, message, resolved = validation_service.validate_target_safety("http://localhost/login")

    assert ok is False
    assert "Localhost" in message
    assert resolved == []


def test_validate_target_safety_blocks_private_ip():
    ok, message, resolved = validation_service.validate_target_safety("http://10.0.0.1/login")

    assert ok is False
    assert "Blocked non-public destination" in message
    assert resolved == ["10.0.0.1"]


def test_validate_target_safety_allows_public_ip():
    ok, message, resolved = validation_service.validate_target_safety("https://8.8.8.8/login")

    assert ok is True
    assert "passed public network safety checks" in message
    assert resolved == ["8.8.8.8"]


def test_run_validation_checks_handles_connectivity_failure(monkeypatch):
    monkeypatch.setattr(
        validation_service,
        "fetch_target_response",
        lambda _url: (None, None, "timed out"),
    )

    summary, checks, err = validation_service.run_validation_checks("https://8.8.8.8/login")

    assert summary == "Validation completed with blocking issues."
    assert err == ""
    assert any(c.name == "Connectivity" and c.status == "FAIL" for c in checks)


def test_run_validation_checks_warns_on_missing_headers(monkeypatch):
    headers = FakeHeaders(mapping={})
    monkeypatch.setattr(
        validation_service,
        "fetch_target_response",
        lambda _url: (200, headers, ""),
    )

    summary, checks, _ = validation_service.run_validation_checks("https://8.8.8.8/login")

    status_by_name = {c.name: c.status for c in checks}
    assert summary == "Validation completed with recommendations."
    assert status_by_name["HTTP Response Status"] == "PASS"
    assert status_by_name["HSTS Header"] == "WARN"
    assert status_by_name["CSP Header"] == "WARN"
    assert status_by_name["X-Frame-Options"] == "WARN"
    assert status_by_name["X-Content-Type-Options"] == "WARN"
    assert status_by_name["Referrer-Policy"] == "WARN"
    assert status_by_name["Session Cookie Flags"] == "WARN"
    assert status_by_name["Authentication Endpoint Hint"] == "PASS"


def test_run_validation_checks_passes_when_headers_and_cookies_are_strong(monkeypatch):
    headers = FakeHeaders(
        mapping={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        },
        set_cookies=["session=abc; Secure; HttpOnly; SameSite=Lax"],
    )
    monkeypatch.setattr(
        validation_service,
        "fetch_target_response",
        lambda _url: (200, headers, ""),
    )

    summary, checks, _ = validation_service.run_validation_checks("https://8.8.8.8/login")

    assert summary == "Validation completed successfully."
    assert all(c.status == "PASS" for c in checks)
