from __future__ import annotations

from secure_checker.models import ValidationCheck
from secure_checker.services import history_service


def test_append_and_read_history(monkeypatch, tmp_path):
    history_file = tmp_path / "history.jsonl"
    monkeypatch.setattr(history_service, "HISTORY_LOG_PATH", history_file)

    checks = [
        ValidationCheck(
            name="Target URL Safety",
            status="PASS",
            details="Safe target",
            recommendation="Keep using authorized targets",
        )
    ]

    history_service.append_validation_history("https://example.com/login", "ok", checks)
    history_service.append_validation_history("https://example.com/register", "ok", checks)

    entries = history_service.read_validation_history(limit=10)

    assert len(entries) == 2
    # Newest entry is first because read iterates from file end.
    assert entries[0]["target_url"] == "https://example.com/register"
    assert entries[1]["target_url"] == "https://example.com/login"
    assert entries[0]["checks"][0]["name"] == "Target URL Safety"
