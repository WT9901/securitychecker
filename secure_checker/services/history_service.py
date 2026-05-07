from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from secure_checker.config import HISTORY_LOG_PATH
from secure_checker.models import ValidationCheck


def append_validation_history(target_url: str, summary: str, checks: List[ValidationCheck]) -> None:
    """Append one validation run to local JSONL history log."""
    record = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "summary": summary,
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "details": check.details,
                "recommendation": check.recommendation,
            }
            for check in checks
        ],
    }

    with HISTORY_LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record) + "\n")


def read_validation_history(limit: int = 10) -> List[dict]:
    """Read latest validation log entries from local JSONL history file."""
    if not HISTORY_LOG_PATH.exists():
        return []

    lines = HISTORY_LOG_PATH.read_text(encoding="utf-8").splitlines()
    entries: List[dict] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(entries) >= limit:
            break

    return entries
