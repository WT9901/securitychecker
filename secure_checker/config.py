from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HISTORY_LOG_PATH = BASE_DIR / "validation_history.jsonl"

MAX_REQUIREMENT_LENGTH = 400
MAX_TARGET_URL_LENGTH = 500

DEFAULT_SECRET = "local-dev-secret-change-me"


def get_secret_key() -> str:
    """Read secret key from environment with a safe local default."""
    return os.environ.get("FLASK_SECRET_KEY", DEFAULT_SECRET)
