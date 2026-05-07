from __future__ import annotations

from secure_checker.config import MAX_REQUIREMENT_LENGTH, MAX_TARGET_URL_LENGTH


def normalize_requirement(raw_text: str) -> str:
    """Validate and normalize user input for safe processing."""
    text = raw_text.strip()

    if len(text) > MAX_REQUIREMENT_LENGTH:
        text = text[:MAX_REQUIREMENT_LENGTH]

    safe_chars = []
    for ch in text:
        if ch.isprintable() or ch in "\n\t\r":
            safe_chars.append(ch)

    return "".join(safe_chars)


def normalize_target_url(raw_url: str) -> str:
    """Normalize and limit the target URL input for validation."""
    url = raw_url.strip()

    if len(url) > MAX_TARGET_URL_LENGTH:
        url = url[:MAX_TARGET_URL_LENGTH]

    return url
