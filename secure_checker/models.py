from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class RiskMatch:
    """One matched OWASP risk with generated guidance."""

    code: str
    title: str
    matched_keywords: List[str]
    abuse_cases: List[str]
    best_practices: List[str]
    confidence_score: int
    confidence_level: str


@dataclass
class ValidationCheck:
    """One technical validation check result."""

    name: str
    status: str
    details: str
    recommendation: str
