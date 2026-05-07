from __future__ import annotations

import re
from typing import List

from knowledge_base import RISK_RULES
from secure_checker.models import RiskMatch


def build_match_views(requirement: str) -> tuple[str, str, set[str]]:
    """Create normalized views for robust term matching."""
    req_lower = requirement.lower()
    req_words = re.sub(r"[^a-z0-9]+", " ", req_lower)
    req_normalized = " ".join(req_words.split())
    tokens = set(req_normalized.split())
    return req_lower, req_normalized, tokens


def term_matches(term: str, req_lower: str, req_normalized: str, tokens: set[str]) -> bool:
    """Match both single-word tokens and multi-word phrases."""
    term_lower = term.lower().strip()
    term_normalized = " ".join(re.sub(r"[^a-z0-9]+", " ", term_lower).split())

    if not term_normalized:
        return False

    if " " in term_normalized:
        return term_normalized in req_normalized

    return term_normalized in tokens or term_lower in req_lower


def map_requirement_to_risks(requirement: str) -> List[RiskMatch]:
    """Map requirement keywords to selected OWASP risks."""
    req_lower, req_normalized, tokens = build_match_views(requirement)
    matches: List[RiskMatch] = []

    for code, config in RISK_RULES.items():
        matched_keywords: List[str] = []
        matched_abuse_cases: List[str] = []
        matched_best_practices: List[str] = []
        matched_signal_count = 0

        for signal in config["signals"]:
            signal_matched = False

            for term in signal["terms"]:
                if term_matches(term, req_lower, req_normalized, tokens) and term not in matched_keywords:
                    matched_keywords.append(term)
                    signal_matched = True

            if signal_matched:
                matched_signal_count += 1
                for abuse_case in signal.get("abuse_cases", []):
                    if abuse_case not in matched_abuse_cases:
                        matched_abuse_cases.append(abuse_case)
                for best_practice in signal.get("best_practices", []):
                    if best_practice not in matched_best_practices:
                        matched_best_practices.append(best_practice)

        if matched_keywords:
            abuse_cases = matched_abuse_cases or config["abuse_cases"]
            best_practices = matched_best_practices or config["best_practices"]

            confidence_score = min(100, matched_signal_count * 35 + len(matched_keywords) * 10)
            if confidence_score >= 70:
                confidence_level = "High"
            elif confidence_score >= 40:
                confidence_level = "Medium"
            else:
                confidence_level = "Low"

            matches.append(
                RiskMatch(
                    code=code,
                    title=config["title"],
                    matched_keywords=matched_keywords,
                    abuse_cases=abuse_cases,
                    best_practices=best_practices,
                    confidence_score=confidence_score,
                    confidence_level=confidence_level,
                )
            )

    matches.sort(key=lambda item: item.confidence_score, reverse=True)
    return matches


def serialize_risk_matches(results: List[RiskMatch]) -> List[dict]:
    """Convert risk match objects into serializable dictionaries."""
    return [
        {
            "code": item.code,
            "title": item.title,
            "matched_keywords": item.matched_keywords,
            "abuse_cases": item.abuse_cases,
            "best_practices": item.best_practices,
            "confidence_score": item.confidence_score,
            "confidence_level": item.confidence_level,
        }
        for item in results
    ]
