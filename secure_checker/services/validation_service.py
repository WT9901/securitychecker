from __future__ import annotations

import ipaddress
import socket
from typing import List
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from secure_checker.models import ValidationCheck


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent redirects so validation checks only the exact target URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def is_public_ip(ip_text: str) -> bool:
    """Allow only public IPs for safer outbound validation requests."""
    ip_obj = ipaddress.ip_address(ip_text)
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def resolve_target_ips(hostname: str) -> List[str]:
    """Resolve hostname to a unique list of IP addresses."""
    addresses: List[str] = []
    for info in socket.getaddrinfo(hostname, None):
        ip_text = info[4][0]
        if ip_text not in addresses:
            addresses.append(ip_text)
    return addresses


def validate_target_safety(target_url: str) -> tuple[bool, str, List[str]]:
    """Validate scheme and block internal/private destinations."""
    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https URLs are allowed.", []

    if not parsed.hostname:
        return False, "Target URL must include a valid hostname.", []

    hostname = parsed.hostname.lower()
    if hostname == "localhost":
        return False, "Localhost targets are blocked.", []

    try:
        ipaddress.ip_address(hostname)
        resolved_ips = [hostname]
    except ValueError:
        try:
            resolved_ips = resolve_target_ips(hostname)
        except socket.gaierror:
            return False, "Unable to resolve target hostname.", []

    if not resolved_ips:
        return False, "No IP addresses could be resolved for target.", []

    for ip_text in resolved_ips:
        if not is_public_ip(ip_text):
            return False, f"Blocked non-public destination: {ip_text}", resolved_ips

    return True, "Target passed public network safety checks.", resolved_ips


def add_validation_check(
    checks: List[ValidationCheck],
    name: str,
    status: str,
    details: str,
    recommendation: str,
) -> None:
    """Append a normalized check result entry."""
    checks.append(
        ValidationCheck(
            name=name,
            status=status,
            details=details,
            recommendation=recommendation,
        )
    )


def fetch_target_response(target_url: str):
    """Fetch one response from target URL without following redirects."""
    opener = build_opener(NoRedirectHandler)
    request_obj = Request(
        target_url,
        headers={"User-Agent": "LoginRegistrationSecurityChecker/1.0"},
        method="GET",
    )

    try:
        with opener.open(request_obj, timeout=8) as response:
            return response.status, response.headers, ""
    except HTTPError as exc:
        return exc.code, exc.headers, str(exc.reason)
    except URLError as exc:
        return None, None, str(exc.reason)
    except Exception as exc:  # pragma: no cover
        return None, None, str(exc)


def run_validation_checks(target_url: str) -> tuple[str, List[ValidationCheck], str]:
    """Run technical validation checks for login/registration target URL."""
    checks: List[ValidationCheck] = []

    is_safe, safety_message, resolved_ips = validate_target_safety(target_url)
    if not is_safe:
        add_validation_check(
            checks,
            "Target URL Safety",
            "FAIL",
            safety_message,
            "Use a public, authorized test URL with http/https and a resolvable hostname.",
        )
        return "Validation blocked: unsafe or invalid target URL.", checks, ""

    add_validation_check(
        checks,
        "Target URL Safety",
        "PASS",
        f"{safety_message} Resolved IPs: {', '.join(resolved_ips)}",
        "Keep validation restricted to authorized public targets.",
    )

    status_code, headers, fetch_error = fetch_target_response(target_url)
    if status_code is None or headers is None:
        add_validation_check(
            checks,
            "Connectivity",
            "FAIL",
            f"Could not fetch target URL: {fetch_error}",
            "Ensure the URL is reachable and accepts direct requests.",
        )
        return "Validation completed with blocking issues.", checks, ""

    if 200 <= status_code < 300:
        status_text = "PASS"
        status_details = f"Received HTTP {status_code}."
    elif 300 <= status_code < 400:
        status_text = "WARN"
        status_details = f"Received HTTP {status_code} redirect response."
    else:
        status_text = "WARN"
        status_details = f"Received HTTP {status_code}. Reason: {fetch_error or 'N/A'}"

    add_validation_check(
        checks,
        "HTTP Response Status",
        status_text,
        status_details,
        "Use stable, reachable authentication endpoints for reliable validation.",
    )

    parsed = urlparse(target_url)
    if parsed.scheme == "https":
        hsts_value = headers.get("Strict-Transport-Security", "")
        if hsts_value and "max-age" in hsts_value.lower():
            add_validation_check(
                checks,
                "HSTS Header",
                "PASS",
                f"Strict-Transport-Security is configured: {hsts_value}",
                "Keep HSTS enabled for all authentication paths.",
            )
        else:
            add_validation_check(
                checks,
                "HSTS Header",
                "WARN",
                "Strict-Transport-Security header is missing or weak.",
                "Set HSTS with an appropriate max-age for HTTPS endpoints.",
            )
    else:
        add_validation_check(
            checks,
            "HTTPS Usage",
            "WARN",
            "Target uses HTTP. Authentication flows should use HTTPS.",
            "Use HTTPS for login/registration traffic.",
        )

    csp_value = headers.get("Content-Security-Policy", "")
    add_validation_check(
        checks,
        "CSP Header",
        "PASS" if csp_value else "WARN",
        f"Content-Security-Policy: {csp_value or 'missing'}",
        "Define a strict CSP to reduce script injection impact.",
    )

    xfo_value = headers.get("X-Frame-Options", "")
    xfo_ok = xfo_value.upper() in ("DENY", "SAMEORIGIN")
    add_validation_check(
        checks,
        "X-Frame-Options",
        "PASS" if xfo_ok else "WARN",
        f"X-Frame-Options: {xfo_value or 'missing'}",
        "Set X-Frame-Options to DENY or SAMEORIGIN.",
    )

    xcto_value = headers.get("X-Content-Type-Options", "")
    add_validation_check(
        checks,
        "X-Content-Type-Options",
        "PASS" if xcto_value.lower() == "nosniff" else "WARN",
        f"X-Content-Type-Options: {xcto_value or 'missing'}",
        "Set X-Content-Type-Options to nosniff.",
    )

    referrer_value = headers.get("Referrer-Policy", "")
    add_validation_check(
        checks,
        "Referrer-Policy",
        "PASS" if referrer_value else "WARN",
        f"Referrer-Policy: {referrer_value or 'missing'}",
        "Set Referrer-Policy to limit sensitive referrer leakage.",
    )

    set_cookie_values = headers.get_all("Set-Cookie", [])
    if set_cookie_values:
        insecure_cookie_count = 0
        for cookie_value in set_cookie_values:
            cookie_lower = cookie_value.lower()
            has_secure = "secure" in cookie_lower
            has_http_only = "httponly" in cookie_lower
            has_same_site = "samesite" in cookie_lower
            if not (has_secure and has_http_only and has_same_site):
                insecure_cookie_count += 1

        if insecure_cookie_count == 0:
            add_validation_check(
                checks,
                "Session Cookie Flags",
                "PASS",
                "All observed cookies include Secure, HttpOnly, and SameSite attributes.",
                "Keep strong cookie attributes on session-related cookies.",
            )
        else:
            add_validation_check(
                checks,
                "Session Cookie Flags",
                "WARN",
                f"{insecure_cookie_count} cookie(s) missing Secure/HttpOnly/SameSite attributes.",
                "Set Secure, HttpOnly, and SameSite on authentication cookies.",
            )
    else:
        add_validation_check(
            checks,
            "Session Cookie Flags",
            "WARN",
            "No Set-Cookie header observed in this response.",
            "Check cookie flags on actual login and session-establishing responses.",
        )

    path_text = (parsed.path or "").lower()
    looks_like_auth_endpoint = any(word in path_text for word in ["login", "signin", "signup", "register", "auth"])
    add_validation_check(
        checks,
        "Authentication Endpoint Hint",
        "PASS" if looks_like_auth_endpoint else "WARN",
        f"Path analyzed: {parsed.path or '/'}",
        "Validate URLs that directly represent login/registration endpoints for best results.",
    )

    has_fail = any(check.status == "FAIL" for check in checks)
    has_warn = any(check.status == "WARN" for check in checks)
    if has_fail:
        summary = "Validation completed with blocking issues."
    elif has_warn:
        summary = "Validation completed with recommendations."
    else:
        summary = "Validation completed successfully."

    return summary, checks, ""
