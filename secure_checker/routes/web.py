from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from flask import Blueprint, jsonify, redirect, render_template, request, send_file, session, url_for

from secure_checker.models import RiskMatch, ValidationCheck
from secure_checker.services.export_service import generate_security_report_pdf
from secure_checker.services.history_service import append_validation_history, read_validation_history
from secure_checker.services.input_service import normalize_requirement, normalize_target_url
from secure_checker.services.risk_service import map_requirement_to_risks, serialize_risk_matches
from secure_checker.services.validation_service import run_validation_checks

web_bp = Blueprint("web", __name__)


def _default_analysis_best_practices() -> List[str]:
    return [
        "Validate all registration and login inputs on the server side.",
        "Use strong password hashing and enforce a clear password policy.",
        "Protect login with rate limiting and temporary lockout.",
        "Use generic authentication error messages to prevent account enumeration.",
        "Enforce role-based authorization on every protected action.",
    ]


@web_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        action = request.form.get("action", "analyze")

        if action == "validate":
            target_url = normalize_target_url(request.form.get("target_url", ""))
            validation_error = ""
            validation_summary = ""
            validation_checks: List[ValidationCheck] = []

            if not target_url:
                validation_error = "Please enter a target login/register URL."
            else:
                validation_summary, validation_checks, validation_error = run_validation_checks(target_url)

            if validation_checks:
                append_validation_history(target_url, validation_summary or validation_error, validation_checks)

            validation_payload = {
                "target_url": target_url,
                "validation_error": validation_error,
                "validation_summary": validation_summary,
                "validation_checks": [
                    {
                        "name": check.name,
                        "status": check.status,
                        "details": check.details,
                        "recommendation": check.recommendation,
                    }
                    for check in validation_checks
                ],
            }
            session["validation_once"] = validation_payload
            session["latest_validation"] = validation_payload
            return redirect(url_for("web.index"))

        requirement = normalize_requirement(request.form.get("requirement", ""))
        error = ""
        guidance = ""
        best_practices: List[str] = []
        results: List[RiskMatch] = []

        if not requirement:
            error = "Please enter a requirement sentence."
        else:
            results = map_requirement_to_risks(requirement)
            if not results:
                guidance = (
                    "No specific selected OWASP risks are associated with this requirement. "
                    "However, use these best practices below to reduce security risks associated with "
                    "login/registration process."
                )
                best_practices = _default_analysis_best_practices()

        analysis_payload = {
            "requirement": requirement,
            "error": error,
            "guidance": guidance,
            "best_practices": best_practices,
            "results": serialize_risk_matches(results),
        }
        session["analysis_once"] = analysis_payload
        session["latest_analysis"] = analysis_payload
        return redirect(url_for("web.index"))

    analysis_state = session.pop("analysis_once", None)
    validation_state = session.pop("validation_once", None)

    requirement = ""
    error = ""
    guidance = ""
    best_practices: List[str] = []
    results: List[RiskMatch] = []
    target_url = ""
    validation_error = ""
    validation_summary = ""
    validation_checks: List[ValidationCheck] = []

    if analysis_state:
        requirement = analysis_state.get("requirement", "")
        error = analysis_state.get("error", "")
        guidance = analysis_state.get("guidance", "")
        best_practices = analysis_state.get("best_practices", [])
        results = [
            RiskMatch(
                code=item.get("code", ""),
                title=item.get("title", ""),
                matched_keywords=item.get("matched_keywords", []),
                abuse_cases=item.get("abuse_cases", []),
                best_practices=item.get("best_practices", []),
                confidence_score=item.get("confidence_score", 0),
                confidence_level=item.get("confidence_level", "Low"),
            )
            for item in analysis_state.get("results", [])
        ]

    if validation_state:
        target_url = validation_state.get("target_url", "")
        validation_error = validation_state.get("validation_error", "")
        validation_summary = validation_state.get("validation_summary", "")
        validation_checks = [
            ValidationCheck(
                name=item.get("name", ""),
                status=item.get("status", "WARN"),
                details=item.get("details", ""),
                recommendation=item.get("recommendation", ""),
            )
            for item in validation_state.get("validation_checks", [])
        ]

    return render_template(
        "index.html",
        requirement=requirement,
        error=error,
        guidance=guidance,
        best_practices=best_practices,
        results=results,
        target_url=target_url,
        validation_error=validation_error,
        validation_summary=validation_summary,
        validation_checks=validation_checks,
        validation_history=read_validation_history(limit=8),
    )


@web_bp.route("/export/evidence.pdf", methods=["GET"])
def export_evidence_pdf():
    try:
        pdf_buffer = generate_security_report_pdf()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.pdf"
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
