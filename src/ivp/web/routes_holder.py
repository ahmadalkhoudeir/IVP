"""The account holder's side of the confirmation — deliberately NOT behind
staff login. In a real deployment this would be a push notification or a
phone call, not a web page; this route exists only so the demo has
something to click. See the "DEMO ONLY" warning shown on the agent's ticket
page (agent/_status_partial.html), which is the only place this URL is
surfaced.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Form, Request

from ivp.core.state_machine import VerificationState
from ivp.db.sqlite_verification_repository import VerificationAttemptNotFound
from ivp.services.verification_service import generate_code

router = APIRouter()


def _decoy_choices(real_code: str) -> list[str]:
    decoys = set()
    while len(decoys) < 2:
        candidate = generate_code()
        if candidate != real_code:
            decoys.add(candidate)
    choices = [real_code, *decoys]
    secrets.SystemRandom().shuffle(choices)
    return choices


@router.get("/confirm/{attempt_id}")
def confirm_form(request: Request, attempt_id: str):
    templates = request.app.state.templates
    verification_repo = request.app.state.verification_repo
    try:
        attempt, code = verification_repo.get(attempt_id)
    except VerificationAttemptNotFound:
        return templates.TemplateResponse(
            request, "holder/not_found.html", {"current_user": None}, status_code=404
        )

    if attempt.state != VerificationState.PENDING_CONFIRMATION:
        return templates.TemplateResponse(
            request,
            "holder/result.html",
            {"current_user": None, "outcome": "ALREADY_RESOLVED", "state": attempt.state.value},
        )

    return templates.TemplateResponse(
        request,
        "holder/confirm.html",
        {
            "current_user": None,
            "attempt_id": attempt_id,
            "choices": _decoy_choices(code),
        },
    )


@router.post("/confirm/{attempt_id}")
def confirm_submit(request: Request, attempt_id: str, selected_code: str = Form(...)):
    templates = request.app.state.templates
    orchestrator = request.app.state.orchestrator
    try:
        result = orchestrator.submit_confirmation(
            attempt_id, selected_code=selected_code, now=datetime.now(UTC)
        )
    except VerificationAttemptNotFound:
        return templates.TemplateResponse(
            request, "holder/not_found.html", {"current_user": None}, status_code=404
        )

    return templates.TemplateResponse(
        request,
        "holder/result.html",
        {"current_user": None, "outcome": result.name, "state": None},
    )


@router.post("/confirm/{attempt_id}/report")
def report_fraud(request: Request, attempt_id: str):
    """"I did not request this." Denies the attempt and records
    FRAUD_REPORTED so supervisors see a likely impersonation attempt
    (docs/decisions/fraud-reporting.md)."""
    templates = request.app.state.templates
    orchestrator = request.app.state.orchestrator
    try:
        result = orchestrator.report_fraud(attempt_id, now=datetime.now(UTC))
    except VerificationAttemptNotFound:
        return templates.TemplateResponse(
            request, "holder/not_found.html", {"current_user": None}, status_code=404
        )
    return templates.TemplateResponse(
        request,
        "holder/result.html",
        {"current_user": None, "outcome": result.name, "state": None},
    )
