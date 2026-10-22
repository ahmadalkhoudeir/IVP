from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.audit.record import BLOCKING_OUTCOMES, AuditOutcome
from ivp.auth.deps import require_permission
from ivp.auth.roles import Permission
from ivp.core.models import TICKET_ACTIONS
from ivp.core.state_machine import VerificationState
from ivp.core.ticket import ClosureBlocked, Ticket
from ivp.db.sqlite_staff_repository import StaffUser
from ivp.services.demo_seed import DEMO_SUBSCRIBERS

KNOWN_SUBSCRIBER_IDS = frozenset(sub_id for sub_id, _name, _channels in DEMO_SUBSCRIBERS)

router = APIRouter(prefix="/agent")


def _require_agent(user: StaffUser = Depends(require_permission(Permission.VIEW_OWN_TICKETS))):
    return user


def _require_requester(
    user: StaffUser = Depends(require_permission(Permission.REQUEST_SENSITIVE_ACTION)),
):
    return user


def _load_owned_ticket(request: Request, ticket_id: str, user: StaffUser) -> Ticket | None:
    """VIEW_OWN_TICKETS means own — an agent may not reach another agent's
    ticket just by knowing its id. Returns None (never raises) so every
    caller handles the not-found/not-owned cases identically."""
    try:
        ticket = request.app.state.ticket_repo.get(ticket_id)
    except TicketNotFound:
        return None
    if ticket.agent_id != user.id:
        return None
    return ticket


def _known_subscribers(request: Request) -> frozenset[str]:
    """Subscribers an agent may open a ticket for: the demo directory plus
    anyone with an enrolled channel. A real deployment would look this up
    in the identity provider through an adapter."""
    enrolled = request.app.state.channel_repo.list_distinct_subscribers()
    return KNOWN_SUBSCRIBER_IDS | frozenset(enrolled)


def _status_context(request: Request, ticket: Ticket) -> dict:
    """Everything the verification-status fragment needs. Shared by the full
    ticket page and the htmx polling endpoint so they can't drift apart."""
    orchestrator = request.app.state.orchestrator
    now = datetime.now(UTC)
    orchestrator.check_and_apply_timeout(ticket.id, now=now)
    latest = orchestrator.verification_repo.latest_for_ticket(ticket.id)
    records = request.app.state.audit_log.records_for_ticket(ticket.id)
    blocks = [r for r in records if r.outcome in BLOCKING_OUTCOMES]
    attempt = latest[1] if latest else None
    seconds_remaining = None
    if attempt and attempt.state == VerificationState.PENDING_CONFIRMATION:
        deadline = attempt.pending_since + attempt.timeout
        seconds_remaining = max(0, int((deadline - now).total_seconds()))
    return {
        "ticket": ticket,
        "attempt": attempt,
        "attempt_id": latest[0] if latest else None,
        "code": latest[2] if latest else None,
        "block": blocks[-1] if blocks else None,
        "fraud_reported": any(r.outcome == AuditOutcome.FRAUD_REPORTED for r in records),
        "seconds_remaining": seconds_remaining,
        "audit_records": records,
        "VerificationState": VerificationState,
    }


@router.get("")
def dashboard(request: Request, user: StaffUser = Depends(_require_agent)):
    tickets = request.app.state.ticket_repo.list_for_agent(user.id)
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "agent/dashboard.html", {"current_user": user, "tickets": tickets}
    )


@router.get("/tickets/new")
def new_ticket_form(request: Request, user: StaffUser = Depends(_require_requester)):
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "agent/new_ticket.html",
        {
            "current_user": user,
            "subscribers": DEMO_SUBSCRIBERS,
            "actions": list(TICKET_ACTIONS),
        },
    )


@router.post("/tickets")
def create_ticket(
    request: Request,
    subscriber_id: str = Form(...),
    requested_action: str = Form(...),
    user: StaffUser = Depends(_require_requester),
):
    action = next((a for a in TICKET_ACTIONS if a.value == requested_action), None)
    if action is None or subscriber_id not in _known_subscribers(request):
        return RedirectResponse(
            url="/agent/tickets/new?error=Unknown+subscriber+or+action", status_code=303
        )
    orchestrator = request.app.state.orchestrator
    ticket_id = f"TCK-{uuid.uuid4().hex[:8]}"
    orchestrator.open_ticket_and_start_verification(
        ticket_id=ticket_id,
        agent_id=user.id,
        subscriber_id=subscriber_id,
        requested_action=action,
        now=datetime.now(UTC),
    )
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}", status_code=303)


@router.get("/tickets/{ticket_id}")
def ticket_detail(request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)):
    ticket = _load_owned_ticket(request, ticket_id, user)
    if ticket is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)

    templates = request.app.state.templates
    context = _status_context(request, ticket)
    context["current_user"] = user
    return templates.TemplateResponse(request, "agent/ticket_detail.html", context)


@router.get("/tickets/{ticket_id}/status")
def ticket_status_partial(
    request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)
):
    """htmx polling target: returns just the status fragment so the ticket
    detail page can show a live countdown/outcome without a full reload."""
    ticket = _load_owned_ticket(request, ticket_id, user)
    if ticket is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "agent/_status_partial.html", _status_context(request, ticket)
    )


@router.post("/tickets/{ticket_id}/retry")
def retry_verification(
    request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)
):
    if _load_owned_ticket(request, ticket_id, user) is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)
    request.app.state.orchestrator.retry_verification(ticket_id, now=datetime.now(UTC))
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/restart")
def restart_verification(
    request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)
):
    """For a ticket whose verification never started (no channel, rate
    limited, carrier risk). The orchestrator refuses if any verification
    record already exists, so this can't re-roll a DENIED result."""
    if _load_owned_ticket(request, ticket_id, user) is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)
    attempt_id = request.app.state.orchestrator.restart_verification(
        ticket_id, now=datetime.now(UTC)
    )
    suffix = "" if attempt_id else "?error=Verification+still+blocked+-+see+the+reason+below"
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}{suffix}", status_code=303)


@router.post("/tickets/{ticket_id}/authorize")
def authorize_action(request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)):
    if _load_owned_ticket(request, ticket_id, user) is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)
    try:
        request.app.state.ticketing.mark_action_performed(ticket_id)
    except ClosureBlocked as exc:
        return RedirectResponse(url=f"/agent/tickets/{ticket_id}?error={exc}", status_code=303)
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}", status_code=303)


@router.post("/tickets/{ticket_id}/close")
def close_ticket(request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)):
    if _load_owned_ticket(request, ticket_id, user) is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)
    try:
        request.app.state.ticketing.close_ticket(ticket_id)
    except ClosureBlocked as exc:
        return RedirectResponse(url=f"/agent/tickets/{ticket_id}?error={exc}", status_code=303)
    return RedirectResponse(
        url=f"/agent/tickets/{ticket_id}?success=Ticket+closed", status_code=303
    )
