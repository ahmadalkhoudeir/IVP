from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.auth.deps import require_permission
from ivp.auth.roles import Permission
from ivp.core.models import SensitiveAction
from ivp.core.state_machine import VerificationState
from ivp.core.ticket import ClosureBlocked, Ticket
from ivp.db.sqlite_staff_repository import StaffUser
from ivp.services.demo_seed import DEMO_SUBSCRIBERS

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
            "actions": list(SensitiveAction),
        },
    )


@router.post("/tickets")
def create_ticket(
    request: Request,
    subscriber_id: str = Form(...),
    requested_action: str = Form(...),
    user: StaffUser = Depends(_require_requester),
):
    orchestrator = request.app.state.orchestrator
    ticket_id = f"TCK-{uuid.uuid4().hex[:8]}"
    orchestrator.open_ticket_and_start_verification(
        ticket_id=ticket_id,
        agent_id=user.id,
        subscriber_id=subscriber_id,
        requested_action=SensitiveAction(requested_action),
        now=datetime.now(UTC),
    )
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}", status_code=303)


@router.get("/tickets/{ticket_id}")
def ticket_detail(request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)):
    ticket = _load_owned_ticket(request, ticket_id, user)
    if ticket is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)

    templates = request.app.state.templates
    orchestrator = request.app.state.orchestrator
    orchestrator.check_and_apply_timeout(ticket_id, now=datetime.now(UTC))

    latest = orchestrator.verification_repo.latest_for_ticket(ticket_id)
    audit_records = request.app.state.audit_log.records_for_ticket(ticket_id)
    return templates.TemplateResponse(
        request,
        "agent/ticket_detail.html",
        {
            "current_user": user,
            "ticket": ticket,
            "attempt": latest[1] if latest else None,
            "attempt_id": latest[0] if latest else None,
            "code": latest[2] if latest else None,
            "audit_records": audit_records,
            "VerificationState": VerificationState,
        },
    )


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
    orchestrator = request.app.state.orchestrator
    orchestrator.check_and_apply_timeout(ticket_id, now=datetime.now(UTC))
    latest = orchestrator.verification_repo.latest_for_ticket(ticket_id)
    return templates.TemplateResponse(
        request,
        "agent/_status_partial.html",
        {
            "ticket": ticket,
            "attempt": latest[1] if latest else None,
            "attempt_id": latest[0] if latest else None,
            "code": latest[2] if latest else None,
            "VerificationState": VerificationState,
        },
    )


@router.post("/tickets/{ticket_id}/retry")
def retry_verification(
    request: Request, ticket_id: str, user: StaffUser = Depends(_require_agent)
):
    if _load_owned_ticket(request, ticket_id, user) is None:
        return RedirectResponse(url="/agent?error=Ticket+not+found", status_code=303)
    request.app.state.orchestrator.retry_verification(ticket_id, now=datetime.now(UTC))
    return RedirectResponse(url=f"/agent/tickets/{ticket_id}", status_code=303)


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
