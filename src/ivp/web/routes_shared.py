"""Routes reachable by more than one role, each with its own server-side
scope check (hard requirement 9).

The verification receipt is the "agent self-protection" adoption driver
from the project brief made concrete: a printable record proving that this
ticket's sensitive action was preceded by an out-of-band confirmation from
a pre-enrolled channel, with the hash of every record and whether the
chain and its external anchors verify right now.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.audit.log import TamperDetected
from ivp.auth.deps import require_login
from ivp.auth.roles import Permission, has_permission
from ivp.core.ticket import Ticket
from ivp.db.sqlite_staff_repository import StaffUser, StaffUserNotFound
from ivp.services.anchor_service import AnchorVerificationFailed
from ivp.services.metrics import resolution_of, time_to_verify

router = APIRouter()


def can_view_ticket(request: Request, user: StaffUser, ticket: Ticket) -> bool:
    if has_permission(user.role, Permission.VIEW_ALL_TICKETS):
        return True
    if has_permission(user.role, Permission.VIEW_TEAM_TICKETS) and user.team_id:
        try:
            owner = request.app.state.staff_repo.get(ticket.agent_id)
        except StaffUserNotFound:
            return False
        return owner.team_id == user.team_id
    if has_permission(user.role, Permission.VIEW_OWN_TICKETS):
        return ticket.agent_id == user.id
    return False


@router.get("/tickets/{ticket_id}/receipt")
def receipt(request: Request, ticket_id: str, user: StaffUser = Depends(require_login)):
    try:
        ticket = request.app.state.ticket_repo.get(ticket_id)
    except TicketNotFound:
        ticket = None
    # Same response for "doesn't exist" and "not yours", so ticket ids
    # can't be probed.
    if ticket is None or not can_view_ticket(request, user, ticket):
        return RedirectResponse(url="/?error=Ticket+not+found", status_code=303)

    audit_log = request.app.state.audit_log
    anchor_service = request.app.state.anchor_service
    records = audit_log.records_for_ticket(ticket_id)

    chain_ok, chain_message = True, "Hash chain recomputes cleanly from genesis."
    try:
        audit_log.verify_integrity()
        anchor_service.verify_against_anchors()
    except (TamperDetected, AnchorVerificationFailed) as exc:
        chain_ok, chain_message = False, f"TAMPERING DETECTED: {exc}"

    latest = anchor_service.anchor_adapter.latest_checkpoint()
    last_sequence = records[-1].sequence if records else None
    anchored = latest is not None and last_sequence is not None and (
        latest.sequence_up_to >= last_sequence
    )
    elapsed = time_to_verify(ticket, records)

    try:
        agent_name = request.app.state.staff_repo.get(ticket.agent_id).username
    except StaffUserNotFound:
        agent_name = ticket.agent_id

    return request.app.state.templates.TemplateResponse(
        request,
        "receipt.html",
        {
            "current_user": user,
            "ticket": ticket,
            "agent_name": agent_name,
            "records": records,
            "resolution": resolution_of(records),
            "elapsed_seconds": elapsed.total_seconds() if elapsed else None,
            "chain_ok": chain_ok,
            "chain_message": chain_message,
            "latest_checkpoint": latest,
            "anchored": anchored,
            "generated_at": datetime.now(UTC),
        },
    )
