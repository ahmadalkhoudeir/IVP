from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.auth.deps import require_permission
from ivp.auth.passwords import hash_password
from ivp.auth.roles import Permission, Role
from ivp.core.models import ChannelType
from ivp.core.ticket import ClosureBlocked
from ivp.db.sqlite_staff_repository import StaffUser, UsernameAlreadyExists

router = APIRouter(prefix="/admin")


def _require(permission: Permission):
    def dependency(user: StaffUser = Depends(require_permission(permission))):
        return user

    return dependency


@router.get("")
def dashboard(request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_TICKETS))):
    templates = request.app.state.templates
    tickets = request.app.state.ticket_repo.list_all()
    return templates.TemplateResponse(
        request, "admin/dashboard.html", {"current_user": user, "tickets": tickets}
    )


@router.get("/audit")
def full_audit(
    request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_AUDIT_LOG))
):
    templates = request.app.state.templates
    records = request.app.state.audit_log.all_records()
    return templates.TemplateResponse(
        request, "admin/audit.html", {"current_user": user, "records": records}
    )


@router.get("/users")
def list_users(
    request: Request, user: StaffUser = Depends(_require(Permission.MANAGE_STAFF_ACCOUNTS))
):
    templates = request.app.state.templates
    staff = request.app.state.staff_repo.list_all()
    return templates.TemplateResponse(
        request, "admin/users.html", {"current_user": user, "staff": staff, "roles": list(Role)}
    )


@router.post("/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    team_id: str = Form(""),
    user: StaffUser = Depends(_require(Permission.MANAGE_STAFF_ACCOUNTS)),
):
    try:
        request.app.state.staff_repo.create(
            username=username,
            password_hash=hash_password(password),
            role=Role(role),
            team_id=team_id or None,
        )
    except UsernameAlreadyExists:
        return RedirectResponse(url="/admin/users?error=Username+already+exists", status_code=303)
    return RedirectResponse(url="/admin/users?success=Account+created", status_code=303)


@router.get("/adapters")
def adapter_info(
    request: Request, user: StaffUser = Depends(_require(Permission.MANAGE_ADAPTER_CONFIG))
):
    templates = request.app.state.templates
    orchestrator = request.app.state.orchestrator
    return templates.TemplateResponse(
        request,
        "admin/adapters.html",
        {
            "current_user": user,
            "max_attempts": orchestrator.max_attempts,
            "timeout_seconds": int(orchestrator.timeout.total_seconds()),
        },
    )


@router.get("/subscribers")
def list_subscribers(
    request: Request, user: StaffUser = Depends(_require(Permission.MANAGE_CHANNEL_ENROLLMENTS))
):
    """Deliberately not reachable from any ticket/call route (no ticket_id
    anywhere in this path) — hard requirement 2 says channel enrollment
    must be a separate, out-of-band process, not something that happens
    mid-call."""
    templates = request.app.state.templates
    channel_repo = request.app.state.channel_repo
    ticket_repo = request.app.state.ticket_repo

    subscriber_ids = sorted(
        set(channel_repo.list_distinct_subscribers()) | set(ticket_repo.list_distinct_subscribers())
    )
    subscribers = [
        {"id": sub_id, "channels": channel_repo.list_for_subscriber(sub_id)}
        for sub_id in subscriber_ids
    ]
    return templates.TemplateResponse(
        request,
        "admin/subscribers.html",
        {"current_user": user, "subscribers": subscribers, "channel_types": list(ChannelType)},
    )


@router.post("/subscribers/channels")
def enroll_channel(
    request: Request,
    subscriber_id: str = Form(...),
    channel_type: str = Form(...),
    label: str = Form(...),
    destination: str = Form(...),
    user: StaffUser = Depends(_require(Permission.MANAGE_CHANNEL_ENROLLMENTS)),
):
    request.app.state.channel_repo.enroll(
        subscriber_id=subscriber_id.strip(),
        channel_type=ChannelType(channel_type),
        label=label,
        destination=destination,
        now=datetime.now(UTC),
    )
    return RedirectResponse(url="/admin/subscribers?success=Channel+enrolled", status_code=303)


@router.get("/tickets/{ticket_id}/override")
def override_form(
    request: Request,
    ticket_id: str,
    user: StaffUser = Depends(require_permission(Permission.ADMIN_OVERRIDE_TICKET)),
):
    templates = request.app.state.templates
    try:
        ticket = request.app.state.ticket_repo.get(ticket_id)
    except TicketNotFound:
        return RedirectResponse(url="/admin?error=Ticket+not+found", status_code=303)
    return templates.TemplateResponse(
        request, "admin/override.html", {"current_user": user, "ticket": ticket}
    )


@router.post("/tickets/{ticket_id}/override")
def submit_override(
    request: Request,
    ticket_id: str,
    reason: str = Form(...),
    user: StaffUser = Depends(require_permission(Permission.ADMIN_OVERRIDE_TICKET)),
):
    closure_gate = request.app.state.closure_gate
    ticketing = request.app.state.ticketing
    now = datetime.now(UTC)
    try:
        ticket = ticketing.get_ticket(ticket_id)
    except TicketNotFound:
        return RedirectResponse(url="/admin?error=Ticket+not+found", status_code=303)

    try:
        closure_gate.admin_override(
            ticket, actor_id=user.id, actor_role=user.role, reason=reason, now=now
        )
        ticketing.mark_action_performed(ticket_id)
        ticketing.close_ticket(ticket_id)
    except ClosureBlocked as exc:
        return RedirectResponse(url=f"/admin?error={exc}", status_code=303)

    return RedirectResponse(
        url="/admin?success=Override+recorded+and+ticket+closed", status_code=303
    )
