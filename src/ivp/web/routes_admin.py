from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from ivp.adapters.ticketing.interface import TicketNotFound
from ivp.audit.log import TamperDetected
from ivp.auth.deps import require_permission
from ivp.auth.passwords import hash_password
from ivp.auth.roles import Permission, Role
from ivp.core.models import ChannelType
from ivp.core.ticket import ClosureBlocked
from ivp.db.sqlite_staff_repository import StaffUser, UsernameAlreadyExists
from ivp.services.anchor_service import AnchorVerificationFailed
from ivp.services.audit_export import records_to_csv
from ivp.services.enrollment_service import EnrollmentRejected
from ivp.services.metrics import compute_metrics

router = APIRouter(prefix="/admin")


def _require(permission: Permission):
    def dependency(user: StaffUser = Depends(require_permission(permission))):
        return user

    return dependency


@router.get("")
def dashboard(request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_TICKETS))):
    templates = request.app.state.templates
    tickets = request.app.state.ticket_repo.list_all()
    metrics = compute_metrics(tickets, request.app.state.audit_log)
    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {"current_user": user, "tickets": tickets, "fraud_ticket_ids": metrics.fraud_ticket_ids},
    )


@router.get("/metrics")
def all_metrics(request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_TICKETS))):
    templates = request.app.state.templates
    metrics = compute_metrics(request.app.state.ticket_repo.list_all(), request.app.state.audit_log)
    return templates.TemplateResponse(
        request,
        "metrics.html",
        {"current_user": user, "metrics": metrics, "scope": "all teams", "back_url": "/admin"},
    )


@router.get("/audit/export.csv")
def export_audit(
    request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_AUDIT_LOG))
):
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        records_to_csv(request.app.state.audit_log.all_records()),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ivp-audit-{stamp}.csv"'},
    )


@router.get("/audit")
def full_audit(
    request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_AUDIT_LOG))
):
    templates = request.app.state.templates
    records = request.app.state.audit_log.all_records()
    checkpoints = request.app.state.anchor_service.anchor_adapter.list_checkpoints()
    return templates.TemplateResponse(
        request,
        "admin/audit.html",
        {"current_user": user, "records": records, "checkpoints": checkpoints},
    )


@router.post("/audit/checkpoint")
def create_checkpoint(
    request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_AUDIT_LOG))
):
    receipt = request.app.state.anchor_service.checkpoint_if_new_records(now=datetime.now(UTC))
    if receipt is None:
        return RedirectResponse(url="/admin/audit?error=Nothing+new+to+checkpoint", status_code=303)
    return RedirectResponse(
        url=f"/admin/audit?success=Checkpoint+published+through+sequence+{receipt.sequence_up_to}",
        status_code=303,
    )


@router.post("/audit/verify")
def verify_anchors(
    request: Request, user: StaffUser = Depends(_require(Permission.VIEW_ALL_AUDIT_LOG))
):
    """Runs both tamper checks available: verify_integrity() catches a
    record whose content no longer matches its own stored hash (a naive
    edit); verify_against_anchors() catches a full, internally-consistent
    rewrite that recomputed every hash forward — see
    docs/decisions/audit-anchoring.md for why both are needed."""
    try:
        request.app.state.audit_log.verify_integrity()
        request.app.state.anchor_service.verify_against_anchors()
    except (TamperDetected, AnchorVerificationFailed) as exc:
        return RedirectResponse(
            url=f"/admin/audit?error=TAMPERING+DETECTED:+{exc}", status_code=303
        )
    return RedirectResponse(
        url="/admin/audit?success=All+published+checkpoints+match+the+live+log",
        status_code=303,
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
    if role not in {r.value for r in Role} or not username.strip() or len(password) < 12:
        return RedirectResponse(
            url="/admin/users?error=Pick+a+valid+role,+a+username,+and+a+password+of+12%2B+characters",
            status_code=303,
        )
    try:
        request.app.state.staff_repo.create(
            username=username.strip(),
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
    notices = sorted(
        [
            *request.app.state.push_adapter.enrollment_notices,
            *request.app.state.pstn_adapter.enrollment_notices,
        ],
        key=lambda n: n.sent_at,
        reverse=True,
    )
    labels = {c.id: c.label for s in subscribers for c in s["channels"]}
    return templates.TemplateResponse(
        request,
        "admin/subscribers.html",
        {
            "current_user": user,
            "subscribers": subscribers,
            "channel_types": list(ChannelType),
            "now": datetime.now(UTC),
            "notices": notices,
            "channel_labels": labels,
            "cooling_off_hours": request.app.state.settings.enrollment_cooling_off.total_seconds()
            / 3600,
        },
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
    try:
        kind = ChannelType(channel_type)
    except ValueError:
        return RedirectResponse(
            url="/admin/subscribers?error=Unknown+channel+type", status_code=303
        )
    try:
        result = request.app.state.enrollment_service.enroll(
            subscriber_id=subscriber_id,
            channel_type=kind,
            label=label,
            destination=destination,
            actor_id=user.id,
            actor_role=user.role.value,
            now=datetime.now(UTC),
        )
    except EnrollmentRejected as exc:
        return RedirectResponse(
            url=f"/admin/subscribers?{urlencode({'error': str(exc)})}", status_code=303
        )
    if result.cooling_off_applied:
        message = (
            f"Channel enrolled. {result.notified_channels} existing channel(s) notified; "
            "the new channel is usable after the cooling-off period."
        )
    else:
        message = "Channel enrolled and usable now (first channel for this subscriber)."
    return RedirectResponse(
        url=f"/admin/subscribers?{urlencode({'success': message})}", status_code=303
    )


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
