from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from ivp.auth.deps import require_permission
from ivp.auth.roles import Permission
from ivp.db.sqlite_staff_repository import StaffUser
from ivp.services.audit_export import records_to_csv
from ivp.services.metrics import compute_metrics

router = APIRouter(prefix="/supervisor")


def _require_team_view(
    user: StaffUser = Depends(require_permission(Permission.VIEW_TEAM_TICKETS)),
):
    return user


def _require_team_audit(
    user: StaffUser = Depends(require_permission(Permission.VIEW_TEAM_AUDIT_LOG)),
):
    return user


def _team_tickets(request: Request, user: StaffUser):
    return request.app.state.ticket_repo.list_for_team(user.team_id) if user.team_id else []


def _team_records(request: Request, user: StaffUser):
    audit_log = request.app.state.audit_log
    return sorted(
        (r for t in _team_tickets(request, user) for r in audit_log.records_for_ticket(t.id)),
        key=lambda r: r.sequence,
    )


@router.get("")
def dashboard(request: Request, user: StaffUser = Depends(_require_team_view)):
    templates = request.app.state.templates
    tickets = _team_tickets(request, user)
    metrics = compute_metrics(tickets, request.app.state.audit_log)
    return templates.TemplateResponse(
        request,
        "supervisor/dashboard.html",
        {"current_user": user, "tickets": tickets, "fraud_ticket_ids": metrics.fraud_ticket_ids},
    )


@router.get("/metrics")
def team_metrics(request: Request, user: StaffUser = Depends(_require_team_view)):
    templates = request.app.state.templates
    metrics = compute_metrics(_team_tickets(request, user), request.app.state.audit_log)
    return templates.TemplateResponse(
        request,
        "metrics.html",
        {
            "current_user": user,
            "metrics": metrics,
            "agent_names": {u.id: u.username for u in request.app.state.staff_repo.list_all()},
            "scope": f"team {user.team_id}",
            "back_url": "/supervisor",
        },
    )


@router.get("/audit")
def team_audit(request: Request, user: StaffUser = Depends(_require_team_audit)):
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "supervisor/audit.html",
        {"current_user": user, "records": _team_records(request, user)},
    )


@router.get("/audit/export.csv")
def export_team_audit(request: Request, user: StaffUser = Depends(_require_team_audit)):
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        records_to_csv(_team_records(request, user)),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ivp-team-audit-{stamp}.csv"'},
    )
