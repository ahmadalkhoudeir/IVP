from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ivp.auth.deps import require_permission
from ivp.auth.roles import Permission
from ivp.db.sqlite_staff_repository import StaffUser

router = APIRouter(prefix="/supervisor")


def _require_team_view(
    user: StaffUser = Depends(require_permission(Permission.VIEW_TEAM_TICKETS)),
):
    return user


def _require_team_audit(
    user: StaffUser = Depends(require_permission(Permission.VIEW_TEAM_AUDIT_LOG)),
):
    return user


@router.get("")
def dashboard(request: Request, user: StaffUser = Depends(_require_team_view)):
    templates = request.app.state.templates
    tickets = (
        request.app.state.ticket_repo.list_for_team(user.team_id) if user.team_id else []
    )
    return templates.TemplateResponse(
        request, "supervisor/dashboard.html", {"current_user": user, "tickets": tickets}
    )


@router.get("/audit")
def team_audit(request: Request, user: StaffUser = Depends(_require_team_audit)):
    templates = request.app.state.templates
    audit_log = request.app.state.audit_log
    tickets = (
        request.app.state.ticket_repo.list_for_team(user.team_id) if user.team_id else []
    )
    records = sorted(
        (r for t in tickets for r in audit_log.records_for_ticket(t.id)),
        key=lambda r: r.sequence,
    )
    return templates.TemplateResponse(
        request, "supervisor/audit.html", {"current_user": user, "records": records}
    )
