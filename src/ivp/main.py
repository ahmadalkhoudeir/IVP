"""FastAPI app factory. Wires the SQLite connection, repositories, mock
adapters, and the verification orchestrator into app.state so routes (via
auth/deps.py) can reach them without a global.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ivp.adapters.anchoring.local_file import LocalFileAnchorAdapter
from ivp.adapters.notification.mock_pstn import MockPstnAdapter
from ivp.adapters.notification.mock_push import MockPushAdapter
from ivp.adapters.ticketing.sqlite_backed import SqlitePersistedTicketingAdapter
from ivp.auth.deps import Forbidden, NotAuthenticated
from ivp.auth.throttle import LoginThrottle
from ivp.core.ticket import TicketClosureGate
from ivp.db.connection import connect
from ivp.db.sqlite_audit_log import SqliteAuditLog
from ivp.db.sqlite_channel_repository import SqliteChannelRepository
from ivp.db.sqlite_staff_repository import SqliteStaffRepository
from ivp.db.sqlite_ticket_repository import SqliteTicketRepository
from ivp.db.sqlite_verification_repository import SqliteVerificationRepository
from ivp.services.anchor_service import AuditAnchorService
from ivp.services.demo_seed import apply_demo_risk_signals, seed_if_empty
from ivp.services.enrollment_service import ChannelEnrollmentService
from ivp.services.verification_service import VerificationOrchestrator
from ivp.settings import load_settings
from ivp.web.routes_admin import router as admin_router
from ivp.web.routes_agent import router as agent_router
from ivp.web.routes_auth import router as auth_router
from ivp.web.routes_holder import router as holder_router
from ivp.web.routes_shared import router as shared_router
from ivp.web.routes_supervisor import router as supervisor_router
from ivp.web.security import SecurityMiddleware

BASE_DIR = Path(__file__).parent


def create_app() -> FastAPI:
    app = FastAPI(title="IVP — Help Desk Identity Verification Protocol")

    settings = load_settings()
    conn = connect(settings.database_path)

    audit_log = SqliteAuditLog(conn)
    ticket_repo = SqliteTicketRepository(conn)
    channel_repo = SqliteChannelRepository(conn)
    verification_repo = SqliteVerificationRepository(conn)
    staff_repo = SqliteStaffRepository(conn)
    closure_gate = TicketClosureGate(audit_log)
    ticketing = SqlitePersistedTicketingAdapter(ticket_repo, closure_gate)

    push_adapter = MockPushAdapter()
    pstn_adapter = MockPstnAdapter()
    orchestrator = VerificationOrchestrator(
        ticket_repo=ticket_repo,
        channel_repo=channel_repo,
        verification_repo=verification_repo,
        audit_log=audit_log,
        push_adapter=push_adapter,
        pstn_adapter=pstn_adapter,
        max_attempts=settings.max_confirmation_attempts,
        timeout=settings.confirmation_timeout,
    )

    enrollment_service = ChannelEnrollmentService(
        channel_repo=channel_repo,
        audit_log=audit_log,
        push_adapter=push_adapter,
        pstn_adapter=pstn_adapter,
        cooling_off=settings.enrollment_cooling_off,
    )

    if settings.seed_demo_data:
        seed_if_empty(staff_repo, channel_repo)
        apply_demo_risk_signals(channel_repo, pstn_adapter)

    anchor_service = AuditAnchorService(
        audit_log=audit_log, anchor_adapter=LocalFileAnchorAdapter(settings.anchor_log_path)
    )
    anchor_service.checkpoint_if_new_records(now=datetime.now(UTC))

    app.state.settings = settings
    app.state.conn = conn
    app.state.audit_log = audit_log
    app.state.ticket_repo = ticket_repo
    app.state.channel_repo = channel_repo
    app.state.verification_repo = verification_repo
    app.state.staff_repo = staff_repo
    app.state.closure_gate = closure_gate
    app.state.ticketing = ticketing
    app.state.orchestrator = orchestrator
    app.state.anchor_service = anchor_service
    app.state.enrollment_service = enrollment_service
    app.state.push_adapter = push_adapter
    app.state.pstn_adapter = pstn_adapter
    app.state.login_throttle = LoginThrottle()
    app.state.templates = Jinja2Templates(directory=str(BASE_DIR / "web" / "templates"))

    app.add_middleware(SecurityMiddleware)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web" / "static")), name="static")

    @app.exception_handler(NotAuthenticated)
    async def handle_not_authenticated(request, exc):  # noqa: ARG001, ANN001
        return RedirectResponse(url="/login", status_code=303)

    @app.exception_handler(Forbidden)
    async def handle_forbidden(request, exc: Forbidden):  # noqa: ARG001, ANN001
        return HTMLResponse(
            f"<h1>403 Forbidden</h1><p>Role {exc.role.value} may not access this page.</p>",
            status_code=403,
        )

    app.include_router(auth_router)
    app.include_router(agent_router)
    app.include_router(supervisor_router)
    app.include_router(admin_router)
    app.include_router(holder_router)
    app.include_router(shared_router)

    return app


app = create_app()
