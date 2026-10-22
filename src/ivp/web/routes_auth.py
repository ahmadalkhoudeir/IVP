from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from ivp.auth.authentication import InvalidCredentials, authenticate
from ivp.auth.deps import get_current_user
from ivp.auth.roles import Role
from ivp.auth.session import SESSION_COOKIE_NAME, create_session_cookie

router = APIRouter()


@router.get("/login")
def login_form(request: Request):
    templates = request.app.state.templates
    if get_current_user(request) is not None:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(request, "login.html", {"current_user": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    staff_repo = request.app.state.staff_repo
    throttle = request.app.state.login_throttle
    now = datetime.now(UTC)
    if throttle.is_locked(username, now):
        # Checked before the password, so a correct guess during lockout
        # still fails and gives the attacker no signal.
        return RedirectResponse(
            url="/login?error=Too+many+failed+attempts.+Try+again+in+15+minutes.",
            status_code=303,
        )
    try:
        user = authenticate(staff_repo, username=username, password=password)
    except InvalidCredentials:
        throttle.record_failure(username, now)
        return RedirectResponse(
            url="/login?error=Invalid+username+or+password", status_code=303
        )
    throttle.record_success(username)

    cookie_value = create_session_cookie(request.app.state.settings.session_secret, user.id)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        cookie_value,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@router.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


@router.get("/")
def index(request: Request):
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login")
    destination = {
        Role.AGENT: "/agent",
        Role.SUPERVISOR: "/supervisor",
        Role.ADMIN: "/admin",
    }[user.role]
    return RedirectResponse(url=destination)
