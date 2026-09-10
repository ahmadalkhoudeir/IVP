"""Integration tests against the actual FastAPI app via TestClient — the
routes, sessions, RBAC wiring, and templates end to end, not just the
underlying business logic (already covered by the rest of the suite).
"""

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("IVP_DATABASE_PATH", ":memory:")
    monkeypatch.setenv("IVP_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("IVP_SEED_DEMO_DATA", "true")
    monkeypatch.setenv("IVP_CONFIRMATION_TIMEOUT_SECONDS", "240")
    monkeypatch.setenv("IVP_MAX_CONFIRMATION_ATTEMPTS", "3")

    from ivp.main import create_app

    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, username: str, password: str):
    return client.post(
        "/login", data={"username": username, "password": password}, follow_redirects=False
    )


def test_login_page_renders(client: TestClient):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "Staff login" in resp.text


def test_invalid_login_redirects_with_error(client: TestClient):
    resp = login(client, "agent1", "wrong-password")
    assert resp.status_code == 303
    assert "error" in resp.headers["location"]


def test_valid_login_redirects_to_role_home(client: TestClient):
    resp = login(client, "agent1", "agent-demo-pass-1")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_unauthenticated_access_redirects_to_login(client: TestClient):
    resp = client.get("/agent", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_agent_cannot_access_admin(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    resp = client.get("/admin")
    assert resp.status_code == 403


def test_supervisor_cannot_use_admin_override_route(client: TestClient):
    login(client, "supervisor1", "supervisor-demo-pass-1")
    resp = client.get("/admin/tickets/anything/override")
    assert resp.status_code == 403


def test_supervisor_team_scoped_dashboard_shows_team_tickets(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-alice", "requested_action": "PASSWORD_RESET"},
        follow_redirects=False,
    )
    ticket_id = create_resp.headers["location"].rsplit("/", 1)[-1]

    client.post("/logout")
    login(client, "supervisor1", "supervisor-demo-pass-1")
    resp = client.get("/supervisor")
    assert resp.status_code == 200
    assert ticket_id in resp.text


def _extract_code_and_attempt_id(ticket_html: str) -> tuple[str, str]:
    code = re.search(r'class="code-display">(\d{6})<', ticket_html).group(1)
    attempt_id = re.search(r"/confirm/([0-9a-f-]+)", ticket_html).group(1)
    return code, attempt_id


def test_full_happy_path_approve_and_close(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-alice", "requested_action": "PASSWORD_RESET"},
        follow_redirects=False,
    )
    ticket_url = create_resp.headers["location"]

    detail = client.get(ticket_url)
    assert "PENDING_CONFIRMATION" in detail.text
    code, attempt_id = _extract_code_and_attempt_id(detail.text)

    confirm_get = client.get(f"/confirm/{attempt_id}")
    assert code in confirm_get.text

    confirm_post = client.post(f"/confirm/{attempt_id}", data={"selected_code": code})
    assert "APPROVED" in confirm_post.text

    client.post(ticket_url + "/authorize")
    close_resp = client.post(ticket_url + "/close", follow_redirects=False)
    assert close_resp.status_code == 303
    assert "success" in close_resp.headers["location"]

    final = client.get(ticket_url)
    assert "CLOSED" in final.text
    assert "ACTION PERFORMED" in final.text


def test_wrong_code_denies_and_ticket_can_still_close(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-alice", "requested_action": "MFA_RESET"},
        follow_redirects=False,
    )
    ticket_url = create_resp.headers["location"]
    detail = client.get(ticket_url)
    _code, attempt_id = _extract_code_and_attempt_id(detail.text)

    confirm_post = client.post(f"/confirm/{attempt_id}", data={"selected_code": "000000"})
    assert "DENIED" in confirm_post.text

    close_resp = client.post(ticket_url + "/close", follow_redirects=False)
    assert close_resp.status_code == 303
    assert "success" in close_resp.headers["location"]

    final = client.get(ticket_url)
    assert "CLOSED" in final.text
    assert "ACTION PERFORMED" not in final.text


def test_no_channel_blocked_requires_admin_override(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-carol", "requested_action": "ACCOUNT_UNLOCK"},
        follow_redirects=False,
    )
    ticket_url = create_resp.headers["location"]
    ticket_id = ticket_url.rsplit("/", 1)[-1]
    detail = client.get(ticket_url)
    assert "NO_CHANNEL_BLOCKED" in detail.text

    blocked = client.post(ticket_url + "/close", follow_redirects=False)
    assert "error" in blocked.headers["location"]

    client.post("/logout")
    login(client, "admin1", "admin-demo-pass-1")
    override_resp = client.post(
        f"/admin/tickets/{ticket_id}/override",
        data={"reason": "Identity proofed in person for this test."},
        follow_redirects=False,
    )
    assert "success" in override_resp.headers["location"]

    audit_page = client.get("/admin/audit")
    assert "ADMIN_OVERRIDE" in audit_page.text
    assert "Identity proofed in person for this test." in audit_page.text
