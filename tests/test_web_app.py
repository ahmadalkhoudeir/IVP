"""Integration tests against the actual FastAPI app via TestClient — the
routes, sessions, RBAC wiring, and templates end to end, not just the
underlying business logic (already covered by the rest of the suite).
"""

import re

from fastapi.testclient import TestClient


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


def test_admin_can_enroll_a_channel_and_it_shows_on_the_subscribers_page(client: TestClient):
    login(client, "admin1", "admin-demo-pass-1")
    resp = client.post(
        "/admin/subscribers/channels",
        data={
            "subscriber_id": "sub-dave",
            "channel_type": "PUSH",
            "label": "Dave's phone",
            "destination": "demo-push-token-dave",
        },
        follow_redirects=False,
    )
    assert "success" in resp.headers["location"]

    page = client.get("/admin/subscribers")
    assert "sub-dave" in page.text
    assert "Dave" in page.text and "phone" in page.text  # Jinja2 escapes the apostrophe
    # The raw destination must never appear in the rendered page.
    assert "demo-push-token-dave" not in page.text


def test_agent_and_supervisor_cannot_reach_the_enrollment_page(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    assert client.get("/admin/subscribers").status_code == 403
    client.post("/logout")

    login(client, "supervisor1", "supervisor-demo-pass-1")
    assert client.get("/admin/subscribers").status_code == 403


def test_enrolling_a_channel_unblocks_a_previously_no_channel_subscriber(client: TestClient):
    """Full circle: sub-carol starts with no enrolled channel (NO_CHANNEL_BLOCKED
    in the demo seed), the admin enrolls one via the new screen, and a fresh
    ticket for her now goes through PENDING_CONFIRMATION instead."""
    login(client, "admin1", "admin-demo-pass-1")
    client.post(
        "/admin/subscribers/channels",
        data={
            "subscriber_id": "sub-carol",
            "channel_type": "PUSH",
            "label": "Carol's new phone",
            "destination": "demo-push-token-carol",
        },
    )
    client.post("/logout")

    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-carol", "requested_action": "PASSWORD_RESET"},
        follow_redirects=False,
    )
    detail = client.get(create_resp.headers["location"])
    assert "PENDING_CONFIRMATION" in detail.text
    assert "NO_CHANNEL_BLOCKED" not in detail.text


def test_create_checkpoint_and_verify_via_admin_audit_page(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-alice", "requested_action": "PASSWORD_RESET"},
        follow_redirects=False,
    )
    ticket_url = create_resp.headers["location"]
    detail = client.get(ticket_url)
    code, attempt_id = _extract_code_and_attempt_id(detail.text)
    client.post(f"/confirm/{attempt_id}", data={"selected_code": code})

    client.post("/logout")
    login(client, "admin1", "admin-demo-pass-1")

    audit_page = client.get("/admin/audit")
    assert "No checkpoints published yet" in audit_page.text

    checkpoint_resp = client.post("/admin/audit/checkpoint", follow_redirects=False)
    assert "Checkpoint+published" in checkpoint_resp.headers["location"]

    audit_page = client.get("/admin/audit")
    assert "No checkpoints published yet" not in audit_page.text

    verify_resp = client.post("/admin/audit/verify", follow_redirects=False)
    assert "checkpoints+match" in verify_resp.headers["location"]


def test_checkpoint_is_a_noop_with_nothing_new(client: TestClient):
    login(client, "admin1", "admin-demo-pass-1")
    resp = client.post("/admin/audit/checkpoint", follow_redirects=False)
    assert "Nothing+new" in resp.headers["location"]


def test_agent_cannot_reach_checkpoint_or_verify_routes(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    assert client.post("/admin/audit/checkpoint").status_code == 403
    assert client.post("/admin/audit/verify").status_code == 403


def test_verify_against_anchors_detects_tampering_via_the_admin_route(client: TestClient):
    login(client, "agent1", "agent-demo-pass-1")
    create_resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": "sub-alice", "requested_action": "PASSWORD_RESET"},
        follow_redirects=False,
    )
    ticket_url = create_resp.headers["location"]
    detail = client.get(ticket_url)
    code, attempt_id = _extract_code_and_attempt_id(detail.text)
    client.post(f"/confirm/{attempt_id}", data={"selected_code": code})

    client.post("/logout")
    login(client, "admin1", "admin-demo-pass-1")
    client.post("/admin/audit/checkpoint")

    # Simulate an attacker with raw database access rewriting a row after
    # the checkpoint was published — bypassing both the Python class (no
    # update method exists) and the SQL trigger (dropped here to simulate a
    # lower-level rewrite, e.g. direct file manipulation), exactly as
    # test_sqlite_audit_log.py's trigger-bypass test does.
    conn = client.app.state.conn
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET outcome = 'DENIED' WHERE sequence = 0")
    conn.commit()

    verify_resp = client.post("/admin/audit/verify", follow_redirects=False)
    assert "TAMPERING+DETECTED" in verify_resp.headers["location"]
