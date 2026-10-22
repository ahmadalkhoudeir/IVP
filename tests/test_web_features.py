"""End-to-end tests for the v1.1 features through the real FastAPI app:
hardening, blocked-verification UX, fraud reporting, enrollment
cooling-off, metrics, receipts and CSV export, each with its RBAC check."""

import time
from datetime import timedelta

from fastapi.testclient import TestClient

from ivp.adapters.notification.rate_limit import SlidingWindowRateLimiter
from tests.test_web_app import _extract_code_and_attempt_id, login

AGENT = ("agent1", "agent-demo-pass-1")
AGENT2 = ("agent2", "agent-demo-pass-2")
SUPERVISOR = ("supervisor1", "supervisor-demo-pass-1")
ADMIN = ("admin1", "admin-demo-pass-1")


def _as(client: TestClient, creds):
    client.post("/logout")
    login(client, *creds)


def _open_ticket(client: TestClient, subscriber="sub-alice", action="PASSWORD_RESET") -> str:
    resp = client.post(
        "/agent/tickets",
        data={"subscriber_id": subscriber, "requested_action": action},
        follow_redirects=False,
    )
    return resp.headers["location"]


# ---- hardening -------------------------------------------------------------


def test_security_headers_on_every_page(client: TestClient):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    assert "cache-control" not in client.get("/static/style.css").headers or (
        client.get("/static/style.css").headers["cache-control"] != "no-store"
    )


def test_cross_site_post_is_rejected_same_site_allowed(client: TestClient):
    evil = client.post(
        "/login",
        data={"username": "agent1", "password": "agent-demo-pass-1"},
        headers={"origin": "https://evil.example"},
        follow_redirects=False,
    )
    assert evil.status_code == 403
    ok = client.post(
        "/login",
        data={"username": "agent1", "password": "agent-demo-pass-1"},
        headers={"origin": "http://testserver"},
        follow_redirects=False,
    )
    assert ok.status_code == 303


def test_login_locks_after_repeated_failures_even_with_right_password(client: TestClient):
    for _ in range(5):
        login(client, "agent1", "wrong")
    resp = login(client, *AGENT)
    assert "Too+many+failed+attempts" in resp.headers["location"]
    assert client.get("/agent", follow_redirects=False).status_code == 303


def test_admin_session_expires_after_one_hour_agent_session_does_not(
    client: TestClient, monkeypatch
):
    login(client, *ADMIN)
    assert client.get("/admin").status_code == 200
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 60 * 60)
    assert client.get("/admin", follow_redirects=False).status_code == 303
    monkeypatch.setattr(time, "time", real_time)

    _as(client, AGENT)
    monkeypatch.setattr(time, "time", lambda: real_time() + 2 * 60 * 60)
    assert client.get("/agent").status_code == 200


def test_unknown_action_or_subscriber_is_rejected(client: TestClient):
    login(client, *AGENT)
    for data in (
        {"subscriber_id": "sub-alice", "requested_action": "CHANNEL_ENROLLMENT"},
        {"subscriber_id": "sub-alice", "requested_action": "DROP_TABLES"},
        {"subscriber_id": "sub-nobody", "requested_action": "PASSWORD_RESET"},
    ):
        resp = client.post("/agent/tickets", data=data, follow_redirects=False)
        assert "error" in resp.headers["location"]
    assert "CHANNEL_ENROLLMENT" not in client.get("/agent/tickets/new").text


def test_admin_cannot_create_staff_with_short_password(client: TestClient):
    login(client, *ADMIN)
    resp = client.post(
        "/admin/users",
        data={"username": "x", "password": "short", "role": "AGENT"},
        follow_redirects=False,
    )
    assert "error" in resp.headers["location"]


# ---- blocked verification ---------------------------------------------------


def test_rate_limited_ticket_shows_reason_instead_of_crashing(client: TestClient):
    client.app.state.push_adapter._rate_limiter = SlidingWindowRateLimiter(
        max_sends=1, window=timedelta(minutes=10)
    )
    login(client, *AGENT)
    _open_ticket(client)
    second = _open_ticket(client)
    page = client.get(second)
    assert page.status_code == 200
    assert "RATE_LIMITED" in page.text
    assert "Try verification again" in page.text
    restart = client.post(second + "/restart", follow_redirects=False)
    assert "still+blocked" in restart.headers["location"]


def test_ported_number_is_risk_blocked(client: TestClient):
    login(client, *AGENT)
    page = client.get(_open_ticket(client, subscriber="sub-erin"))
    assert "RISK_BLOCKED" in page.text
    assert "class=\"code-display\"" not in page.text


def test_pending_ticket_shows_countdown(client: TestClient):
    login(client, *AGENT)
    page = client.get(_open_ticket(client))
    assert "expires in" in page.text


# ---- fraud reporting ---------------------------------------------------------


def test_fraud_report_flows_to_agent_supervisor_and_metrics(client: TestClient):
    login(client, *AGENT)
    ticket_url = _open_ticket(client)
    ticket_id = ticket_url.rsplit("/", 1)[-1]
    _code, attempt_id = _extract_code_and_attempt_id(client.get(ticket_url).text)

    result = client.post(f"/confirm/{attempt_id}/report")
    assert "REPORTED" in result.text

    page = client.get(ticket_url)
    assert "FRAUD_REPORTED" in page.text
    blocked = client.post(ticket_url + "/authorize", follow_redirects=False)
    assert "error" in blocked.headers["location"]

    _as(client, SUPERVISOR)
    dash = client.get("/supervisor")
    assert "Fraud reported on 1 ticket" in dash.text and ticket_id in dash.text
    assert "Fraud reports" in client.get("/supervisor/metrics").text


# ---- enrollment ----------------------------------------------------------------


def test_second_channel_cools_off_notifies_and_is_audited(client: TestClient):
    login(client, *ADMIN)
    resp = client.post(
        "/admin/subscribers/channels",
        data={
            "subscriber_id": "sub-alice",
            "channel_type": "PSTN",
            "label": "Alice new cell",
            "destination": "+15555550199",
        },
        follow_redirects=False,
    )
    assert "existing+channel" in resp.headers["location"]
    page = client.get("/admin/subscribers")
    assert "cooling off until" in page.text
    assert "Enrollment notices sent" in page.text
    assert "+15555550199" not in page.text
    assert "CHANNEL_ENROLLED" in client.get("/admin/audit").text

    dup = client.post(
        "/admin/subscribers/channels",
        data={
            "subscriber_id": "sub-alice",
            "channel_type": "PSTN",
            "label": "Again",
            "destination": "+15555550199",
        },
        follow_redirects=False,
    )
    assert "already+enrolled" in dup.headers["location"]

    # The ticket still goes to Alice's original PUSH channel.
    _as(client, AGENT)
    assert "PENDING_CONFIRMATION" in client.get(_open_ticket(client)).text


# ---- receipts, metrics, export ---------------------------------------------------


def _approved_ticket(client: TestClient) -> str:
    login(client, *AGENT)
    ticket_url = _open_ticket(client)
    code, attempt_id = _extract_code_and_attempt_id(client.get(ticket_url).text)
    client.post(f"/confirm/{attempt_id}", data={"selected_code": code})
    return ticket_url.rsplit("/", 1)[-1]


def test_receipt_shows_hashes_and_is_scoped_by_role(client: TestClient):
    ticket_id = _approved_ticket(client)
    receipt = client.get(f"/tickets/{ticket_id}/receipt")
    assert receipt.status_code == 200
    assert "VERIFIED" in receipt.text and "APPROVED" in receipt.text
    record_hash = client.app.state.audit_log.records_for_ticket(ticket_id)[0].record_hash
    assert record_hash in receipt.text

    for creds in (SUPERVISOR, ADMIN):
        _as(client, creds)
        assert client.get(f"/tickets/{ticket_id}/receipt").status_code == 200

    _as(client, AGENT2)
    other = client.get(f"/tickets/{ticket_id}/receipt", follow_redirects=False)
    assert other.status_code == 303 and "not+found" in other.headers["location"]

    client.post("/logout")
    anon = client.get(f"/tickets/{ticket_id}/receipt", follow_redirects=False)
    assert anon.headers["location"] == "/login"


def test_receipt_reports_tampering(client: TestClient):
    ticket_id = _approved_ticket(client)
    conn = client.app.state.conn
    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("UPDATE audit_log SET outcome = 'DENIED' WHERE sequence = 0")
    conn.commit()
    assert "TAMPERING DETECTED" in client.get(f"/tickets/{ticket_id}/receipt").text


def test_metrics_pages_and_rbac(client: TestClient):
    _approved_ticket(client)
    assert client.get("/supervisor/metrics").status_code == 403
    assert client.get("/admin/metrics").status_code == 403

    _as(client, SUPERVISOR)
    page = client.get("/supervisor/metrics")
    assert page.status_code == 200 and "Median time to verify" in page.text
    assert "agent1" in page.text
    assert client.get("/admin/metrics").status_code == 403

    _as(client, ADMIN)
    assert client.get("/admin/metrics").status_code == 200


def test_csv_export_rbac_and_content(client: TestClient):
    ticket_id = _approved_ticket(client)
    assert client.get("/admin/audit/export.csv").status_code == 403
    assert client.get("/supervisor/audit/export.csv").status_code == 403

    _as(client, SUPERVISOR)
    team = client.get("/supervisor/audit/export.csv")
    assert team.status_code == 200
    assert team.headers["content-type"].startswith("text/csv")
    assert ticket_id in team.text and "record_hash" in team.text

    _as(client, ADMIN)
    full = client.get("/admin/audit/export.csv")
    assert full.status_code == 200 and "attachment" in full.headers["content-disposition"]
