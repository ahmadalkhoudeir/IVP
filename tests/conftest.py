"""Shared fixtures. `client` is a TestClient over a fresh in-memory app with
the synthetic demo seed."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("IVP_DATABASE_PATH", ":memory:")
    monkeypatch.setenv("IVP_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("IVP_SEED_DEMO_DATA", "true")
    monkeypatch.setenv("IVP_CONFIRMATION_TIMEOUT_SECONDS", "240")
    monkeypatch.setenv("IVP_MAX_CONFIRMATION_ATTEMPTS", "3")
    monkeypatch.setenv("IVP_ANCHOR_LOG_PATH", str(tmp_path / "anchor_log.jsonl"))

    from ivp.main import create_app

    app = create_app()
    with TestClient(app, headers={"origin": "http://testserver"}) as test_client:
        yield test_client
