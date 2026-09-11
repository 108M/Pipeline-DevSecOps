import os
import tempfile
from pathlib import Path

import pytest

# app.config requires FLEET_SECRET_KEY to be set (see docs/VULNERABILITIES.md,
# Vulnerability 2 — no hardcoded default on purpose). Set a fixed, obviously
# fake test-only value *before* anything imports app.config, so test runs
# don't depend on a real secret and JWTs stay verifiable within a single run.
os.environ.setdefault("FLEET_SECRET_KEY", "test-only-secret-key-not-for-production")


@pytest.fixture()
def client():
    # Isolate each test run in its own throwaway SQLite file so tests never
    # touch a real fleet.db and never leak state between tests.
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    os.environ["FLEET_DB_PATH"] = db_path

    # Import after setting the env var so config.py picks it up.
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client

    Path(db_path).unlink(missing_ok=True)


@pytest.fixture()
def auth_headers(client):
    from app import config

    resp = client.post(
        "/auth/token",
        data={"username": config.ADMIN_USERNAME, "password": config.ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
