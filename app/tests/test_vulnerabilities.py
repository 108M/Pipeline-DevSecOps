"""
Security regression tests for the vulnerabilities documented in
docs/VULNERABILITIES.md. Both vulnerabilities covered here (SQL injection
and hardcoded secrets) have already been fixed in this codebase — these
tests exist to prove the fixed behavior stays fixed, not to demonstrate
the original vulnerable behavior (see docs/VULNERABILITIES.md for that;
it also documents the original code, the CWE, and how each was found).
"""


def test_search_endpoint_is_not_sql_injectable(client, auth_headers):
    """
    Vulnerability 3 (SQL Injection) — FIXED. Regression test.

    This exact payload used to close the quoted LIKE pattern, re-close the
    surrounding parenthesis, inject an always-true condition, and comment
    out the rest of the query — bypassing the intended filter entirely
    (verified against sqlite3 directly while the vulnerability was still
    present; see docs/VULNERABILITIES.md, "Vulnerability 3"). Now that
    `search_devices()` uses a parameterized query, the same string is
    treated as a literal search term and matches nothing.
    """
    client.post(
        "/devices",
        json={"asset_tag": "SENSOR-100", "device_type": "iot-sensor", "firmware_version": "1.0"},
        headers=auth_headers,
    )
    client.post(
        "/devices",
        json={"asset_tag": "POS-200", "device_type": "pos-terminal", "firmware_version": "2.0"},
        headers=auth_headers,
    )

    payload = "nonexistent' OR '1'='1') -- "
    resp = client.get(
        "/devices/search", params={"q": payload}, headers=auth_headers
    )
    assert resp.status_code == 200

    # FIXED behavior: the payload is treated as a literal search string,
    # matches nothing, and no injection occurs.
    assert resp.json() == []


def test_seeded_admin_account_logs_in_with_configured_credential(client):
    """
    Vulnerability 2 (hardcoded secrets/insecure defaults) — FIXED.

    `config.SECRET_KEY` now comes from the required `FLEET_SECRET_KEY` env
    var (see conftest.py, which sets a test-only value before import — the
    app itself has no hardcoded fallback and fails fast without one).
    `config.ADMIN_PASSWORD` is either an operator-provided
    `FLEET_ADMIN_PASSWORD` or a randomly generated one-time password — never
    a fixed, guessable value. This test doesn't assert a specific password;
    it asserts that whatever credential the app actually ended up with at
    startup is the one that logs in, proving the seeded account and the JWT
    signing flow both still work end-to-end after the fix.
    """
    from app import config

    resp = client.post(
        "/auth/token",
        data={"username": config.ADMIN_USERNAME, "password": config.ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
