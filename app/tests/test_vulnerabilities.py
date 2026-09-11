"""
Security regression tests for the vulnerabilities documented in
docs/VULNERABILITIES.md.

These tests exist to make the vulnerable behavior *observable* and
reproducible, not just theoretical — and to double as regression tests
once each vulnerability is fixed in its own commit (see
docs/VULNERABILITIES.md for the expected fix and how this test should
change afterwards).
"""


def test_search_endpoint_is_sql_injectable(client, auth_headers):
    """
    Vulnerability 3 (SQL Injection): a payload that closes the quoted LIKE
    pattern, re-closes the surrounding parenthesis, injects an always-true
    condition, and comments out the rest of the query should return every
    device regardless of the intended `asset_tag`/`device_type` filter —
    proving the query is not parameterized.

    The payload has to account for the trailing `%'` the vulnerable code
    appends after `{query}` (see database.py::search_devices) — a naive
    `' OR '1'='1` payload actually lands as the comparison `'1'='1%'`
    (false) once that trailing `%` is appended, and does NOT bypass the
    filter. Closing the parenthesis and starting a `--` comment sidesteps
    that entirely; verified directly against sqlite3 while writing this test.

    After the fix (parameterized query), this same payload must be treated
    as a literal search string and return zero results — flip the
    assertion below when you apply the fix.
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

    # VULNERABLE behavior today: the injected OR '1'='1' bypasses the
    # intended filter and returns every device, even though no device's
    # asset_tag/device_type actually contains the literal "nonexistent".
    tags = [d["asset_tag"] for d in resp.json()]
    assert "SENSOR-100" in tags
    assert "POS-200" in tags


def test_admin_default_credentials_work_out_of_the_box(client):
    """
    Vulnerability 2 (hardcoded/insecure defaults): the seeded operator
    account uses a hardcoded, never-forced-to-rotate password. This test
    documents that the product is NOT secure-by-default (CRA Annex I,
    Part I, 2(b)) until an operator explicitly changes the credential.
    """
    from app import config

    resp = client.post(
        "/auth/token",
        data={"username": config.ADMIN_USERNAME, "password": config.ADMIN_PASSWORD},
    )
    assert resp.status_code == 200
