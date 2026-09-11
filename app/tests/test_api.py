def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_login_success(auth_headers):
    assert "Authorization" in auth_headers


def test_login_wrong_password(client):
    from app import config

    resp = client.post(
        "/auth/token",
        data={"username": config.ADMIN_USERNAME, "password": "wrong-password"},
    )
    assert resp.status_code == 401


def test_devices_require_auth(client):
    resp = client.get("/devices")
    assert resp.status_code == 401


def test_register_and_list_device(client, auth_headers):
    create_resp = client.post(
        "/devices",
        json={
            "asset_tag": "SENSOR-001",
            "device_type": "iot-sensor",
            "firmware_version": "1.4.2",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    device = create_resp.json()
    assert device["asset_tag"] == "SENSOR-001"
    assert device["status"] == "active"

    list_resp = client.get("/devices", headers=auth_headers)
    assert list_resp.status_code == 200
    tags = [d["asset_tag"] for d in list_resp.json()]
    assert "SENSOR-001" in tags


def test_duplicate_asset_tag_is_rejected(client, auth_headers):
    payload = {
        "asset_tag": "POS-100",
        "device_type": "pos-terminal",
        "firmware_version": "2.0.0",
    }
    first = client.post("/devices", json=payload, headers=auth_headers)
    assert first.status_code == 201

    second = client.post("/devices", json=payload, headers=auth_headers)
    assert second.status_code == 409


def test_heartbeat_updates_firmware_and_last_seen(client, auth_headers):
    created = client.post(
        "/devices",
        json={
            "asset_tag": "PLC-050",
            "device_type": "industrial-plc",
            "firmware_version": "3.1.0",
        },
        headers=auth_headers,
    ).json()

    assert created["last_seen"] is None

    hb_resp = client.post(
        f"/devices/{created['id']}/heartbeat",
        json={"firmware_version": "3.2.0"},
        headers=auth_headers,
    )
    assert hb_resp.status_code == 200
    updated = hb_resp.json()
    assert updated["firmware_version"] == "3.2.0"
    assert updated["last_seen"] is not None


def test_update_status_and_delete_device(client, auth_headers):
    created = client.post(
        "/devices",
        json={
            "asset_tag": "SENSOR-002",
            "device_type": "iot-sensor",
            "firmware_version": "1.0.0",
        },
        headers=auth_headers,
    ).json()
    device_id = created["id"]

    patch_resp = client.patch(
        f"/devices/{device_id}", json={"status": "quarantined"}, headers=auth_headers
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "quarantined"

    delete_resp = client.delete(f"/devices/{device_id}", headers=auth_headers)
    assert delete_resp.status_code == 204

    missing_resp = client.get(f"/devices/{device_id}", headers=auth_headers)
    assert missing_resp.status_code == 404


def test_get_nonexistent_device_returns_404(client, auth_headers):
    resp = client.get("/devices/999999", headers=auth_headers)
    assert resp.status_code == 404
