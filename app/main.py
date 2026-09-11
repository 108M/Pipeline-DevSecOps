"""
Fleet Compliance API — a small, deliberately realistic FastAPI service used
as the target application for the DevSecOps pipeline in this repository.

What it's for: security/IT teams that operate a fleet of connected devices
(IoT sensors, POS terminals, industrial controllers, ...) need a single place
to know *what firmware each device is currently running* and to flag devices
that fall behind — exactly the kind of asset & vulnerability inventory the
EU Cyber Resilience Act expects manufacturers/operators to maintain (see
CRA_MAPPING.md). Devices check in via a `/heartbeat` endpoint the way a real
OTA (over-the-air) update agent would.

See docs/VULNERABILITIES.md for the 3 intentional, documented vulnerabilities
this app ships with, and its final section for the hardening-headers
middleware below — added after a real OWASP ZAP run against this exact app
flagged `X-Content-Type-Options` and `Cross-Origin-Resource-Policy` as
missing, which is why those two are non-negotiable here; the rest follow
standard API-hardening practice for a JSON-only service with no
browser-rendered frontend.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from . import auth, database, models
from .feature_flags import load_feature_flags


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    yield


app = FastAPI(
    title="Fleet Compliance API",
    description=(
        "Tracks a fleet of connected devices and their firmware compliance "
        "status. Portfolio demo API for a DevSecOps / CRA pipeline project."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # No browser-rendered frontend ships from this origin, so a maximally
    # restrictive CSP is correct here rather than a permissive default.
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains"
    )
    return response


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/auth/token", response_model=models.Token, tags=["auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends()) -> models.Token:
    user = database.get_user(form_data.username)
    if user is None or not auth.verify_password(
        form_data.password, user["hashed_password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth.create_access_token(subject=user["username"])
    return models.Token(access_token=token)


@app.post(
    "/devices",
    response_model=models.DeviceOut,
    status_code=status.HTTP_201_CREATED,
    tags=["devices"],
)
def register_device(
    device: models.DeviceCreate,
    username: str = Depends(auth.get_current_username),
) -> models.DeviceOut:
    try:
        row = database.create_device(
            device.asset_tag, device.device_type, device.firmware_version, username
        )
    except Exception as exc:  # unique constraint on asset_tag
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="asset_tag already registered"
        ) from exc
    return models.DeviceOut(**dict(row))


@app.get("/devices", response_model=list[models.DeviceOut], tags=["devices"])
def list_devices(username: str = Depends(auth.get_current_username)):
    rows = database.list_devices(username)
    return [models.DeviceOut(**dict(r)) for r in rows]


@app.get("/devices/search", response_model=list[models.DeviceOut], tags=["devices"])
def search_devices(q: str, username: str = Depends(auth.get_current_username)):
    """
    Search devices by (partial) asset tag or device type.

    VULNERABILITY 3 — this delegates to database.search_devices(), which
    builds a raw SQL string via f-string interpolation instead of using a
    parameterized query. See docs/VULNERABILITIES.md.
    """
    flags = load_feature_flags()
    if not flags.get("allow_device_search", True):
        raise HTTPException(status_code=503, detail="Search temporarily disabled")

    rows = database.search_devices(q, username)
    return [models.DeviceOut(**dict(r)) for r in rows]


@app.get("/devices/{device_id}", response_model=models.DeviceOut, tags=["devices"])
def get_device(device_id: int, username: str = Depends(auth.get_current_username)):
    row = database.get_device(device_id, username)
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return models.DeviceOut(**dict(row))


@app.patch("/devices/{device_id}", response_model=models.DeviceOut, tags=["devices"])
def update_device(
    device_id: int,
    update: models.DeviceUpdate,
    username: str = Depends(auth.get_current_username),
):
    row = database.update_device(device_id, username, status=update.status)
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return models.DeviceOut(**dict(row))


@app.post(
    "/devices/{device_id}/heartbeat", response_model=models.DeviceOut, tags=["devices"]
)
def heartbeat(
    device_id: int,
    payload: models.HeartbeatIn,
    username: str = Depends(auth.get_current_username),
):
    """
    A device (or its OTA agent) checks in and reports the firmware version
    it is currently running. Updates `last_seen` so operators can spot
    devices that have gone silent (potentially offline, tampered with, or
    stuck on an old firmware that can no longer phone home).
    """
    row = database.record_heartbeat(device_id, username, payload.firmware_version)
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return models.DeviceOut(**dict(row))


@app.delete(
    "/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["devices"]
)
def delete_device(device_id: int, username: str = Depends(auth.get_current_username)):
    deleted = database.delete_device(device_id, username)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
