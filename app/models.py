"""Pydantic request/response schemas for the Fleet Compliance API."""

from typing import Literal, Optional

from pydantic import BaseModel, Field

DeviceStatus = Literal["active", "quarantined", "decommissioned"]


class DeviceCreate(BaseModel):
    asset_tag: str = Field(..., min_length=1, max_length=100)
    device_type: str = Field(..., min_length=1, max_length=100, description="e.g. iot-sensor, pos-terminal, industrial-plc")
    firmware_version: str = Field(..., min_length=1, max_length=50)


class DeviceUpdate(BaseModel):
    status: DeviceStatus


class HeartbeatIn(BaseModel):
    firmware_version: str = Field(..., min_length=1, max_length=50)


class DeviceOut(BaseModel):
    id: int
    asset_tag: str
    device_type: str
    firmware_version: str
    status: str
    last_seen: Optional[str] = None
    owner: str

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
