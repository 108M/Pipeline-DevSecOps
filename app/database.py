"""
Minimal persistence layer on top of sqlite3 for the Fleet Compliance API.

Most functions here use parameterized queries correctly. `search_devices()`
is the deliberate exception — see docs/VULNERABILITIES.md, "Vulnerability 3".
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from . import config
from .auth import hash_password


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and seed a demo operator account on first run."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_tag TEXT UNIQUE NOT NULL,
                device_type TEXT NOT NULL,
                firmware_version TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                last_seen TEXT,
                owner TEXT NOT NULL
            )
            """
        )
        conn.commit()

        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (config.ADMIN_USERNAME,)
        ).fetchone()
        if existing is None:
            # Demo seed account. Credential itself is VULNERABILITY 2 (see config.py).
            conn.execute(
                "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                (config.ADMIN_USERNAME, hash_password(config.ADMIN_PASSWORD)),
            )
            conn.commit()


def get_user(username: str) -> Optional[sqlite3.Row]:
    # Safe: parameterized query.
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def create_device(
    asset_tag: str, device_type: str, firmware_version: str, owner: str
) -> sqlite3.Row:
    # Safe: parameterized query.
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO devices (asset_tag, device_type, firmware_version, owner)
            VALUES (?, ?, ?, ?)
            """,
            (asset_tag, device_type, firmware_version, owner),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM devices WHERE id = ?", (cur.lastrowid,)
        ).fetchone()


def list_devices(owner: str) -> list[sqlite3.Row]:
    # Safe: parameterized query.
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM devices WHERE owner = ?", (owner,)
        ).fetchall()


def get_device(device_id: int, owner: str) -> Optional[sqlite3.Row]:
    # Safe: parameterized query.
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM devices WHERE id = ? AND owner = ?", (device_id, owner)
        ).fetchone()


def update_device(
    device_id: int, owner: str, status: Optional[str] = None
) -> Optional[sqlite3.Row]:
    # Safe: parameterized query.
    with get_connection() as conn:
        if status is not None:
            conn.execute(
                "UPDATE devices SET status = ? WHERE id = ? AND owner = ?",
                (status, device_id, owner),
            )
            conn.commit()
        return conn.execute(
            "SELECT * FROM devices WHERE id = ? AND owner = ?", (device_id, owner)
        ).fetchone()


def record_heartbeat(
    device_id: int, owner: str, firmware_version: str
) -> Optional[sqlite3.Row]:
    """
    Simulates an OTA (over-the-air) agent checking in from the field and
    reporting the firmware version it is currently running. This is the
    core "compliance" signal: comparing this value against the latest
    known-good / known-vulnerable firmware versions for the device type.
    """
    # Safe: parameterized query.
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE devices
            SET firmware_version = ?, last_seen = ?
            WHERE id = ? AND owner = ?
            """,
            (firmware_version, datetime.now(timezone.utc).isoformat(), device_id, owner),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM devices WHERE id = ? AND owner = ?", (device_id, owner)
        ).fetchone()


def delete_device(device_id: int, owner: str) -> bool:
    # Safe: parameterized query.
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM devices WHERE id = ? AND owner = ?", (device_id, owner)
        )
        conn.commit()
        return cur.rowcount > 0


def search_devices(query: str, owner: str) -> list[sqlite3.Row]:
    """
    Fixed version of Vulnerability 3 (SQL Injection) — see
    docs/VULNERABILITIES.md, "Vulnerability 3", for the original vulnerable
    code, the CWE/OWASP reference, and how Semgrep caught it.

    `query` is now passed as a bound parameter instead of being
    interpolated into the SQL string, so a payload like
    `nonexistent' OR '1'='1') -- ` is treated as a literal search string
    and matches nothing.
    """
    with get_connection() as conn:
        like_pattern = f"%{query}%"
        sql = (
            "SELECT * FROM devices WHERE owner = ? "
            "AND (asset_tag LIKE ? OR device_type LIKE ?)"
        )
        return conn.execute(sql, (owner, like_pattern, like_pattern)).fetchall()
