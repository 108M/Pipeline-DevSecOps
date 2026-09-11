"""
Application configuration.

Fixed version of Vulnerability 2 (hardcoded/mismanaged secrets) — see
docs/VULNERABILITIES.md, "Vulnerability 2", for the original hardcoded
values, the CWE reference, and how Gitleaks caught them.

The JWT signing key now comes from the environment with no default (the app
fails fast at startup if it's unset, rather than silently signing tokens
with a value baked into source control). The admin password comes from the
environment too; if it's not provided, a random one-time password is
generated at startup instead of shipping a fixed, guessable default.
"""

import os
import secrets
from pathlib import Path

SECRET_KEY = os.environ["FLEET_SECRET_KEY"]  # no default: fail fast if unset
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ADMIN_USERNAME = os.getenv("FLEET_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("FLEET_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
if "FLEET_ADMIN_PASSWORD" not in os.environ:
    print(
        f"[startup] No FLEET_ADMIN_PASSWORD set — generated one-time password: {ADMIN_PASSWORD}"
    )

# --- Non-sensitive configuration (fine to keep as plain variables/env with defaults)
DB_PATH = os.getenv("FLEET_DB_PATH", "fleet.db")
# Default resolves relative to this package (app/settings.yaml) so it's found
# regardless of the working directory the app is started from; the Docker
# image and .env.example both set FLEET_SETTINGS_FILE explicitly anyway.
SETTINGS_FILE = os.getenv(
    "FLEET_SETTINGS_FILE", str(Path(__file__).parent / "settings.yaml")
)
