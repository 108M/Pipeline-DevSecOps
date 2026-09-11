"""
Application configuration.

VULNERABILITY 2 — Hardcoded / mismanaged secrets (intentional, for educational
purposes). See docs/VULNERABILITIES.md for the full write-up, the tool that
catches it (Gitleaks) and the exact fix.

In a real project these values MUST come from environment variables injected
at deploy time (GitHub Actions secrets, Docker secrets, a vault, ...) and
never be committed to version control. They are hardcoded here on purpose so
the secret-scanning job in the pipeline has something real to detect.
"""

import os
from pathlib import Path

# --- VULNERABLE: a realistic-looking, high-entropy secret hardcoded in source.
# This is exactly the pattern Gitleaks' "generic-api-key" rule is built to catch.
SECRET_KEY = "Tz8pQ2mXnJ5vLk9wRcYbE3hUiO7sAqDf"  # noqa: S105 -- intentional, see docs/VULNERABILITIES.md
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- VULNERABLE: insecure default credentials shipped in the codebase.
# Beyond being a hardcoded secret, this also violates the CRA "secure by
# default" expectation (Annex I, Part I, point 2(b)) because the product
# ships with a guessable, unchanged administrator credential.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!"  # noqa: S105 -- intentional, see docs/VULNERABILITIES.md

# --- Non-sensitive configuration (fine to keep as plain variables/env with defaults)
DB_PATH = os.getenv("FLEET_DB_PATH", "fleet.db")
# Default resolves relative to this package (app/settings.yaml) so it's found
# regardless of the working directory the app is started from; the Docker
# image and .env.example both set FLEET_SETTINGS_FILE explicitly anyway.
SETTINGS_FILE = os.getenv(
    "FLEET_SETTINGS_FILE", str(Path(__file__).parent / "settings.yaml")
)
