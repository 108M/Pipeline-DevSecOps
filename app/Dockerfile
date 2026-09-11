# syntax=docker/dockerfile:1
#
# Multi-stage build for the Fleet Compliance API.
#
# Deliberately follows container hardening good practice (slim base image,
# non-root user, no build tools in the final image, pinned dependency
# versions) so that the Trivy IMAGE scan job in the pipeline mostly surfaces
# the one intentional vulnerable dependency (PyYAML, see
# docs/VULNERABILITIES.md) rather than avoidable Dockerfile mistakes.

# ---- build stage ------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# PyYAML==5.3.1 (intentionally outdated, see docs/VULNERABILITIES.md) predates
# Python 3.12 and ships no prebuilt wheel for it, so pip must compile it from
# source here. build-essential stays confined to this discarded build stage —
# the runtime stage below never sees a compiler.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# pip and setuptools (bundled together in the base image) tend to lag
# behind their own published CVEs (caught by the Trivy image scan, same as
# any other package) — upgrade both before installing anything else.
RUN pip install --no-cache-dir --upgrade pip setuptools

COPY app/requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---- runtime stage ------------------------------------------------------
FROM python:3.12-slim AS runtime

# This image never installs anything at runtime — every package it needs is
# copied over, pre-built, from the builder stage below. pip/setuptools/wheel
# have no job to do here at all, so remove them outright instead of trying
# to keep them patched. (This replaced an earlier attempt that just upgraded
# them: Trivy kept reporting an old msgpack/setuptools version no upgrade
# ever changed — almost certainly pip's own internally-bundled copies, not
# anything from requirements.txt. Removing pip removes that whole category
# of findings instead of chasing it version by version.) Order matters:
# uninstall pip's dependents first, pip itself last, in the same command
# `pip` is still around to run it — this is the standard safe pattern for
# self-uninstalling pip from a container.
RUN python -m pip uninstall --yes wheel setuptools \
    && python -m pip uninstall --yes pip

# Create an unprivileged user to run the application as (never run as root).
RUN addgroup --system app && adduser --system --ingroup app --home /home/app app

WORKDIR /app

# Bring in the packages installed in the build stage only (no compilers,
# no pip cache, smaller attack surface).
COPY --from=builder /root/.local /home/app/.local

COPY app/ /app/app/

ENV PATH="/home/app/.local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLEET_DB_PATH=/home/app/data/fleet.db \
    FLEET_SETTINGS_FILE=/app/app/settings.yaml

RUN mkdir -p /home/app/data && chown -R app:app /home/app

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
