# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the slice-1 alfred-core container.
#
#  * builder  — resolves the uv lockfile into /app/.venv. Pulls in the
#    uv binary from the upstream Astral image so we don't carry an
#    apt-get install of pip/uv into the runtime layer.
#  * runtime  — non-root `alfred` user, /var/lib/alfred state dir owned by
#    that user, every runtime artefact (venv, alembic.ini, config/, locale/)
#    copied into /app. ENTRYPOINT is the installed `alfred` console script
#    so `docker compose run --rm alfred-core <cmd>` maps 1:1 to
#    `alfred <cmd>` — there is no shell or alternative surface.

FROM python:3.12-slim AS builder
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# --no-dev keeps pytest / mypy / pyright / hypothesis out of the runtime
# venv. textual and babel are runtime deps (verified in pyproject.toml)
# so they ride along with --no-dev.
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Non-root runtime user. /var/lib/alfred is owned by alfred:alfred so
# the orchestrator can persist state (per PRD §2.4 the agent writes
# state here; operators get read-only access on the host).
RUN groupadd --system alfred \
    && useradd --system --gid alfred --create-home --home-dir /home/alfred alfred \
    && mkdir -p /var/lib/alfred \
    && chown -R alfred:alfred /var/lib/alfred

WORKDIR /app
COPY --from=builder /app /app
# Every file the runtime touches has to land in this stage — the earlier
# draft of this Dockerfile shipped without alembic.ini / config / locale
# and the first `alembic upgrade head` inside the container failed.
COPY alembic.ini ./alembic.ini
COPY config ./config
COPY locale ./locale

RUN chown -R alfred:alfred /app
USER alfred

ENTRYPOINT ["alfred"]
