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

FROM python:3.14-slim-bookworm AS builder
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# The wheel build force-includes ``locale/`` at ``alfred/_locale`` (pyproject.toml
# ``[tool.hatch.build.targets.wheel.force-include]``, BUG-2 PR-S4-11c-2b0) so a
# pip-installed alfred carries its catalogs. ``uv sync`` builds alfred here, so the
# source ``locale/`` MUST exist in the builder stage or hatchling refuses with
# "Forced include not found: /app/locale". The runtime stage still copies
# ``locale/`` separately for the ``/app/locale`` container-layout finder candidate.
COPY locale ./locale

# --no-dev keeps pytest / mypy / pyright / hypothesis out of the runtime
# venv. textual and babel are runtime deps (verified in pyproject.toml)
# so they ride along with --no-dev.
RUN uv sync --frozen --no-dev

FROM python:3.14-slim-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Install git + util-linux.
# git: required for state.git operations (spec §8.1, §11.1).
# util-linux: provides `runuser` — required by alfred-plugin-launcher for
# UID-drop to alfred-quarantine at subprocess spawn (spec §5.2, sec-003).
# Without runuser the launcher cannot drop privileges and the isolation
# guarantee collapses.
# bubblewrap: provides `bwrap` — Slice-4 PR-S4-6's bash launcher invokes
# bwrap directly with per-plugin policy files (spec §7.5 Linux policy /
# ADR-0015). Debian Bookworm ships bubblewrap 0.8.x which provides the
# `--bind-fd` / `--ro-bind-fd` / `--sync-fd` family the PR-S4-6 launcher
# uses for fd-3 provider-key inheritance into the sandbox. Without bwrap
# Linux production refuses to launch the quarantined-LLM with
# `policy_ref_unreadable` because no binary can apply the policy.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends git util-linux bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. /var/lib/alfred is owned by alfred:alfred so
# the orchestrator can persist state (per PRD §2.4 the agent writes
# state here; operators get read-only access on the host).
#
# alfred-quarantine is the dedicated UID for quarantined-LLM subprocess
# isolation (spec §5.2). It has no home dir and cannot read alfred's
# secrets file (OS-level enforcement of the secrets boundary).
# devops-008: `--user-group` creates a dedicated GID for alfred-quarantine
# (separate from any default group) so the OS-level secret-file ownership
# boundary is enforceable: alfred's secret files owned alfred:alfred are
# not readable by the alfred-quarantine GID.
RUN groupadd --system alfred \
    && useradd --system --gid alfred --create-home --home-dir /home/alfred alfred \
    && useradd --system --no-create-home --user-group alfred-quarantine \
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
# bin/ contains alfred-plugin-launcher (stub shipped in PR-S3-3a) plus the
# alfred-state-git-seed.sh script invoked by bin/alfred-setup.sh. Copied
# into the image so the seed script is reachable from
# `docker compose run --rm --entrypoint /bin/sh alfred-core ...`.
COPY bin ./bin

RUN chown -R alfred:alfred /app
USER alfred

ENTRYPOINT ["alfred"]
