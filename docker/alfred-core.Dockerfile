# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the alfred-core container.
#
#  * builder  — fetches a self-contained python-build-standalone (PBS) 3.14
#    interpreter via proto and installs `alfred` (+ runtime deps) NON-editable
#    INTO it, so interpreter + stdlib + site-packages share ONE relocatable,
#    RUNPATH-linked prefix (`/opt/alfred-python`).
#  * runtime  — non-root `alfred` user, /var/lib/alfred state dir owned by
#    that user, the PBS prefix copied verbatim. ENTRYPOINT is the installed
#    `alfred` console script so `docker compose run --rm alfred-core <cmd>`
#    maps 1:1 to `alfred <cmd>` — there is no shell or alternative surface.
#
# WHY a PBS interpreter as the PRIMARY interpreter (#290, Option B):
#
# The dual-LLM quarantine child runs under bwrap with the `kind="full"` policy,
# which binds ONLY `/usr`, `/lib`, `/lib64` read-only (no `/etc`, no repo bind).
# A stock python.org/slim CPython resolves `libpython3.14.so.1.0` via
# `/etc/ld.so.cache`, which the policy omits — so the child dies with
# "libpython3.14.so.1.0: cannot open shared object file" AFTER the namespace is
# built. A PBS interpreter is RUNPATH-linked (finds its libpython relative to the
# binary, no ld.so.cache), and lives under a single prefix the launcher binds
# into the sandbox via the opt-in `ALFRED_SANDBOX_BIND_INTERP_PREFIX` flag
# (ADR-0030). Installing `alfred` NON-editable into that same prefix means the
# child resolves BOTH the interpreter AND `alfred.security.quarantine_child` from
# one bound, cache-independent prefix — the layer-3 fix #290 needs. The exact
# recipe is the one the `integration-privileged` CI job (ADR-0030 / #248) proves
# end-to-end; here it becomes the SHIPPED image's main install.

FROM debian:bookworm-slim AS builder
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PROTO_HOME=/opt/proto \
    ALFRED_PYTHON_PREFIX=/opt/alfred-python

COPY --from=ghcr.io/astral-sh/uv:0.5.4 /uv /usr/local/bin/uv

# curl/ca-certificates: fetch the proto installer + the PBS tarball.
# xz-utils: proto's python-build-standalone tarball is `.tar.xz`; the slim base
# lacks xz so tar can't extract it ("xz: Cannot exec").
# git: `uv pip install .` may resolve VCS metadata; cheap to have in the builder.
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends curl ca-certificates xz-utils git \
    && rm -rf /var/lib/apt/lists/*

# Fetch a hermetic, self-contained PBS python 3.14 via proto (NOT `uv python
# install`: the pinned uv 0.5.4 predates 3.14 PBS availability — "No download
# found for cpython-3.14-linux-x86_64-gnu"). proto installs under
# ${PROTO_HOME}/tools/python/<ver>; the PBS layout is bin/python3. We RELOCATE
# the resolved version dir to a STABLE, version-independent prefix
# (${ALFRED_PYTHON_PREFIX}) so the runtime stage, the entrypoint, the launcher
# prefix-bind, and ALFRED_QUARANTINE_CHILD_PYTHON all reference one fixed path —
# a PBS interpreter is RUNPATH-relative and relocates cleanly.
# Pin the PBS patch version (not bare `3.14`) so the shipped interpreter is
# reproducible across rebuilds — bare `3.14` would float to whatever PBS patch
# release is latest at build time (tracked as the #254 pin-proto-install
# follow-up). Bump deliberately. The relocation glob stays patch-tolerant so a
# pin bump needs only this one line.
ARG ALFRED_PYTHON_VERSION=3.14.6
# DL4006 / CodeRabbit (#290): pipefail so a mid-stream `curl` failure fails the build
# rather than letting `bash` exit 0 on a truncated proto installer.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://moonrepo.dev/install/proto.sh | bash -s -- --yes \
    && "${PROTO_HOME}/bin/proto" install python "${ALFRED_PYTHON_VERSION}" \
    && PROTO_PY_DIR="$(ls -d "${PROTO_HOME}"/tools/python/3.14.* | sort -V | tail -1)" \
    && test -x "${PROTO_PY_DIR}/bin/python3" \
    && cp -a "${PROTO_PY_DIR}" "${ALFRED_PYTHON_PREFIX}" \
    && "${ALFRED_PYTHON_PREFIX}/bin/python3" -V \
    && rm -rf "${PROTO_HOME}"

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
# The wheel build force-includes `locale/` at `alfred/_locale` (pyproject.toml
# `[tool.hatch.build.targets.wheel.force-include]`, BUG-2 PR-S4-11c-2b0) so a
# pip-installed alfred carries its catalogs. `uv pip install .` builds the alfred
# wheel here, so the source `locale/` MUST exist in the builder stage or
# hatchling refuses with "Forced include not found: /app/locale".
COPY locale ./locale

# Install `alfred` (+ runtime deps) NON-EDITABLE into the PBS prefix. NON-editable
# (a real wheel build + copy into site-packages, NOT `-e`) is load-bearing for
# #290: an editable install leaves the code at /app/src behind a `.pth`, which
# bwrap does NOT bind — the quarantine child cannot import alfred from there.
# A non-editable install lands the package INSIDE the bound prefix's
# site-packages, reachable under the launcher's prefix-bind. We resolve deps from
# the frozen lockfile for reproducibility (`uv pip sync` the locked set), then
# install the project itself without deps on top.
# BuildKit cache mount for uv's download/wheel cache so repeated builds reuse
# resolved wheels (the lockfile guarantees the RESOLVED set is reproducible, so
# a warm cache cannot change what is installed — only how fast). Dropped the
# prior `--no-cache`: it forced a cold re-download every build for no
# reproducibility gain (uv.lock is the reproducibility source of truth).
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --python "${ALFRED_PYTHON_PREFIX}/bin/python3" . \
    && "${ALFRED_PYTHON_PREFIX}/bin/python3" -c \
       "import alfred.security.quarantine_child as m; print('child resolves alfred at', m.__file__)" \
    && test -x "${ALFRED_PYTHON_PREFIX}/bin/alfred"

FROM debian:bookworm-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    HOME=/home/alfred \
    ALFRED_PYTHON_PREFIX=/opt/alfred-python \
    PATH="/opt/alfred-python/bin:${PATH}" \
    # ADR-0030 bound-interpreter contract: the bwrap quarantine child execs THIS
    # PBS interpreter (RUNPATH-linked → needs no ld.so.cache) and imports `alfred`
    # from its co-located site-packages. `_child_env` sets
    # ALFRED_SANDBOX_BIND_INTERP_PREFIX=1 so the launcher ro-binds this prefix into
    # the sandbox. (`sys.executable` is now this same interpreter, so the production
    # default would also resolve here — we set the override explicitly for clarity
    # and so a non-PBS daemon interpreter can never silently leak in.)
    ALFRED_QUARANTINE_CHILD_PYTHON=/opt/alfred-python/bin/python3

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
# jq: the bash launcher (bin/alfred-plugin-launcher.sh) reads the plugin
# manifest's [sandbox] kind + policy_refs via jq to translate them into bwrap
# flags. Without it the launcher refuses EVERY kind=full spawn with
# `jq_unavailable` — so the dual-LLM quarantine child cannot start in the
# production container at all (#290). The launcher's own comment already assumes
# "alfred-core apt-installs jq"; this line makes that true.
# ca-certificates: the PBS interpreter makes TLS provider calls (OpenAI/Anthropic)
# and needs the system trust store (the slim base ships none).
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends git util-linux bubblewrap jq ca-certificates \
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
    && chown -R alfred:alfred /var/lib/alfred \
    && mkdir -p /home/alfred/.run \
    && chown alfred:alfred /home/alfred/.run \
    && chmod 0700 /home/alfred/.run

# The self-contained PBS interpreter + the non-editable `alfred` install. Copied
# verbatim from the builder — it is fully relocatable (RUNPATH-relative). World-
# readable + executable so the bwrap quarantine child (which may run under a
# dropped UID) can read+exec the interpreter the launcher binds RO into the
# sandbox, and so `import alfred` resolves for any UID in the namespace.
COPY --from=builder /opt/alfred-python /opt/alfred-python
RUN chmod -R a+rX /opt/alfred-python

# `python3` (no prefix) must resolve to the PBS interpreter: the launcher runs
# `python3 -m alfred.plugins.manifest_reader` to read the manifest / translate
# the sandbox policy, and that interpreter MUST carry `alfred`. Pointing
# /usr/local/bin/python3 at the PBS python guarantees the launcher uses the SAME
# alfred-bearing interpreter the child execs (no alfred-less system python in the
# mix). PATH already prepends the prefix bin for interactive use; this covers
# absolute `python3` lookups via /usr/local/bin.
RUN ln -sf /opt/alfred-python/bin/python3 /usr/local/bin/python3

WORKDIR /app
# Runtime artefacts the package does not carry but the container touches at
# runtime. The wheel install put alfred's CODE + locale catalogs into the PBS
# site-packages, but alembic.ini / config / bin / the source locale tree are
# repo-root files the running container reads from /app.
COPY alembic.ini ./alembic.ini
COPY config ./config
COPY locale ./locale
# bin/ contains alfred-plugin-launcher.sh (the bwrap launcher) plus the
# alfred-state-git-seed.sh script invoked by bin/alfred-setup.sh. Copied into the
# image so the launcher + seed script are reachable from the running container.
COPY bin ./bin

RUN chown -R alfred:alfred /app
USER alfred

ENTRYPOINT ["alfred"]
