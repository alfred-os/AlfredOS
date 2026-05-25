# AlfredOS Makefile — thin wrappers around developer tools.
# See docs/python-conventions.md for the toolchain rationale.
#
# Two main entry points:
#   make fix    — auto-format + auto-fix lint (MUTATES the tree)
#   make check  — verify (matches CI; no mutations)
#
# `make check` is the contract. If it passes locally, it should pass in CI.
# If it fails with mutation-recoverable issues, run `make fix` first.
#
# Pre-Slice-1 state: src/ and tests/ don't exist yet. Each Python-tool target
# below probes for the relevant directories and no-ops with a `::notice::` line
# if absent, matching the CI workflow's srccheck guards and lefthook's path
# probes. Once Slice 1 lands the directories, the guards transparently activate.

.PHONY: help setup autosquash \
        fix format-fix lint-fix \
        check format-check lint-check typecheck test test-unit test-integration test-smoke test-adversarial

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ──────────────────────────────────────────────────────────────
# One-time setup
# ──────────────────────────────────────────────────────────────
setup: ## One-time: uv sync --dev + lefthook install (idempotent; lefthook is optional).
	uv sync --dev
	@if command -v lefthook >/dev/null 2>&1; then \
		lefthook install; \
	else \
		echo "lefthook not found on PATH — pre-push gates will be CI-only."; \
		echo "Install: brew install lefthook  (or: npm i -g @evilmartians/lefthook)"; \
		echo "Then re-run: make setup"; \
	fi

# ──────────────────────────────────────────────────────────────
# Mutating targets — auto-fix everything that can be auto-fixed
# ──────────────────────────────────────────────────────────────
lint-fix: ## Auto-fix lint issues with ruff check --fix (mutates).
	@if [ -d src ] || [ -d tests ]; then \
		targets=""; [ -d src ] && targets="$$targets src"; [ -d tests ] && targets="$$targets tests"; \
		uv run ruff check $$targets --fix; \
	else \
		echo "::notice::no src/ or tests/ yet — skipping lint-fix"; \
	fi

format-fix: ## Auto-format with ruff format (mutates).
	@if [ -d src ] || [ -d tests ]; then \
		targets=""; [ -d src ] && targets="$$targets src"; [ -d tests ] && targets="$$targets tests"; \
		uv run ruff format $$targets; \
	else \
		echo "::notice::no src/ or tests/ yet — skipping format-fix"; \
	fi

# Order matters: `ruff check --fix` first (its rewrites can affect formatting),
# then `ruff format`. See https://docs.astral.sh/ruff/formatter/
fix: lint-fix format-fix ## Run all auto-fixers in the recommended order.

# ──────────────────────────────────────────────────────────────
# Verifying targets — match CI exactly; no mutations
# ──────────────────────────────────────────────────────────────
lint-check: ## Verify lint (ruff check, no --fix).
	@if [ -d src ] || [ -d tests ]; then \
		targets=""; [ -d src ] && targets="$$targets src"; [ -d tests ] && targets="$$targets tests"; \
		uv run ruff check $$targets; \
	else \
		echo "::notice::no src/ or tests/ yet — skipping lint-check"; \
	fi

format-check: ## Verify formatting (ruff format --check, no mutation).
	@if [ -d src ] || [ -d tests ]; then \
		targets=""; [ -d src ] && targets="$$targets src"; [ -d tests ] && targets="$$targets tests"; \
		uv run ruff format --check $$targets; \
	else \
		echo "::notice::no src/ or tests/ yet — skipping format-check"; \
	fi

typecheck: ## Run both type-checkers (mypy --strict + pyright).
	@if [ -d src ]; then \
		uv run mypy --strict src && uv run pyright src; \
	else \
		echo "::notice::no src/ yet — skipping typecheck"; \
	fi

test-unit: ## Run unit tests only (fast; no Docker).
	@if [ -d tests/unit ]; then \
		uv run pytest tests/unit -q; \
	else \
		echo "::notice::no tests/unit/ yet — skipping test-unit"; \
	fi

test-integration: ## Run integration tests only (needs Docker for testcontainers).
	@if [ -d tests/integration ]; then \
		uv run pytest tests/integration -q; \
	else \
		echo "::notice::no tests/integration/ yet — skipping test-integration"; \
	fi

test: test-unit test-integration ## Run unit + integration (matches what CI runs).

test-smoke: ## Run smoke tests against a running stack (requires `docker compose up`).
	@if [ -d tests/smoke ]; then \
		uv run pytest tests/smoke -q; \
	else \
		echo "::notice::no tests/smoke/ yet — skipping test-smoke"; \
	fi

test-adversarial: ## Run the adversarial security suite (nightly + release-blocking).
	@if [ -d tests/adversarial ]; then \
		uv run pytest tests/adversarial -q; \
	else \
		echo "::notice::no tests/adversarial/ yet — skipping test-adversarial"; \
	fi

check: format-check lint-check typecheck test ## Verify everything (identical to CI). No mutations.

# ──────────────────────────────────────────────────────────────
# Git helpers
# ──────────────────────────────────────────────────────────────
autosquash: ## Squash fixup!/squash!/amend! commits into their targets (tree-preserving).
	scripts/autosquash.sh
