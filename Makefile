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
        check format-check lint-check typecheck test test-unit test-integration test-smoke test-adversarial test-perf \
        docs-check

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

# Mirrors `test-adversarial`'s shape: its own gate, NOT part of `check`'s
# prerequisites. Benches are slow (~0.5–2s/bench) and hardware-sensitive
# (CI vs laptop p99 deltas differ), so the perf suite runs as its own
# release-blocking gate in CI (.github/workflows/perf.yml), not on every
# `make check`. Two pytest invocations because `--benchmark-only`
# deselects `test_refusal_short_circuits_subscribers` (a correctness pin
# paired with the 5-chain bench; no benchmark fixture by design).
test-perf: ## Run the release-blocking hook-dispatch perf gate (host-load-sensitive).
	@if [ -d tests/perf ] && find tests/perf -name 'test_*.py' 2>/dev/null | grep -q .; then \
		FORCE=0; \
		case "$$(printf '%s' "$$ALFRED_TEST_PERF_FORCE" | tr '[:upper:]' '[:lower:]')" in 1|true|yes) FORCE=1 ;; esac; \
		if [ "$$FORCE" = "0" ]; then \
			LOAD_INFO=$$(python3 -c 'import os; l = os.getloadavg()[0]; c = os.cpu_count() or 4; print(f"{l} {c} {l/c:.2f}")' 2>&1); \
			if [ $$? -ne 0 ]; then \
				echo "::error::could not read os.getloadavg() — refusing to silently run benches. Set ALFRED_TEST_PERF_FORCE=1 to override."; \
				exit 75; \
			fi; \
			LOAD=$$(echo "$$LOAD_INFO" | awk '{print $$1}'); \
			CPUS=$$(echo "$$LOAD_INFO" | awk '{print $$2}'); \
			RATIO=$$(echo "$$LOAD_INFO" | awk '{print $$3}'); \
			BUSY=$$(awk -v r="$$RATIO" 'BEGIN {print (r >= 1.0) ? "refuse" : (r >= 0.7) ? "warn" : "ok"}'); \
			if [ "$$BUSY" = "refuse" ]; then \
				echo "::warning::host load $$LOAD on $$CPUS CPUs (ratio $$RATIO) — benches will be unreliable."; \
				echo "::warning::Refusing to run with load >= 1.0x CPU count. Wait for the box to quiesce, or set ALFRED_TEST_PERF_FORCE=1 (CI sets this)."; \
				echo "::warning::This is NOT a pass — exit 75 (EX_TEMPFAIL) so release scripts catch it."; \
				exit 75; \
			fi; \
			if [ "$$BUSY" = "warn" ]; then \
				echo "::warning::host load $$LOAD on $$CPUS CPUs (ratio $$RATIO) — benches MAY be noisy. Proceeding anyway."; \
			fi; \
		fi; \
		uv run pytest tests/perf -v --benchmark-only --benchmark-json=benchmark.json && \
		uv run pytest tests/perf -v -k refusal_short_circuits_subscribers ; \
	else \
		echo "::notice::no tests/perf/test_*.py — skipping test-perf"; \
	fi

check: format-check lint-check typecheck test ## Verify everything (identical to CI). No mutations.

# ──────────────────────────────────────────────────────────────
# Docs link + anchor checker (PR E, plan task 8)
# ──────────────────────────────────────────────────────────────
# scripts/docs_check.py is stdlib-only — no `uv run` needed, so the target
# works on a fresh clone before dev deps are synced. Anchor-aware: every
# `[text](path#anchor)` resolves the `#anchor` against the target file's
# heading set (GitHub-compatible slug algorithm). The glossary anchors
# `#authorization-role` + `#canonical-user-id` are load-bearing surfaces;
# this gate catches forward-reference drift before merge.
#
# `docs/superpowers/plans/` is excluded because those are working/draft
# documents whose forward-refs (to specs that haven't been written yet)
# legitimately fail until later PRs land. The trivy IaC scan applies the
# same exclude (see .github/workflows/pr-validate-security.yml).
docs-check: ## Verify markdown link + anchor integrity across docs/, top-level *.md.
	python3 scripts/docs_check.py docs/ PRD.md README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md \
		--exclude docs/superpowers/plans

# ──────────────────────────────────────────────────────────────
# Git helpers
# ──────────────────────────────────────────────────────────────
autosquash: ## Squash fixup!/squash!/amend! commits into their targets (tree-preserving).
	scripts/autosquash.sh
