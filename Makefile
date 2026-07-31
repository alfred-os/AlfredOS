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
# Python-tool targets probe for their directories first. `test-perf` is FAIL-CLOSED
# (#514) — tests/perf is permanent, so finding nothing means the probe broke and it
# exits 1, matching the CI srccheck guards which are now fail-closed too. Other
# targets still emit a `::notice::` and no-op; those are convenience wrappers, not
# merge gates. Never probe with `find … | grep -q` (SIGPIPE under pipefail — #514).

.PHONY: help setup autosquash \
        fix format-fix lint-fix \
        check format-check lint-check typecheck strict-declarations-lint tag-t3-check test test-unit test-integration test-smoke test-e2e test-adversarial test-perf \
        i18n-check i18n-fix coverage-unit coverage-gates-unit coverage-gates \
        docs-check wiki-check

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
		uv run mypy --strict src scripts/check_tag_t3.py && uv run pyright src scripts/check_tag_t3.py; \
	else \
		echo "::notice::no src/ yet — skipping typecheck"; \
	fi

test-unit: ## Run unit tests only (fast; no Docker).
	@if [ -d tests/unit ]; then \
		uv run pytest tests/unit -q; \
	else \
		echo "::notice::no tests/unit/ yet — skipping test-unit"; \
	fi

# -m "not real_llm" deselects the nightly-only real-LLM smoke
# (test_act_loop_real_llm_smoke.py) from this local/CI broad run to avoid
# unintended provider spend; the nightly real-llm-smoke job runs it
# explicitly via -m real_llm. Same deselect below on test-smoke.
test-integration: ## Run integration tests only (needs Docker for testcontainers).
	@if [ -d tests/integration ]; then \
		uv run pytest tests/integration -q -m "not real_llm"; \
	else \
		echo "::notice::no tests/integration/ yet — skipping test-integration"; \
	fi

test: test-unit test-integration ## Run unit + integration (matches what CI runs).

# ──────────────────────────────────────────────────────────────
# i18n catalog drift (#474)
# ──────────────────────────────────────────────────────────────
# CLAUDE.md's i18n hard rule #4 makes catalog drift a release blocker, and
# pr-validate-python.yml is its ONLY enforcement — `make check` never ran it.
# The trap it catches is not a changed message: editing ANY file containing a
# `t()` call moves the catalog's `#:` source references, so the catalog goes
# stale without a single string changing. That is exactly how PR #529 tripped it.
# Commands mirror pr-validate-python.yml verbatim, including
# `--ignore-pot-creation-date` (without it the timestamp alone reports drift).
i18n-check: ## Verify the i18n catalog is not stale (CLAUDE.md i18n hard rule #4).
	uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
	@if ! uv run pybabel update --check -i /tmp/alfred.pot -d locale -D alfred \
			--no-fuzzy-matching --ignore-pot-creation-date; then \
		echo "::error::i18n catalog drift. Run: make i18n-fix && commit the diff."; \
		exit 1; \
	fi

i18n-fix: ## Regenerate the i18n catalog after touching any file with a t() call (mutates).
	uv run pybabel extract -F babel.cfg -o /tmp/alfred.pot src/alfred plugins
	uv run pybabel update -i /tmp/alfred.pot -d locale -D alfred --no-fuzzy-matching
	uv run pybabel compile -d locale -D alfred --statistics

# ──────────────────────────────────────────────────────────────
# Per-module 100% coverage gates (#474)
# ──────────────────────────────────────────────────────────────
# `make check` claimed "identical to CI" while running NONE of CI's 50
# per-module `--fail-under=100` gates. That is the rule CLAUDE.md calls hard —
# every security boundary at 100% line+branch — and locally none of it was
# enforced. PR #529 passed `make check` and then failed CI's "Gateway kernel
# trust-boundary 100%" gate on one partial branch; that is the gap, observed.
#
# The gate list is DERIVED from .github/workflows/ci.yml by
# scripts/run_coverage_gates.py — never restated here. A hand-copied list is a
# second source of truth that drifts silently (#422); deriving it means a gate
# added to CI is enforced locally the same day.
#
# Two datasets, because CI has two gate-bearing jobs and they are NOT
# interchangeable: the `python` job's 28 gates read unit-only coverage, and the
# `coverage-gates` job's 22 read combined unit+integration. Running a combined
# gate against unit-only data reports false failures, so each target builds the
# dataset its gates expect.

coverage-unit: ## Build the unit-only coverage dataset CI's `python` job gates read.
	uv run pytest tests/unit -q --cov=src/alfred --cov=scripts --cov-report= --cov-fail-under=0

coverage-gates-unit: coverage-unit ## Run the 28 unit-tier 100% gates from ci.yml.
	uv run python3 scripts/run_coverage_gates.py --job python --min-gates 28

# ORDER IS LOAD-BEARING: the unit gates must read unit-ONLY data. Combined data
# is a superset, so running them after the integration append would let a module
# covered solely by integration tests pass locally and fail CI's `python` job —
# a false negative in exactly the direction that wastes a CI round-trip. So:
# unit data -> unit gates -> append integration -> combined gates, in one pass
# (no re-running the unit tier twice).
coverage-gates: coverage-gates-unit ## Run every per-module 100% gate CI runs (needs Docker).
	uv run pytest tests/integration -q -m "not real_llm" \
		--cov=src/alfred --cov-append --cov-report= --cov-fail-under=0
	uv run python3 scripts/run_coverage_gates.py --job coverage-gates --min-gates 22

test-smoke: ## Run smoke tests against a running stack (requires `docker compose up`).
	@if [ -d tests/smoke ]; then \
		uv run pytest tests/smoke -q -m "not real_llm"; \
	else \
		echo "::notice::no tests/smoke/ yet — skipping test-smoke"; \
	fi

test-e2e: ## Run the #494 e2e first-run boot lane (nightly-only; needs Docker + builds the core image).
	@if [ -f tests/e2e/conftest.py ]; then \
		uv run pytest tests/e2e -o addopts='' && uv run python -m tests.e2e._assert_ran e2e-tally.json; \
	else \
		echo "::notice::no tests/e2e/ yet — skipping test-e2e"; \
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
	@if [ -n "$$(find tests/perf -name 'test_*.py' -print -quit 2>/dev/null)" ]; then \
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
		echo "::error::tests/perf/test_*.py probe found nothing — release-blocking perf gate cannot run"; \
		exit 1; \
	fi

strict-declarations-lint: ## #119 SEC-Med-1: `strict_declarations=False` MUST NOT appear in src/.
	python3 scripts/check_strict_declarations.py

# #541: the scan roots live in the script (`_DEFAULT_SCAN_ROOTS`), NOT here.
# Passing them on the command line meant dropping one was a one-word edit that
# no gate could see — and it silently stopped gating 39 first-party plugin
# files. There is no argument left to drop.
tag-t3-check: ## Slice-3 spec §3.7-3.8: reject unauthorised tag(T3 + cast(TaggedContent[ uses.
	@if [ -d src/alfred ]; then \
		python3 scripts/check_tag_t3.py; \
	else \
		echo "::error::no src/alfred/ — the gate cannot run"; \
		exit 1; \
	fi

# `check` runs the gates CI runs that are reproducible on a dev box. It is NOT
# the whole of CI: the arm64/WSL/Windows legs, the privileged bwrap legs, the
# adversarial suite and CodeQL live only in CI. It previously claimed to be
# "identical to CI" while running NONE of the 50 per-module 100% coverage
# gates (#474) — an overclaim that cost a CI round-trip on PR #529.
check: format-check lint-check typecheck strict-declarations-lint tag-t3-check i18n-check coverage-gates ## Verify what CI verifies locally (see comment). No mutations.

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

wiki-check: ## Validate .devin/wiki.json (schema, limits, anchor resolution, secret shapes).
	python3 scripts/validate_devin_wiki.py .devin/wiki.json --repo-root "$(CURDIR)"

# ──────────────────────────────────────────────────────────────
# Git helpers
# ──────────────────────────────────────────────────────────────
autosquash: ## Squash fixup!/squash!/amend! commits into their targets (tree-preserving).
	scripts/autosquash.sh
