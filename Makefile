# AlfredOS Makefile — thin wrappers around developer tools.

.PHONY: help autosquash

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

autosquash: ## Squash fixup!/squash!/amend! commits into their targets (tree-preserving).
	scripts/autosquash.sh
