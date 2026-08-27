# Thin wrappers. Every knob has a default; override on the command line.
# `make check` is what CI runs, and it runs offline: jq and a shell, no
# Keycloak, no database, no container, no network.

SHELL := /bin/bash
.DEFAULT_GOAL := help

REPO_ROOT ?= $(CURDIR)

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-22s %s\n", $$1, $$2}'

.PHONY: check
check: secrets-selftest secrets policy ## Everything CI runs, offline

.PHONY: policy
policy: ## Offline policy gate + sensitivity proof
	./bin/check-policy.sh

.PHONY: sensitivity
sensitivity: ## The sensitivity proof alone
	./tests/run-policy-tests.sh

.PHONY: secrets
secrets: ## Refuse a tree containing a secret value
	./bin/check-no-secrets.sh

.PHONY: secrets-selftest
secrets-selftest: ## Prove the secret scanner rejects before trusting it
	./bin/check-no-secrets.sh --self-test

.PHONY: lint
lint: ## Static checks on the scripts (NOT test evidence)
	shellcheck -S warning bin/*.sh tests/*.sh

.PHONY: verify
verify: ## LIVE verifier. Runs on the IdP host only; needs a real realm.
	./bin/verify.sh

.PHONY: deploy
deploy: ## Deploy an exact commit: make deploy COMMIT=<40-char sha>
	@test -n "$(COMMIT)" || { echo "usage: make deploy COMMIT=<40-char sha>"; exit 2; }
	./bin/deploy.sh $(COMMIT)
