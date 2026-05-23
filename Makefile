.PHONY: help setup setup-hooks setup-env build test test-debug lint format \
       gazelle clean expunge info build-release push-containers preset-update query

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

##@ Setup

setup: setup-env setup-hooks ## Full dev environment setup

setup-env: ## Build bazel_env toolchain and allow direnv
	brew install bazelisk direnv
	bazel run //tools:bazel_env
	direnv allow

setup-hooks: ## Configure git pre-commit hooks
	git config core.hooksPath .githooks

##@ Build

build: ## Build all targets
	bazel build //...

build-release: ## Build all targets with stamping
	bazel build --config=release //...

##@ Test

test: ## Run all tests
	bazel test //...

test-debug: ## Run all tests in debug mode (streamed output, no cache)
	bazel test --config=debug //...

##@ Lint & Format

lint: ## Lint all targets (uses Aspect CLI - which is provisioned by multitool)
	aspect lint //...

format: ## Format all files
	format

##@ Code Generation

gazelle: ## Regenerate BUILD files (Starlark + Rust)
	bazel run gazelle
	bazel run gazelle_rust

##@ Containers

push-containers: ## Push all OCI container images (runs all oci_push targets)
	@targets=$$(bazel query 'kind(oci_push, //...)' 2>/dev/null); \
	if [ -z "$$targets" ]; then \
		echo "No oci_push targets found"; \
	else \
		echo "$$targets" | xargs -P4 -I{} bazel run {}; \
	fi

##@ Maintenance

preset-update: ## Update the generated preset.bazelrc
	bazel run //tools:preset.update

clean: ## Clean bazel build outputs
	bazel clean

expunge: ## Full clean including external caches
	bazel clean --expunge

info: ## Print bazel workspace info
	bazel info

query: ## Print all bazel targets within the module
	bazel query //...
