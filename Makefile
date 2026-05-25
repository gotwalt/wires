.PHONY: help setup setup-hooks setup-env build test test-debug check lint format \
	format-check gazelle lockfile clean expunge info build-release images \
	load-images push-containers preset-update query

# Default target
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next} \
		/^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

check: build test lint format-check ## Build, test, lint, and format-check (CI-style, non-mutating)

lint: ## Lint all targets (uses Aspect CLI - which is provisioned by multitool)
	aspect lint //...

format: ## Format all files in place
	format

format-check: ## Check formatting without modifying files (fails if unformatted)
	bazel run //tools/format:format.check

##@ Dependencies

lockfile: ## Refresh Cargo.lock via the Bazel-vendored cargo (the only cargo touchpoint)
	bazel run @rules_rust//tools/upstream_wrapper:cargo -- generate-lockfile

##@ Code Generation

gazelle: ## Regenerate BUILD files: Starlark, then refresh Cargo.lock, then Rust
	bazel run //:gazelle
	$(MAKE) lockfile
	bazel run //:gazelle_rust

##@ Containers

images: ## Build the distroless OCI images (//...:image)
	bazel build $$(bazel query 'attr(name, "^image$$", //...)')

load-images: ## Build and `docker load` every image locally
	@for t in $$(bazel query 'attr(name, "image.load", //...)'); do \
		echo "loading $$t"; bazel run "$$t"; \
	done

push-containers: ## Push all OCI images (runs every oci_push target; none defined yet)
	@targets=$$(bazel query 'kind(oci_push, //...)' 2>/dev/null); \
	if [ -z "$$targets" ]; then \
		echo "No oci_push targets found (see //tools/oci/rust_image.bzl)"; \
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
