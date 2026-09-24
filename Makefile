# Dev loop over plain Cargo. `make help` lists the targets.
SH := $(shell git ls-files '*.sh' .githooks/pre-commit)

.PHONY: help build test lint fmt fmt-check demo python demo-python image hooks

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
build: ## Build the workspace (debug)
	cargo build --workspace
test: ## Run every test, doctests included
	cargo test --workspace
lint: ## clippy (warnings are errors) + shellcheck
	cargo clippy --workspace --all-targets -- -D warnings
	shellcheck $(SH)
fmt: ## Format Rust and shell in place
	cargo fmt --all
	shfmt -w $(SH)
fmt-check: ## Fail if anything is unformatted
	cargo fmt --all --check
	shfmt -d $(SH)
demo: ## Run the self-asserting loopback demo
	.scripts/demo-remote-cli.sh --quiet
python: ## Build the Python bindings into target/python (card 33)
	.scripts/build-python.sh
demo-python: ## Serve a Python-native service on a loopback fabric and call it
	.scripts/demo-python-service.sh
image: ## Build the distroless image natively (wires:dev)
	docker build -t wires:dev .
hooks: ## Use the repo's git hooks (cargo fmt --check on commit)
	git config core.hooksPath .githooks
