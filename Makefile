# Origin — Build & Development

.DEFAULT_GOAL := help

.PHONY: help build test check clean coverage docs release

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build release binary
	cargo build --release

test: ## Run all tests
	cargo test

check: ## Run all checks (fmt, clippy, build, test, docs, deny)
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo build --release
	cargo test
	cargo doc --no-deps --document-private-items

coverage: ## Generate code coverage report (requires cargo-llvm-cov)
	cargo llvm-cov --all-features --html

docs: ## Build documentation
	cargo doc --no-deps --document-private-items

clean: ## Clean build artifacts
	cargo clean

release: ## Publish to crates.io (requires CARGO_REGISTRY_TOKEN)
	cargo publish -p origin-core
	cargo publish -p origin-cli
