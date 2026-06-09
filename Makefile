# Origin — Build & Development

.DEFAULT_GOAL := help

.PHONY: help build test check clean coverage docs man fuzz bench sbom tag-release dist release

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

man: ## Install man page
	cp docs/origin.1 /usr/local/share/man/man1/
	mandb -q

fuzz: ## Run fuzz tests (requires nightly + cargo-fuzz)
	cargo fuzz run parse -- -max_len=1024 -runs=100000
	cargo fuzz run verify -- -max_len=2048 -runs=100000

bench: ## Run benchmarks (requires nightly)
	cargo bench

sbom: ## Generate SBOM (requires cargo-cyclonedx)
	cargo cyclonedx --all

tag-release: ## Create a signed release tag (usage: make tag-release VERSION=v1.1.1)
	git tag -s $(VERSION) -m "Origin $(VERSION)"
	git push origin $(VERSION)

dist: ## Build tarball of the release binary
	mkdir -p dist
	cp target/release/origin dist/
	cp target/release/origin.origin dist/ 2>/dev/null || true
	cp docs/origin-public.key dist/
	tar -czf origin-$(shell cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/').tar.gz -C dist .

clean: ## Clean build artifacts
	cargo clean
	rm -rf dist

release: ## Publish to crates.io (requires CARGO_REGISTRY_TOKEN)
	cargo publish -p origin-core
	cargo publish -p origin-cli
