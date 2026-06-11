# Origin — Build & Development

.DEFAULT_GOAL := help

.PHONY: help build test check clean coverage docs man install-man fuzz bench sbom tag-release dist release docker docker-push wasm

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

man: ## Build gzipped man page
	gzip -c docs/origin.1 > docs/origin.1.gz

install-man: man ## Install man page
	install -m 644 docs/origin.1.gz /usr/local/share/man/man1/origin.1.gz
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

docker: ## Build distroless Docker image
	docker build -t origin:$(shell cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/') .

docker-push: docker ## Push Docker image to GHCR
	docker tag origin:$(shell cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/') ghcr.io/thupa-pro/origin:$(shell cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/')
	docker tag origin:$(shell cargo metadata --no-deps --format-version 1 | sed 's/.*"version":"\([^"]*\)".*/\1/') ghcr.io/thupa-pro/origin:latest
	docker push ghcr.io/thupa-pro/origin --all-tags

wasm: ## Build WASM example
	cargo build -p origin-wasm-example --target wasm32-unknown-unknown

release: ## Publish to crates.io (requires CARGO_REGISTRY_TOKEN)
	cargo publish -p origin-core
	cargo publish -p origin-cli
