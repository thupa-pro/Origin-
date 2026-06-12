#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  Omega Sentinel — Origin Network Crucible Verification
#  Runs all gates that a release must pass.
# ═══════════════════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
GATES=()

banner()   { echo -e "\n══════════════════════════════════════════════════════════"; }
pass()     { echo "  ✅ $1"; ((PASS++)); }
fail()     { echo "  ❌ $1"; ((FAIL++)); }
gate()     { GATES+=("$1"); }

gate "cargo fmt --check"
gate "cargo clippy --all-targets -- -D warnings"
gate "cargo deny check"
gate "cargo build"
gate "cargo test"
gate "cargo test --all-features"
gate "cargo build -p origin-core --target wasm32-unknown-unknown"
gate "cargo clippy -p origin-core --target wasm32-unknown-unknown --all-targets -- -D warnings"

# TypeScript SDK integration
gate() {
  local desc=$1 cmd=$2
  banner
  echo "  🔍 $desc"
  if eval "$cmd" 2>&1; then pass "$desc"; else fail "$desc"; fi
}

banner
echo "  🛡️  ORIGIN OMEGA SENTINEL"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
banner

gate "Formatting check"     "cd $ROOT && cargo fmt --check"
gate "Clippy (all targets)" "cd $ROOT && cargo clippy --all-targets -- -D warnings"
gate "cargo-deny"           "cd $ROOT && cargo deny check"
gate "Build (all crates)"   "cd $ROOT && cargo build"
gate "Tests (default)"      "cd $ROOT && cargo test"
gate "Tests (all features)" "cd $ROOT && cargo test --all-features"
gate "WASM build"           "cd $ROOT && cargo build -p origin-core --target wasm32-unknown-unknown"
gate "WASM clippy"          "cd $ROOT && cargo clippy -p origin-core --target wasm32-unknown-unknown --all-targets -- -D warnings"

if [ -f "$ROOT/packages/origin-sdk/test.mjs" ]; then
  gate "Node.js SDK tests" "cd $ROOT && mkdir -p packages/origin-sdk/bin && \
    cp target/wasm32-unknown-unknown/debug/origin_core.wasm packages/origin-sdk/bin/origin-core.wasm && \
    node --test packages/origin-sdk/test.mjs"
fi

gate "Benchmarks (compile)" "cd $ROOT && cargo bench --no-run"

banner
echo "  RESULTS: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  echo "  VERDICT: ❌ FAILED — $FAIL gate(s) not cleared"
  exit 1
fi
echo "  VERDICT: ✅ CLEAR — all gates passed"
banner
