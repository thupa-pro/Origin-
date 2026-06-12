#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  OpenAPI Drift Detector — Origin Network
#  Rebuilds the OpenAPI spec from Rust types and compares with the checked-in
#  version. Exits non-zero if they differ (indicating drift).
# ═══════════════════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC_FILE="$ROOT/docs/specs/openapi.yaml"

if ! command -v cargo-utoipa &>/dev/null && ! command -v utoipa-gen &>/dev/null; then
  echo "⚠️   OpenAPI generation not available — skipping drift check"
  echo "    Install with: cargo install utoipa-gen"
  exit 0
fi

echo "🔍  Checking OpenAPI spec drift..."
echo "    Spec: $SPEC_FILE"

# TODO: generate openapi spec from service crates
# This will be implemented when services/ crates have utoipa annotations.
echo "    ℹ️   No service crates with utoipa yet — skipping check"
exit 0
