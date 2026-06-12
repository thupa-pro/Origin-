#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  Unsafe Rust Audit — Origin Network
#  Scans all crates for `unsafe` blocks and reports them for review.
#  Exit code = number of unsafe blocks found (0 = clean).
# ═══════════════════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOTAL=0

echo "══════════════════════════════════════════════════════════"
echo "  Unsafe Rust Block Audit"
echo "  Scanning workspace crates..."
echo "══════════════════════════════════════════════════════════"

while IFS= read -r -d '' crate; do
  name=$(basename "$crate")
  count=$(grep -rn "unsafe\b" "$crate/src" 2>/dev/null | grep -v "^.*\/\/.*unsafe" | grep -v "unsafe_code" | wc -l || true)
  if [ "$count" -gt 0 ]; then
    echo "  ⚠️   $name: $count unsafe block(s)"
    grep -rn "unsafe\b" "$crate/src" 2>/dev/null | grep -v "^.*\/\/.*unsafe" | grep -v "unsafe_code" | while IFS= read -r line; do
      echo "       → $line"
    done
  else
    echo "  ✅  $name: clean (0 unsafe blocks)"
  fi
  TOTAL=$((TOTAL + count))
done < <(find "$ROOT/crates" -maxdepth 1 -type d -print0)

echo "══════════════════════════════════════════════════════════"
echo "  Total: $TOTAL unsafe blocks across workspace"

# origin-core has #![deny(unsafe_code)] — should always be 0
CORE_UNSAFE=$(grep -rn "unsafe\b" "$ROOT/crates/origin-core/src" 2>/dev/null | grep -v "^.*\/\/.*unsafe" | grep -v "unsafe_code" | wc -l || true)
if [ "$CORE_UNSAFE" -gt 0 ]; then
  echo "  ❌ CRITICAL: origin-core has $CORE_UNSAFE unsafe blocks (must be 0)"
  echo "     origin-core has #![deny(unsafe_code)] — this should not happen."
fi

exit "$TOTAL"
