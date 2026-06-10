#!/usr/bin/env bash
set -euo pipefail

# sign-with-parent.sh — Create a provenance chain by signing with a parent
#
# Usage: ./sign-with-parent.sh <artifact-path> <parent-statement> [<key-file>]

ARTIFACT="${1:?Usage: $0 <artifact-path> <parent-statement> [<key-file>]}"
PARENT="${2:?Usage: $0 <artifact-path> <parent-statement> [<key-file>]}"
KEY="${3:-origin-secret.key}"

if [ ! -f "$ARTIFACT" ]; then
    echo "Error: artifact not found: $ARTIFACT"
    exit 1
fi

if [ ! -f "$PARENT" ]; then
    echo "Error: parent statement not found: $PARENT"
    exit 1
fi

echo "Signing $ARTIFACT with parent $PARENT..."
origin sign "$ARTIFACT" --key "$KEY" --parent "$PARENT"

echo ""
echo "Verifying..."
origin verify "${ARTIFACT}.origin" "$ARTIFACT" --consistency-only

echo ""
echo "Parent reference:"
grep '^parent: ' "${ARTIFACT}.origin"

echo ""
echo "Done. Statement written to ${ARTIFACT}.origin"
echo "Chain: $PARENT -> ${ARTIFACT}.origin"
