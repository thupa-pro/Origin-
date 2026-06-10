#!/usr/bin/env bash
set -euo pipefail

# verify-release.sh — Verify a release artifact against its Origin statement
#
# Usage: ./verify-release.sh <artifact-path> [<key-file>]
#
# If no key file is specified, tries origin-public.key in the current directory.
# Prints VERIFIED or FAILED and exits with 0 or 1.

ARTIFACT="${1:?Usage: $0 <artifact-path> [<key-file>]}"
STATEMENT="${ARTIFACT}.origin"
KEY="${2:-origin-public.key}"

if [ ! -f "$STATEMENT" ]; then
    echo "Error: statement not found: $STATEMENT"
    echo ""
    echo "Expected a .origin file next to the artifact."
    echo "Download both the artifact and the .origin file from the publisher."
    exit 1
fi

# If no specific key file, try to extract the key from the statement and
# prompt the user to verify it out of band.
if [ ! -f "$KEY" ]; then
    echo "Note: no public key file found at $KEY"
    echo ""
    echo "The statement contains this public key:"
    grep '^key: ' "$STATEMENT" | sed 's/^key: /  /'
    echo ""
    echo "Verify this key through a trusted channel (website, Signal, etc.)"
    echo "Then save it to $KEY and re-run this script."
    echo ""
    echo "For now, verifying with the key embedded in the statement..."
    grep '^key: ' "$STATEMENT" | sed 's/^key: //' > /tmp/origin-verify-key.$$
    origin verify "$STATEMENT" "$ARTIFACT" --consistency-only 2>&1 || true
    rm -f /tmp/origin-verify-key.$$
    exit 1
fi

origin verify "$STATEMENT" "$ARTIFACT" --trusted-key "$KEY"
