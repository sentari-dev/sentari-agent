#!/usr/bin/env bash
# Measure aggregate statement coverage and fail below THRESHOLD.
set -euo pipefail
THRESHOLD="${1:-80}"
# Portable temp file; an EXIT trap guarantees cleanup on every path (success,
# failure, or interrupt) rather than relying on manual rm calls.
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
if ! CGO_ENABLED=0 go test -coverprofile=coverage.out ./... >"$LOG" 2>&1; then
  echo "go test FAILED:"; tail -30 "$LOG"; exit 1
fi
TOTAL="$(go tool cover -func=coverage.out | awk '/^total:/ {print $3}' | tr -d '%')"
echo "total coverage: ${TOTAL}% (floor ${THRESHOLD}%)"
awk -v t="$TOTAL" -v th="$THRESHOLD" 'BEGIN { exit (t+0 < th+0) ? 1 : 0 }' \
  || { echo "FAIL: coverage ${TOTAL}% < ${THRESHOLD}%"; exit 1; }
