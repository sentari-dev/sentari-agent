#!/usr/bin/env bash
# Measure aggregate statement coverage and fail below THRESHOLD.
set -euo pipefail
THRESHOLD="${1:-80}"
if ! CGO_ENABLED=0 go test -coverprofile=coverage.out ./... >/tmp/agent-cov-test.log 2>&1; then
  echo "go test FAILED:"; tail -30 /tmp/agent-cov-test.log; exit 1
fi
TOTAL="$(go tool cover -func=coverage.out | awk '/^total:/ {print $3}' | tr -d '%')"
echo "total coverage: ${TOTAL}% (floor ${THRESHOLD}%)"
awk -v t="$TOTAL" -v th="$THRESHOLD" 'BEGIN { exit (t+0 < th+0) ? 1 : 0 }' \
  || { echo "FAIL: coverage ${TOTAL}% < ${THRESHOLD}%"; exit 1; }
