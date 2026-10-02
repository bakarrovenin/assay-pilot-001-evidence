#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${ASSAY_BENCHMARK_DB:-/opt/assay-benchmark-data/results.db}"
: "${ASSAY_BACKUP_S3_URI:?Set ASSAY_BACKUP_S3_URI to a private S3 bucket prefix}"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Assay database not found: $DB_PATH" >&2
  exit 1
fi

snapshot="$(mktemp /tmp/assay-results.XXXXXX.db)"
trap 'rm -f "$snapshot"' EXIT
sqlite3 "$DB_PATH" ".backup '$snapshot'"
aws s3 cp "$snapshot" \
  "${ASSAY_BACKUP_S3_URI%/}/results-$(date -u +%Y%m%dT%H%M%SZ).db" \
  --only-show-errors
