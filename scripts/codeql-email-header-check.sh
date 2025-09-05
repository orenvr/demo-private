#!/usr/bin/env bash
set -euo pipefail

TOP="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
DB="$TOP/.codeql-db/db-py"
QPACK_DIR="$TOP/.github/codeql/ryudes-python-email"
QABS="$QPACK_DIR/queries/EmailHeaderInjection.ql"
OUT="$TOP/out-email-header.bqrs"
CSV="$TOP/out-email-header.csv"
LOG="$TOP/codeql-run.log"

echo "[i] Repo root: $TOP"
echo "[i] Query:     $QABS"

# 0) Pre-flight
command -v codeql >/dev/null || { echo "[!] codeql not found"; exit 1; }
[ -f "$QABS" ] || { echo "[!] Missing query: $QABS"; exit 1; }

# 1) Ensure python-all pack
if ! codeql resolve packs --format=text | grep -q 'codeql/python-all:'; then
  echo "[i] Downloading codeql/python-all..."
  codeql pack download codeql/python-all@4.0.14
fi

# 2) Create DB fresh
rm -rf "$DB"
echo "[i] Building DB at $DB ..."
codeql database create "$DB" \
  --language=python \
  --source-root="$TOP" \
  --overwrite \
  --log-to-stderr --verbosity=progress | tee "$LOG"

# 3) Verify database was created successfully
if [ ! -f "$DB/codeql-database.yml" ] && [ ! -f "$DB/src.zip" ] && [ ! -d "$DB/sourceArchive" ]; then
  echo "[!] DB creation failed; missing essential files." | tee -a "$LOG"
  exit 2
fi

# 4) Run query
echo "[i] Running query..."
codeql query run \
  --database "$DB" \
  --additional-packs "$TOP/.github/codeql" \
  --output "$OUT" \
  --log-to-stderr --verbosity=progress \
  "$QABS" | tee -a "$LOG"

# 5) Decode results to CSV
echo "[i] Decoding BQRS → CSV..."
codeql bqrs decode --format=csv "$OUT" > "$CSV"

# 6) Require non-empty findings (header + ≥1 row)
rows=$(tail -n +2 "$CSV" | wc -l | tr -d ' ')
if [ "$rows" -lt 1 ]; then
  echo "[!] No findings produced. Expected ≥1 from the vulnerable fixture."
  echo "[!] See $LOG and verify sources/sinks are modeled correctly."
  exit 3
fi

echo "[✓] Success: $rows finding(s) produced."
echo "[i] CSV: $CSV"
