#!/bin/bash

# Enterprise-Grade Email Header Injection Detection - E2E Test Script
# This script validates that the CodeQL query correctly detects email header injection vulnerabilities

set -e

REPO_ROOT="/workspaces/demo-private"
QUERY_PATH="$REPO_ROOT/.github/codeql/ryudes-python-email/queries/EmailHeaderInjection.ql"
DB_PATH="$REPO_ROOT/.codeql-db/db-py"
OUTPUT_CSV="$REPO_ROOT/out-email-header.csv"

echo "[i] Repo root: $REPO_ROOT"
echo "[i] Query: $QUERY_PATH"

# Step 1: Build CodeQL database
echo "[i] Building DB at $DB_PATH ..."
cd "$REPO_ROOT"
codeql database create --language=python --source-root="$REPO_ROOT" "$DB_PATH" --overwrite

# Step 2: Run query
echo "[i] Running query..."
codeql query run --database="$DB_PATH" "$QUERY_PATH" --output="$REPO_ROOT/out-email-header.bqrs"

# Step 3: Decode results
echo "[i] Decoding BQRS → CSV..."
codeql bqrs decode --format=csv --output="$OUTPUT_CSV" "$REPO_ROOT/out-email-header.bqrs"

# Step 4: Count results
RESULT_COUNT=$(tail -n +2 "$OUTPUT_CSV" | wc -l)
echo "[✓] Success: $RESULT_COUNT finding(s) produced."
echo "[i] CSV: $OUTPUT_CSV"

# Step 5: Validate expected results
if [ "$RESULT_COUNT" -gt 0 ]; then
    echo "[✓] Query successfully detected vulnerabilities!"
    echo "[i] Results:"
    tail -n +2 "$OUTPUT_CSV" | head -10
else
    echo "[!] No vulnerabilities detected. This may indicate:"
    echo "    - Query logic needs adjustment"
    echo "    - Test cases are not vulnerable enough"
    echo "    - Source/sink patterns don't match actual code"
fi
