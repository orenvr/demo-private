#!/bin/bash
# File: .github/scripts/setup-custom-codeql.sh

set -e

echo "🔧 Setting up Custom CodeQL Environment"

# Verify CodeQL CLI is available
if ! command -v codeql &> /dev/null; then
    echo "❌ CodeQL CLI not found in PATH"
    echo "GitHub Actions should have CodeQL available, checking..."
    ls -la /opt/ | grep -i codeql || true
    which codeql || true
    echo "PATH: $PATH"
    exit 1
else
    echo "✅ CodeQL CLI found: $(codeql version --format=json | jq -r .productName) $(codeql version --format=json | jq -r .semanticVersion)"
fi

# Verify custom query pack exists
echo "🔍 Verifying custom query pack..."
PACK_PATH=".github/codeql/ryudes-python-email"

if [ ! -f "${PACK_PATH}/codeql-pack.yml" ]; then
    echo "❌ Missing codeql-pack.yml in ${PACK_PATH}"
    exit 1
fi

if [ ! -d "${PACK_PATH}/queries" ]; then
    echo "❌ Missing queries directory in ${PACK_PATH}"
    exit 1
fi

echo "✅ Custom query pack structure verified"

# Install pack dependencies
echo "📦 Installing query pack dependencies..."
cd "${PACK_PATH}"
codeql pack install --mode=update || {
    echo "⚠️ Pack install failed, trying without update mode..."
    codeql pack install || {
        echo "❌ Failed to install pack dependencies"
        exit 1
    }
}

# Compile queries to verify syntax
echo "🔨 Compiling custom queries..."
compiled_queries=0
failed_queries=0

for query in queries/*.ql; do
    if [ -f "$query" ]; then
        query_name=$(basename "$query")
        echo "  Compiling: $query_name"
        if codeql query compile "$query"; then
            echo "  ✅ $query_name compiled successfully"
            ((compiled_queries++))
        else
            echo "  ❌ $query_name failed to compile"
            ((failed_queries++))
        fi
    fi
done

cd - > /dev/null

echo ""
echo "📊 Compilation Summary:"
echo "  ✅ Successfully compiled: $compiled_queries queries"
echo "  ❌ Failed to compile: $failed_queries queries"

if [ $failed_queries -gt 0 ]; then
    echo "❌ Some queries failed to compile"
    exit 1
fi

echo "✅ Custom CodeQL setup completed successfully!"
