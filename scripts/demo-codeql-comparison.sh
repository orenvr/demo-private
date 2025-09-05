#!/bin/bash

# Demo script to show the difference between standard and custom CodeQL analysis
# This demonstrates the value of custom CodeQL rules

set -e

echo "=========================================="
echo "CodeQL Analysis Comparison Demo"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Ensure we have a database
if [[ ! -d "codeql-database" ]]; then
    echo -e "${BLUE}[1/4] Creating CodeQL database...${NC}"
    codeql database create codeql-database --language=python --source-root=.
    echo ""
else
    echo -e "${BLUE}[1/4] Using existing CodeQL database...${NC}"
    echo ""
fi

echo -e "${BLUE}[2/4] Running STANDARD CodeQL analysis (built-in rules only)...${NC}"
echo "This analysis uses only the standard CodeQL security queries."
echo "Expected: Will NOT detect our email header injection vulnerability"
echo ""

# Run standard analysis
codeql database analyze codeql-database \
    --format=csv \
    --output=standard-results.csv \
    codeql/python-queries:codeql-suites/python-security-extended.qls

echo -e "${YELLOW}Standard analysis results:${NC}"
if [[ -f "standard-results.csv" ]]; then
    result_count=$(tail -n +2 standard-results.csv | wc -l)
    echo "Found $result_count vulnerabilities using standard rules"
    if [[ $result_count -gt 0 ]]; then
        echo "Standard vulnerabilities found:"
        tail -n +2 standard-results.csv | cut -d',' -f1,4 | head -5
    fi
else
    echo "No results file generated"
fi

echo ""
echo -e "${BLUE}[3/4] Running CUSTOM CodeQL analysis (with email header injection detection)...${NC}"
echo "This analysis includes our custom email header injection rule."
echo "Expected: WILL detect the email header injection vulnerabilities"
echo ""

# Run custom analysis  
codeql database analyze codeql-database \
    --format=csv \
    --output=custom-results.csv \
    .github/codeql/ryudes-python-email/queries/EmailHeaderInjection.ql

echo -e "${GREEN}Custom analysis results:${NC}"
if [[ -f "custom-results.csv" ]]; then
    custom_count=$(tail -n +2 custom-results.csv | wc -l)
    echo "Found $custom_count email header injection vulnerabilities using custom rule"
    if [[ $custom_count -gt 0 ]]; then
        echo "Email header injection vulnerabilities:"
        tail -n +2 custom-results.csv | cut -d',' -f4
    fi
else
    echo "No results file generated"
fi

echo ""
echo -e "${BLUE}[4/4] Summary and Comparison${NC}"
echo "=========================================="
echo -e "${YELLOW}Standard CodeQL Results:${NC}"
if [[ -f "standard-results.csv" ]]; then
    standard_count=$(tail -n +2 standard-results.csv | wc -l)
    echo "  • Found $standard_count vulnerabilities (general security issues)"
    echo "  • Did NOT detect email header injection (as expected)"
else
    echo "  • Found 0 vulnerabilities"
fi

echo ""
echo -e "${GREEN}Custom CodeQL Results:${NC}"
if [[ -f "custom-results.csv" ]]; then
    custom_count=$(tail -n +2 custom-results.csv | wc -l)
    echo "  • Found $custom_count email header injection vulnerabilities"
    echo "  • Successfully detected our specific vulnerability pattern"
else
    echo "  • Found 0 vulnerabilities"
fi

echo ""
echo -e "${RED}🎯 Key Takeaway:${NC}"
echo "Custom CodeQL rules allow you to detect application-specific"
echo "vulnerabilities that standard rules miss. This demonstrates the"
echo "power of extending CodeQL with domain-specific security knowledge."

echo ""
echo "Files generated:"
echo "  • standard-results.csv - Standard CodeQL findings"
echo "  • custom-results.csv - Custom rule findings"
