# CodeQL Custom Rules Demo

This repository demonstrates the power of custom CodeQL rules by comparing standard CodeQL analysis with custom email header injection detection.

## 🎯 Demo Overview

This demo shows how custom CodeQL rules can detect application-specific vulnerabilities that standard rules miss.

### What gets detected:
- **Standard CodeQL**: General security vulnerabilities (SQL injection, XSS, etc.)
- **Custom Rule**: Email header injection vulnerabilities in Python code

### Vulnerable Code Location:
- `vuln_demo.py` - Contains email header injection vulnerabilities that standard CodeQL won't catch

## 🚀 Running the Demo

### Option 1: Local Comparison Demo
Run both analyses locally to see the difference:

```bash
./scripts/demo-codeql-comparison.sh
```

This will:
1. Create a CodeQL database
2. Run standard CodeQL analysis 
3. Run custom email header injection analysis
4. Compare results and show the value of custom rules

### Option 2: GitHub Actions CI
The repository is configured with two separate GitHub Actions jobs:

1. **Standard CodeQL Analysis** - Uses built-in CodeQL rules only
2. **Custom CodeQL Analysis** - Includes our email header injection detection

Both results appear in GitHub's Security tab under "Code scanning alerts" with different categories.

## 📁 Project Structure

```
.github/
  codeql/
    ryudes-python-email/    # Custom query pack
      qlpack.yml           # Query pack configuration
      queries/
        EmailHeaderInjection.ql  # Custom email header injection rule
  workflows/
    codeql.yml             # GitHub Actions workflow (dual analysis)

scripts/
  demo-codeql-comparison.sh          # Local demo script
  codeql-email-header-check.sh       # Custom rule test script

vuln_demo.py               # Vulnerable Python code (test fixture)
docs/
  CODEQL_LEARNING_GUIDE.md           # CodeQL learning guide
  EMAIL_HEADER_INJECTION_GUIDE.md    # Email header injection guide
```

## 🔍 Understanding the Results

### Standard CodeQL (Expected Results)
- ✅ Detects common vulnerabilities (if any exist)
- ❌ **Does NOT detect email header injection** (no built-in rule for this)

### Custom CodeQL (Expected Results)  
- ✅ **Detects email header injection** vulnerabilities
- ✅ Finds untrusted data flowing into email headers/SMTP calls
- ✅ Shows specific source → sink data flow paths

## 💡 Key Takeaways

1. **Standard rules are comprehensive but not exhaustive** - They can't cover every application-specific vulnerability pattern
2. **Custom rules fill the gaps** - Domain experts can encode specialized security knowledge
3. **Both approaches are valuable** - Standard + custom rules provide the most comprehensive coverage
4. **CodeQL is extensible** - Easy to add new vulnerability detection as your understanding evolves

## 🛠️ Technical Details

### Custom Rule Features:
- **Taint tracking**: Follows data flow from untrusted sources to dangerous sinks
- **Modern CodeQL API**: Uses latest `semmle.python.dataflow.new.DataFlow` framework
- **Comprehensive sources**: Environment variables, user input, external data
- **Specific sinks**: Email headers, SMTP recipient lists, email content

### Vulnerability Pattern:
```python
# This pattern gets detected by our custom rule:
user_input = os.environ.get('USER_EMAIL')  # Source: untrusted data
msg['To'] = user_input                     # Sink: email header assignment
```

## 📚 Learning Resources

- [CODEQL_LEARNING_GUIDE.md](docs/CODEQL_LEARNING_GUIDE.md) - Comprehensive CodeQL learning guide
- [EMAIL_HEADER_INJECTION_GUIDE.md](docs/EMAIL_HEADER_INJECTION_GUIDE.md) - Email header injection security guide
