# Email Header Injection Detection with CodeQL

This is a complete CodeQL query pack that detects email header injection vulnerabilities in Python codebases. The query identifies untrusted data flows that reach email headers or SMTP recipient lists, which can lead to email header injection attacks.

## Overview

Email header injection is a vulnerability where attackers can inject malicious content into email headers by manipulating input data. This can lead to:
- Sending emails to unintended recipients (Bcc injection)
- Spam/phishing email relay attacks
- Email content manipulation
- Header forgery attacks

## Implementation

### Query Logic
The CodeQL query uses the modern `semmle.python.dataflow.new` API to perform taint tracking analysis:

- **Sources**: Environment variables (`os.environ.get()`), function parameters with email-related names, `input()` calls
- **Sinks**: SMTP method calls (`sendmail`, `send_message`) where untrusted data can reach recipient lists
- **Flow Analysis**: Tracks data flow from untrusted sources to dangerous sinks

### Files Structure
```
.github/codeql/ryudes-python-email/
├── qlpack.yml                          # Package metadata
├── queries/
│   └── EmailHeaderInjection.ql        # Main detection query
└── README.md                           # This file

src/emailservice/
└── vuln_demo.py                        # Vulnerable test fixture

scripts/
└── codeql-email-header-check.sh       # E2E execution script
```

## Usage

### Prerequisites
- CodeQL CLI 2.19.0 or later
- Python codebase for analysis

### Running the Analysis

1. **Execute the complete analysis:**
   ```bash
   cd /path/to/your/project
   export PATH="/path/to/codeql:$PATH"
   ./scripts/codeql-email-header-check.sh
   ```

2. **Manual execution:**
   ```bash
   # Create database
   codeql database create demo-db --language=python

   # Run query
   codeql query run .github/codeql/ryudes-python-email/queries/EmailHeaderInjection.ql \
     --database=demo-db --output=results.csv --format=csv
   ```

### Results Interpretation

The query produces path-problem results showing:
- **Source**: Location where untrusted data originates
- **Sink**: Location where untrusted data reaches a vulnerable operation
- **Path**: Data flow path from source to sink
- **Description**: Vulnerability explanation

Example result:
```
Email header injection vulnerability: os.environ.get("TO_ADDR") flows to SMTP call.
```

## Vulnerable Patterns Detected

### 1. Environment Variable to SMTP
```python
# Source: untrusted environment data
user_email = os.environ.get("TO_ADDR", "default@example.com")

# Sink: SMTP recipient list
smtp.sendmail("from@example.com", [user_email], message)
```

### 2. Function Parameter Flow
```python
def send_email(recipient):  # Source: function parameter
    server = smtplib.SMTP("localhost")
    server.sendmail("from@example.com", [recipient], body)  # Sink
```

## Technical Details

### CodeQL API Version
- Uses modern `semmle.python.dataflow.new.DataFlow` and `semmle.python.dataflow.new.TaintTracking` APIs
- Compatible with CodeQL Python pack `codeql/python-all@4.0.14`
- Implements `DataFlow::ConfigSig` interface for taint tracking configuration

### Query Metadata
- **ID**: `ryudes/email-header-injection`
- **Kind**: `path-problem`
- **Severity**: `error`
- **Security Severity**: `5.0`
- **Precision**: `high`
- **CWE Tags**: CWE-117, CWE-93

## Testing

The included `src/emailservice/vuln_demo.py` demonstrates vulnerable patterns:
- Environment variable source (`os.environ.get`)
- SMTP sink (`smtplib.SMTP.sendmail`)
- Data flow from source to sink

**Expected Result**: 1 vulnerability detection showing the flow from `os.environ.get` to `sendmail`.

## Limitations

1. **Current Scope**: Focuses on SMTP sinks; email header assignment sinks were simplified to avoid AST complexity issues
2. **API Compatibility**: Designed for modern CodeQL dataflow API (not classic/legacy APIs)
3. **False Negatives**: May miss complex indirect flows or framework-specific patterns
4. **Context Sensitivity**: Limited inter-procedural analysis depth

## Future Enhancements

1. **Extended Sinks**: Add support for email header assignment detection (`msg["To"] = value`)
2. **Framework Support**: Add support for Django, Flask, FastAPI email frameworks
3. **Sanitization**: Implement proper email validation sanitizer recognition
4. **Additional Sources**: HTTP request parameters, database queries, file inputs

## Development

### Running Tests
```bash
# Execute the test script
./scripts/codeql-email-header-check.sh

# Expected output: 1 finding in out-email-header.csv
```

### Adding New Patterns
Extend the `isSource` or `isSink` predicates in `queries/EmailHeaderInjection.ql`:

```ql
predicate isSource(DataFlow::Node source) {
  // Add new source patterns here
  // e.g., HTTP request data
  exists(DataFlow::CallCfgNode call |
    source = call and
    call.getFunction().asExpr().(Name).getId() = "request_data"
  )
  or
  // existing patterns...
}
```

## Security Impact

Email header injection vulnerabilities can lead to:
- **High Impact**: Unauthorized email sending, spam relay abuse
- **Medium Impact**: Information disclosure, reputation damage  
- **Compliance**: Relevant for security audits and penetration testing

This CodeQL query pack provides automated detection to help identify and remediate these security vulnerabilities during code review and CI/CD processes.

Run end-to-end via `scripts/codeql-email-header-check.sh`.
