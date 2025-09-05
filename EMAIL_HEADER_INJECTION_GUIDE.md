# Email Header Injection Rule - Implementation Guide

This document provides the exact steps to implement the email header injection CodeQL rule, based on the successful debugging process.

## Quick Reference: Working Solution

### Final Working Query Structure
```ql
/**
 * @name Email Header Injection
 * @description Detects untrusted data flowing into email headers or SMTP recipient lists
 * @kind path-problem
 * @id ryudes/email-header-injection
 * @severity error
 * @security-severity 5.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-117
 *       external/cwe/cwe-93
 */

import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import python

module EmailHeaderInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Sources implementation
  }

  predicate isSink(DataFlow::Node sink) {
    // Comprehensive sink patterns
  }
}

module EmailHeaderInjectionFlow = TaintTracking::Global<EmailHeaderInjectionConfig>;

from EmailHeaderInjectionFlow::PathNode source, EmailHeaderInjectionFlow::PathNode sink
where EmailHeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Email header injection vulnerability: $@ flows to email headers or SMTP calls.", source.getNode(), "untrusted data"
```

## Implementation Steps

### Step 1: Project Structure
```
.github/codeql/ryudes-python-email/
├── qlpack.yml                    # Package metadata
├── queries/
│   └── EmailHeaderInjection.ql  # Main query
└── README.md                     # Documentation
```

### Step 2: Package Configuration (`qlpack.yml`)
```yaml
name: ryudes/python-email
version: 0.0.1
dependencies:
  codeql/python-all: "*"
```

### Step 3: Source Patterns (Untrusted Data Origins)

```ql
predicate isSource(DataFlow::Node source) {
  // Environment variables - primary attack vector
  exists(DataFlow::CallCfgNode call |
    source = call and
    call.getFunction().(DataFlow::AttrRead).getObject().(DataFlow::ModuleVariableNode).getVariable().getName() = "os" and
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "environ"
  )
  or
  // os.getenv() calls
  exists(DataFlow::CallCfgNode call |
    source = call and
    call.getFunction().(DataFlow::AttrRead).getObject().(DataFlow::ModuleVariableNode).getVariable().getName() = "os" and
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "getenv"  
  )
  or
  // input() function calls
  exists(DataFlow::CallCfgNode call |
    source = call and
    call.getFunction().asExpr().(Name).getId() = "input"
  )
  or
  // Function parameters with email-related names
  exists(DataFlow::ParameterNode param |
    source = param and
    param.getParameter().getName().regexpMatch("(?i)(name|email|recipient|addr|address|to|from|subject)")
  )
}
```

### Step 4: Sink Patterns (Dangerous Operations)

**Critical insight**: The sink is the UNTRUSTED VALUE, not the operation using it.

```ql
predicate isSink(DataFlow::Node sink) {
  // SMTP sendmail - recipients argument (position 1)
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
    sink = call.getArg(1)
  )
  or
  // SMTP send_message - message argument (position 0)
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "send_message" and
    sink = call.getArg(0)
  )
  or
  // Email header assignments: msg["To"] = value (the value is the sink)
  exists(AssignStmt assign, Subscript target |
    assign.getATarget() = target and
    DataFlow::exprNode(assign.getValue()) = sink and
    target.getIndex().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender|return-path)")
  )
  or
  // Header method calls: msg.add_header("To", value) (the value is the sink)
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "add_header" and
    sink = call.getArg(1) and
    call.getArg(0).asExpr().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender|return-path)")
  )
}
```

## Testing Implementation

### Test Fixture (`test_vuln.py`)
```python
import os
import smtplib
from email.message import Message

def test_smtp_injection():
    """Should detect: SMTP recipient injection"""
    user_addr = os.environ.get("TO_ADDR", "attacker@evil.com")
    s = smtplib.SMTP("localhost")
    s.sendmail("from@example.com", [user_addr], "body")  # SINK: arg(1)

def test_header_assignment():
    """Should detect: Email header assignment"""
    user_addr = os.environ.get("TO_ADDR", "attacker@evil.com") 
    msg = Message()
    msg["To"] = user_addr  # SINK: the value being assigned

def test_header_method():
    """Should detect: Header method call"""
    user_addr = os.environ.get("TO_ADDR", "attacker@evil.com")
    msg = Message()
    msg.add_header("To", user_addr)  # SINK: arg(1)

def test_parameter_flow():
    """Should detect: Parameter to header flow"""
    def send_email(recipient):  # SOURCE: parameter
        msg = Message()
        msg["To"] = recipient  # SINK: parameter flows here
        return msg
```

### Expected Results
The query should detect **4 vulnerability paths**:
1. `os.environ.get()` → `sendmail()` recipients
2. `os.environ.get()` → `msg["To"]` assignment  
3. `os.environ.get()` → `add_header()` value
4. Function parameter → `msg["To"]` assignment

### Validation Command
```bash
# Create database
codeql database create test-db --language=python

# Run query
codeql query run queries/EmailHeaderInjection.ql \
  --database=test-db \
  --output=results.bqrs

# Decode results
codeql bqrs decode --format=csv results.bqrs

# Expected: 4+ results showing source→sink flows
```

## Common Issues & Solutions

### Issue 1: No Results Found
**Cause**: Source or sink patterns not matching actual code  
**Solution**: Test patterns individually:
```ql
// Debug sources
select source from DataFlow::Node source where isSource(source)

// Debug sinks  
select sink from DataFlow::Node sink where isSink(sink)
```

### Issue 2: Wrong AST Types
**Cause**: Using incorrect type names (e.g., `StrLiteral` instead of `StringLiteral`)  
**Solution**: Check CodeQL documentation for Python AST types

### Issue 3: Missing Header Assignment Detection
**Cause**: Trying to detect assignment operation instead of the value  
**Solution**: Use `DataFlow::exprNode(assign.getValue()) = sink`

### Issue 4: Compilation Errors
**Cause**: API misuse or wrong imports  
**Solution**: Use modern APIs consistently:
```ql
import semmle.python.dataflow.new.DataFlow      // ✅ Modern
import semmle.python.dataflow.new.TaintTracking // ✅ Modern
// NOT: semmle.python.dataflow.DataFlow          // ❌ Legacy
```

## Performance Considerations

### Efficient Patterns
```ql
// GOOD: Specific attribute names
call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail"

// GOOD: Specific regex patterns  
target.getIndex().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc)")
```

### Patterns to Avoid
```ql
// AVOID: Overly broad matching
call.getFunction().(DataFlow::AttrRead).getAttributeName().matches("%mail%")

// AVOID: Complex nested exists without constraints
exists(DataFlow::Node n | exists(DataFlow::Node m | ... ))
```

## Extension Points

### Adding New Sources
```ql
// HTTP request data
exists(DataFlow::CallCfgNode call |
  source = call and
  call.getFunction().toString().matches("%request%")
)

// Database query results
exists(DataFlow::CallCfgNode call |
  source = call and
  call.getFunction().toString().matches("%.execute%")
)
```

### Adding New Sinks
```ql
// Email library method calls
exists(DataFlow::CallCfgNode call |
  call.getFunction().(DataFlow::AttrRead).getAttributeName().matches("send%") and
  sink = call.getArg(0)
)

// Template rendering with email data
exists(DataFlow::CallCfgNode call |
  call.getFunction().toString().matches("%.render%") and
  sink = call.getArg(0)
)
```

## Deployment

### Integration with CI/CD
```yaml
# .github/workflows/codeql.yml
- name: Run Custom CodeQL Queries
  run: |
    codeql database create db --language=python
    codeql query run .github/codeql/*/queries/*.ql --database=db
```

### Query Pack Distribution
```bash
# Package for distribution
codeql pack create .github/codeql/ryudes-python-email/

# Install in other projects
codeql pack install ryudes/python-email
```

This implementation guide provides the exact patterns and approaches that work, avoiding the pitfalls encountered during development.
