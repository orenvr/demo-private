# CodeQL Learning Guide: Email Header Injection Rule Creation

This document provides comprehensive guidance for creating CodeQL rules, specifically based on lessons learned from implementing an email header injection detection rule for Python.

## Table of Contents
1. [Core Principles](#core-principles)
2. [API Selection Strategy](#api-selection-strategy)
3. [Sink Pattern Design](#sink-pattern-design)
4. [Common Mistakes & Pitfalls](#common-mistakes--pitfalls)
5. [Step-by-Step Implementation](#step-by-step-implementation)
6. [Testing & Validation](#testing--validation)
7. [Best Practices for Coding Agents](#best-practices-for-coding-agents)

## Core Principles

### 1. Start Simple, Build Incrementally
❌ **DON'T**: Try to implement complex pattern matching on the first attempt  
✅ **DO**: Start with basic patterns that you know work, then expand coverage

```ql
// START with simple, known patterns
predicate isSink(DataFlow::Node sink) {
  // SMTP calls only - test this first
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
    sink = call.getArg(1)
  )
}
```

### 2. Understand Your Target Patterns First
Before writing any CodeQL, manually identify ALL vulnerability patterns:

```python
# Pattern 1: SMTP recipient injection
s.sendmail("from@example.com", [user_controlled], "body")  # sink = arg(1)

# Pattern 2: Email header assignment
msg["To"] = user_controlled  # sink = the VALUE being assigned

# Pattern 3: Header method calls  
msg.add_header("To", user_controlled)  # sink = arg(1)
```

### 3. Use the Right Mental Model
- **Sources**: Where untrusted data originates (`os.environ.get()`, `input()`, function parameters)
- **Sinks**: Where untrusted data becomes dangerous (the VALUE that gets used unsafely)
- **Flows**: How data moves from sources to sinks (CodeQL handles this automatically)

## API Selection Strategy

### Modern vs Legacy APIs

| Use Case | Modern API (✅ Preferred) | Legacy API (❌ Avoid) |
|----------|--------------------------|----------------------|
| Taint Tracking | `TaintTracking::Global<Config>` | `TaintTracking::Configuration` |
| DataFlow Nodes | `DataFlow::Node`, `DataFlow::CallCfgNode` | Custom AST traversal |
| AST Access | Direct AST when needed: `AssignStmt`, `StringLiteral` | Complex casting chains |

### Key API Components
```ql
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import python  // For AST access when needed
```

## Sink Pattern Design

### Critical Insight: Identify What Is Actually Dangerous

**The sink should be the UNTRUSTED VALUE, not the operation that uses it.**

#### Example: Email Header Assignment
```python
msg["To"] = user_controlled_value  # <-- THIS is the sink (the value)
```

```ql
// CORRECT: Detect the value being assigned
exists(AssignStmt assign, Subscript target |
  assign.getATarget() = target and
  DataFlow::exprNode(assign.getValue()) = sink and  // sink = the VALUE
  target.getIndex().(StringLiteral).getText() = "To"
)
```

#### Example: SMTP Call
```python
s.sendmail("from", [recipients], "body")  # <-- recipients list is the sink
```

```ql
// CORRECT: Detect the argument containing recipients
exists(DataFlow::CallCfgNode call |
  call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
  sink = call.getArg(1)  // sink = the recipients argument
)
```

### Comprehensive Sink Patterns

```ql
predicate isSink(DataFlow::Node sink) {
  // Pattern 1: SMTP sendmail - recipients parameter
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
    sink = call.getArg(1)
  )
  or
  // Pattern 2: SMTP send_message - message parameter
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "send_message" and
    sink = call.getArg(0)
  )
  or
  // Pattern 3: Email header assignment - the value being assigned
  exists(AssignStmt assign, Subscript target |
    assign.getATarget() = target and
    DataFlow::exprNode(assign.getValue()) = sink and
    target.getIndex().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender)")
  )
  or
  // Pattern 4: Header method calls - header value parameter
  exists(DataFlow::CallCfgNode call |
    call.getFunction().(DataFlow::AttrRead).getAttributeName() = "add_header" and
    sink = call.getArg(1) and
    call.getArg(0).asExpr().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender)")
  )
}
```

## Common Mistakes & Pitfalls

### 1. Wrong AST Type Names
❌ **MISTAKE**: Using made-up type names
```ql
// WRONG - these types don't exist
assignment.asExpr().(Assign)
subscript.getSlice().(StrLiteral)
```

✅ **CORRECT**: Use actual CodeQL AST types
```ql
// RIGHT - these are real types
assign.(AssignStmt)
index.(StringLiteral)
```

### 2. Overcomplicating DataFlow Access
❌ **MISTAKE**: Complex casting and chaining
```ql
// WRONG - overly complex
exists(DataFlow::CfgNode assignment |
  assignment.asCfgNode().getNode().(Assign).getValue() = sink.asCfgNode().getNode()
)
```

✅ **CORRECT**: Direct AST access when needed
```ql
// RIGHT - simple and clear
exists(AssignStmt assign |
  DataFlow::exprNode(assign.getValue()) = sink
)
```

### 3. Misunderstanding Sink Location
❌ **MISTAKE**: Trying to make the assignment operation the sink
```ql
// WRONG - the assignment itself isn't dangerous
exists(DataFlow::PostUpdateNode post | sink = post)
```

✅ **CORRECT**: The VALUE being assigned is dangerous
```ql
// RIGHT - the untrusted value is what flows to the sink
DataFlow::exprNode(assign.getValue()) = sink
```

### 4. API Version Confusion
❌ **MISTAKE**: Mixing old and new APIs
```ql
// WRONG - mixing TaintTracking::Configuration (old) with DataFlow (new)
class MyConfig extends TaintTracking::Configuration {
  predicate isSink(DataFlow::Node sink) { ... }
}
```

✅ **CORRECT**: Use consistent modern APIs
```ql
// RIGHT - pure modern API
module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { ... }
  predicate isSink(DataFlow::Node sink) { ... }
}
```

## Step-by-Step Implementation

### Phase 1: Basic Infrastructure
1. Create proper pack structure with `qlpack.yml`
2. Set up imports for modern APIs
3. Create minimal source detection (e.g., `os.environ.get()`)
4. Create ONE simple sink pattern (e.g., SMTP calls only)
5. Test with one vulnerability

### Phase 2: Expand Coverage
1. Add more source patterns incrementally
2. Add more sink patterns one at a time
3. Test each addition separately
4. Validate against test fixtures

### Phase 3: Refinement
1. Add regex patterns for comprehensive coverage
2. Handle edge cases
3. Optimize performance if needed
4. Document limitations

## Testing & Validation

### Create Comprehensive Test Fixtures
```python
# test_fixtures.py - Cover ALL patterns you want to detect
import os
import smtplib
from email.message import Message

def vuln_smtp():
    user_data = os.environ.get("TO_ADDR")
    smtp = smtplib.SMTP("localhost")
    smtp.sendmail("from@example.com", [user_data], "body")  # Should detect

def vuln_header():
    user_data = os.environ.get("TO_ADDR") 
    msg = Message()
    msg["To"] = user_data  # Should detect

def vuln_method():
    user_data = os.environ.get("TO_ADDR")
    msg = Message()
    msg.add_header("To", user_data)  # Should detect
```

### Validation Process
1. **Count expected results**: Manual review of test fixtures
2. **Run query**: Execute against test database
3. **Compare**: Actual results vs expected results
4. **Debug gaps**: For each missing result, understand why pattern didn't match

## Best Practices for Coding Agents

### DO's for CodeQL Development

1. **Start with working examples**: Use CodeQL documentation and GitHub's official queries as templates
2. **Test incrementally**: Add one pattern at a time, verify it works
3. **Use proper AST types**: Check CodeQL documentation for correct type names
4. **Validate early and often**: Create test fixtures and verify results continuously
5. **Keep patterns simple**: Prefer clear, readable patterns over clever complex ones
6. **Document your intent**: Add comments explaining what each pattern detects

### DON'Ts for CodeQL Development

1. **Don't mix API versions**: Stick to modern APIs consistently
2. **Don't over-engineer**: Simple patterns that work are better than complex patterns that don't
3. **Don't assume types exist**: Always verify AST type names in documentation
4. **Don't skip testing**: Each pattern should be validated against real code
5. **Don't try to detect everything at once**: Build coverage incrementally
6. **Don't ignore compilation errors**: Fix syntax before moving to logic

### Debugging Approach

When queries don't work as expected:

1. **Simplify**: Remove complex patterns, start with basics
2. **Check types**: Verify all AST types are correct
3. **Add debug output**: Use simple `select` statements to understand what's being matched
4. **Test individual patterns**: Comment out all but one pattern to isolate issues
5. **Read compilation errors carefully**: CodeQL errors often point to specific API misuse

### Example Debug Query
```ql
// Debug query - see what assignments we're finding
from AssignStmt assign, Subscript target
where assign.getATarget() = target
select assign, target, target.getIndex()
```

## Key Takeaways

1. **Simplicity wins**: The working solution was much simpler than the broken complex attempts
2. **Know your APIs**: Modern CodeQL APIs are more straightforward than legacy ones  
3. **Test thoroughly**: Every pattern should be validated against real code
4. **Understand the vulnerability**: Before coding, clearly identify what makes code dangerous
5. **Iterate incrementally**: Build working solutions step by step, don't try to solve everything at once

This guide represents lessons learned from extensive debugging and refinement. Following these principles should help avoid the common pitfalls that made this implementation initially complex.
