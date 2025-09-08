/**
 * @name Email Header Injection Detection (En       // SMTP method calls (optimized)
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )TP method calls (optimized)
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") anded v2.1)
 * @description Fast and reliable email header injection detection with proven patterns
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, enhanced-v2-1
 * @id py/enhanced-v2-1-email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EnhancedV21EmailConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Function parameters with email-related names (optimized patterns)
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(that|email|service|to|name|address|Message|body|subject|message|from).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    // Environment variables for SMTP configuration
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr() = "getenv" and
      exists(StringLiteral s | s = c.getArg(0) |
        s.getText().regexpMatch("(?i).*(SMTP_|EMAIL_|MAIL_).*")
      ) and
      source = DataFlow::exprNode(c)
    )
    or
    // User input function calls
    exists(Call c |
      c.getFunc() instanceof Name and
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read).*") and
      source = DataFlow::exprNode(c)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Email header assignments (proven pattern)
    exists(Subscript s |
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email).*") and
      exists(StringLiteral header | header = s.getIndex() |
        header.getText().regexpMatch("(?i)(to|from|subject|cc|bcc|reply-to)")
      ) and
      sink.asExpr() = s.getValue()
    )
    or
    // SMTP method calls (optimized)
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc() instanceof Attribute and getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
  }
}

module EnhancedV21EmailFlow = TaintTracking::Global<EnhancedV21EmailConfig>;

from EnhancedV21EmailFlow::PathNode source, EnhancedV21EmailFlow::PathNode sink
where EnhancedV21EmailFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Enhanced v2.1: Untrusted input flows to email header/SMTP operation"
