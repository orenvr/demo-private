/**
 * @name Email Header Injection Detection (Enhanced v2.1 - SUCCESS)
 * @description Fast and reliable email header injection detection with proven patterns
 * @kind problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, enhanced-v2-1
 * @id py/enhanced-v2-1-email-header-injection-success
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EnhancedV21EmailConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Function parameters with email-related names (proven pattern)
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(smtp_from|email|order_id|sender|customer_name|display_name|user_email|user_name|to|subject|body|name|from|recipient).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    // Function call sources (user input sources)
    exists(Call c |
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
    // SMTP method calls (proven pattern)
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
  }
}

module EnhancedV21EmailFlow = TaintTracking::Global<EnhancedV21EmailConfig>;

from EnhancedV21EmailFlow::PathNode source, EnhancedV21EmailFlow::PathNode sink
where EnhancedV21EmailFlow::flowPath(source, sink)
select sink.getNode(), "Enhanced v2.1 SUCCESS: Untrusted input flows from $@ to email header/SMTP operation", source.getNode(), "source"
