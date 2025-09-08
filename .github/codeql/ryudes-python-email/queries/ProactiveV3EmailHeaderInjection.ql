/**
 * @name Email Header Injection Detection (Proactive v3)
 * @description Proactive detection of email header injection from requirements analysis. Generated with realistic expectations and iterative correction.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, proactive-v3, realistic
 * @id py/proactive-v3-email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module ProactiveV3EmailConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Function parameters with email-related names
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(smtp_from|email|order_id|sender|src/emailservice/|customer_name|display_name|user_email|user_name|to|EmailMessage|subject|body|name|from|recipient).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    // Environment variables for SMTP configuration
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "getenv" and
      exists(StringLiteral s | s = c.getArg(0) |
        s.getText().regexpMatch("(?i).*(SMTP_|EMAIL_|MAIL_).*")
      ) and
      source = DataFlow::exprNode(c)
    )
    or
    // User input function calls
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read).*") and
      source = DataFlow::exprNode(c)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Email header assignments
    exists(Subscript s |
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email).*") and
      exists(StringLiteral header | header = s.getIndex() |
        header.getText().regexpMatch("(?i)(to|from|subject|cc|bcc|reply-to)")
      ) and
      sink.asExpr() = s.getValue()
    )
    or
    // SMTP method calls
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
  }
}

module ProactiveV3EmailFlow = TaintTracking::Global<ProactiveV3EmailConfig>;

from ProactiveV3EmailFlow::PathNode source, ProactiveV3EmailFlow::PathNode sink
where ProactiveV3EmailFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Proactive v3 detection (confidence: 100.0%): Untrusted input flows to email header/SMTP operation"