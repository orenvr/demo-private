/**
 * @name Untrusted input in email header or SMTP envelope
 * @description Flags untrusted input from function parameters flowing into email headers or SMTP envelope fields, even through intermediate variables and function calls.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113
 * @id py/untrusted-email-header-or-envelope
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EmailHeaderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Environment variable sources (as mentioned in PR success)
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "getenv" and
      source = DataFlow::exprNode(c)
    )
    or
    // Function parameter sources with suspicious names  
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(name|email|order_id|body|from|to|display_name|recipient|user_name|user_email|smtp_from).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    // Function call sources (user input sources mentioned in PR)
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read).*") and
      source = DataFlow::exprNode(c)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Email header assignment sinks: msg["Header"] = value
    exists(Subscript s |
      sink.asExpr() = s.getValue()
    )
    or
    // SMTP sink detection: sendmail methods (as mentioned in PR success)
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
  }
}

module EmailHeaderFlow = TaintTracking::Global<EmailHeaderConfig>;

from EmailHeaderFlow::PathNode source, EmailHeaderFlow::PathNode sink
where EmailHeaderFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted input flows into an email header or SMTP envelope field."
