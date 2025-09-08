/**
 * @name Email Header Injection via Order Confirmation Parameters (Proactive)
 * @description Detects untrusted input from order confirmation parameters flowing into email headers and SMTP operations. Generated proactively from agent instructions without seeing implementation code.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, proactive-synthesis
 * @id py/proactive-email-header-injection-order-confirmation
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module ProactiveEmailHeaderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Order confirmation specific parameters (predicted from agent instructions)
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(display_name|email|order_id|user_name|recipient|shopper_name|customer_email|smtp_from|from|to|subject|body|name).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    // Environment variables for SMTP configuration (from agent instructions)
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "getenv" and
      exists(StringLiteral s | s = c.getArg(0) |
        s.getText().regexpMatch("(?i).*(SMTP_HOST|SMTP_PORT|EMAIL_.*|MAIL_.*)")
      ) and
      source = DataFlow::exprNode(c)
    )
    or
    // Dictionary/request parameter access (web context)
    exists(Subscript s |
      s.getObject().(Name).getId().regexpMatch("(?i).*(request|params|form|data).*") and
      exists(StringLiteral key | key = s.getIndex() |
        key.getText().regexpMatch("(?i).*(name|email|order|display|recipient)")
      ) and
      source = DataFlow::exprNode(s)
    )
    or
    // Function calls that retrieve user input
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(get|input|recv|read|fetch).*") and
      source = DataFlow::exprNode(c)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Email header assignment (predicted pattern from requirements)
    exists(Subscript s |
      // Match email message objects (msg, message, email_msg, etc.)
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email|mail).*") and
      // Match email headers mentioned in requirements: To, Subject
      exists(StringLiteral header | header = s.getIndex() |
        header.getText().regexpMatch("(?i)(to|from|subject|cc|bcc|reply-to|sender)")
      ) and
      sink.asExpr() = s.getValue()
    )
    or
    // SMTP method calls (sendmail, send_message from requirements)
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message|send).*") and
      // Check first two arguments (typical SMTP envelope fields)
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )
    or
    // Email message constructor calls
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(set_content|attach|add_header).*") and
      sink.asExpr() = c.getArg(0)
    )
    or
    // String formatting in email context (f-strings, format calls)
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "format" and
      // Check if the base string contains email-related keywords
      exists(StringLiteral s | s = c.getFunc().(Attribute).getObject() |
        s.getText().regexpMatch("(?i).*(subject|to|from|hello|dear|order).*")
      ) and
      sink.asExpr() = c.getArg(_)
    )
  }
}

module ProactiveEmailHeaderFlow = TaintTracking::Global<ProactiveEmailHeaderConfig>;

from ProactiveEmailHeaderFlow::PathNode source, ProactiveEmailHeaderFlow::PathNode sink
where ProactiveEmailHeaderFlow::flowPath(source, sink)
select sink.getNode(), source, sink, 
  "Proactive Detection: Untrusted input from order confirmation parameter '" + 
  source.getNode().toString() + "' flows to email header/SMTP operation at '" + 
  sink.getNode().toString() + "'. This vulnerability was predicted from agent instructions before code implementation."
