/**
 * @name Email Header Injection Detection (Enhanced v2.1 - Detailed Alerts)
 * @description Detailed email header injection detection with specific alert types
 * @kind problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, enhanced-v2-1
 * @id py/enhanced-v2-1-email-header-injection-detailed
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

from EnhancedV21EmailFlow::PathNode source, EnhancedV21EmailFlow::PathNode sink, string alertType, string specificMessage
where 
  EnhancedV21EmailFlow::flowPath(source, sink) and
  (
    // EMAIL HEADER INJECTION ALERTS
    (
      exists(Subscript s, StringLiteral header |
        s = sink.getNode().asExpr() and
        s.getObject().toString().regexpMatch("(?i).*(msg|message|email).*") and
        header = s.getIndex() and
        (
          (header.getText().regexpMatch("(?i)to") and alertType = "Email-To-Header-Injection" and specificMessage = "User input flows to email 'To' header - enables recipient manipulation") or
          (header.getText().regexpMatch("(?i)subject") and alertType = "Email-Subject-Header-Injection" and specificMessage = "User input flows to email 'Subject' header - enables subject manipulation") or
          (header.getText().regexpMatch("(?i)from") and alertType = "Email-From-Header-Injection" and specificMessage = "User input flows to email 'From' header - enables sender spoofing") or
          (header.getText().regexpMatch("(?i)(cc|bcc)") and alertType = "Email-CC-BCC-Header-Injection" and specificMessage = "User input flows to email CC/BCC headers - enables recipient injection") or
          (header.getText().regexpMatch("(?i)reply") and alertType = "Email-Reply-Header-Injection" and specificMessage = "User input flows to email 'Reply-To' header - enables reply hijacking")
        )
      )
    ) or
    // SMTP ENVELOPE INJECTION ALERTS  
    (
      exists(Call c |
        c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
        (
          (sink.getNode().asExpr() = c.getArg(0) and alertType = "SMTP-Sender-Envelope-Injection" and specificMessage = "User input flows to SMTP sender envelope - enables sender spoofing") or
          (sink.getNode().asExpr() = c.getArg(1) and alertType = "SMTP-Recipient-Envelope-Injection" and specificMessage = "User input flows to SMTP recipient envelope - enables recipient manipulation")
        )
      )
    )
  )
select sink.getNode(), alertType + ": " + specificMessage + " from $@", source.getNode(), "user input (" + source.getNode().asExpr().toString() + ")"
