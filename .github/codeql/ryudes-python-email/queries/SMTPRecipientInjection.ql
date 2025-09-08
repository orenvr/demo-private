/**
 * @name SMTP Recipient Envelope Injection
 * @description User input flows to SMTP sendmail recipient parameter, enabling recipient manipulation attacks
 * @kind problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113
 * @id py/smtp-recipient-envelope-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module SMTPRecipientConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(smtp_from|email|order_id|sender|customer_name|display_name|user_email|user_name|to|subject|body|name|from|recipient).*") and
      source = DataFlow::parameterNode(p)
    )
    or
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read).*") and
      source = DataFlow::exprNode(c)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message).*") and
      sink.asExpr() = c.getArg(1)  // Second argument is recipient list
    )
  }
}

module SMTPRecipientFlow = TaintTracking::Global<SMTPRecipientConfig>;

from SMTPRecipientFlow::PathNode source, SMTPRecipientFlow::PathNode sink
where SMTPRecipientFlow::flowPath(source, sink)
select sink.getNode(), "User input flows to SMTP recipient envelope from $@, enabling recipient manipulation", source.getNode(), "user parameter"
