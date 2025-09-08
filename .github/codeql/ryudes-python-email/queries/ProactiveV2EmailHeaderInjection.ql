/**
 * @name Email Header Injection via Order Parameters (Enhanced Proactive v2)
 * @description Enhanced proactive detection of email header injection vulnerabilities from order confirmation parameters, generated using learned corrections for first-attempt success.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113, proactive-v2, enhanced
 * @id py/proactive-v2-email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module ProactiveV2EmailConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    
    exists(Parameter p |
      p.getName().regexpMatch("(?i).*(display_name|order_id|from|body|name|shopper_name|user_name|customer_email|to|user_email|subject| email|shopper display name|recipient|email| display name|id|order|smtp_from).*") and
      source = DataFlow::parameterNode(p)
    )or
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "getenv" and
      exists(StringLiteral s | s = c.getArg(0) |
        s.getText().regexpMatch("(?i).*(EMAIL_FROM|SMTP_PORT|SMTP_HOST|MAIL_SERVER).*")
      ) and
      source = DataFlow::exprNode(c)
    )or
    exists(Call c |
      c.getFunc().(Name).getId().regexpMatch("(?i).*(input|get|recv|read|fetch).*") and
      source = DataFlow::exprNode(c)
    )or
    exists(Subscript s |
      s.getObject().(Name).getId().regexpMatch("(?i).*(request|params|form|data|args).*") and
      exists(StringLiteral key | key = s.getIndex() |
        key.getText().regexpMatch("(?i).*(display_name|order_id|from|body|name|shopper_name|user_name|customer_email|to|user_email|subject| email|shopper display name|recipient|email| display name|id|order|smtp_from).*")
      ) and
      source = DataFlow::exprNode(s)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    
    exists(Subscript s |
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email|mail).*") and
      exists(StringLiteral header | header = s.getIndex() |
        header.getText().regexpMatch("(?i)(to|from|subject|cc|bcc|reply-to|sender)")
      ) and
      sink.asExpr() = s.getValue()
    )or
    exists(Call c |
      c.getFunc() instanceof Attribute and
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(sendmail|send_message|send).*") and
      (sink.asExpr() = c.getArg(0) or sink.asExpr() = c.getArg(1))
    )or
    exists(Call c |
      c.getFunc().(Attribute).getAttr().regexpMatch("(?i).*(set_content|attach|add_header).*") and
      sink.asExpr() = c.getArg(0)
    )or
    exists(Call c |
      c.getFunc().(Attribute).getAttr() = "format" and
      exists(StringLiteral s | s = c.getFunc().(Attribute).getObject() |
        s.getText().regexpMatch("(?i).*(subject|to|from|hello|dear|order|confirmation).*")
      ) and
      sink.asExpr() = c.getArg(_)
    )
  }
}

module ProactiveV2EmailFlow = TaintTracking::Global<ProactiveV2EmailConfig>;

from ProactiveV2EmailFlow::PathNode source, ProactiveV2EmailFlow::PathNode sink
where ProactiveV2EmailFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Enhanced proactive detection: Untrusted input from order confirmation parameters flows to email headers or SMTP operations.", source, sink