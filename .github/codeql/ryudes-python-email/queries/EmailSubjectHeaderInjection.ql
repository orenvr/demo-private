/**
 * @name Email Subject Header Injection
 * @description User input flows to email 'Subject' header field, enabling subject manipulation attacks
 * @kind problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113
 * @id py/email-subject-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EmailSubjectHeaderConfig implements DataFlow::ConfigSig {
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
    exists(Subscript s, StringLiteral header |
      s.getObject().toString().regexpMatch("(?i).*(msg|message|email).*") and
      header = s.getIndex() and
      header.getText().regexpMatch("(?i)subject") and
      sink.asExpr() = s.getValue()
    )
  }
}

module EmailSubjectHeaderFlow = TaintTracking::Global<EmailSubjectHeaderConfig>;

from EmailSubjectHeaderFlow::PathNode source, EmailSubjectHeaderFlow::PathNode sink
where EmailSubjectHeaderFlow::flowPath(source, sink)
select sink.getNode(), "User input flows to email 'Subject' header from $@, enabling subject manipulation", source.getNode(), "user parameter"
