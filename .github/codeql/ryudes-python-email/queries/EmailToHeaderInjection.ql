/**
 * @name Email To Header Injection
 * @description User input flows to email 'To' header field, enabling recipient manipulation attacks
 * @kind problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-93, external/cwe/cwe-113
 * @id py/email-to-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EmailToHeaderConfig implements DataFlow::ConfigSig {
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
      header.getText().regexpMatch("(?i)to") and
      sink.asExpr() = s.getValue()
    )
  }
}

module EmailToHeaderFlow = TaintTracking::Global<EmailToHeaderConfig>;

from EmailToHeaderFlow::PathNode source, EmailToHeaderFlow::PathNode sink
where EmailToHeaderFlow::flowPath(source, sink)
select sink.getNode(), "User input flows to email 'To' header from $@, enabling recipient manipulation", source.getNode(), "user parameter"
