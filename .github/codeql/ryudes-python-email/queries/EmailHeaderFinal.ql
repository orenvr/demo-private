/**
 * @name Email header injection
 * @description Detects untrusted data flowing into email headers or SMTP recipients  
 * @kind path-problem
 * @problem.severity error
 * @id ryudes/email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module EmailHeaderInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // os.environ.get() calls
    exists(DataFlow::CallCfgNode call |
      source = call and
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "get" and
      call.getFunction().(DataFlow::AttrRead).getObject().(DataFlow::AttrRead).getAttributeName() = "environ"
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // SMTP sendmail - recipient argument
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
      sink = call.getArg(1)
    )
    or
    // Email header assignment: msg["To"] = value (the value is the sink)
    exists(AssignStmt assign, Subscript target |
      assign.getATarget() = target and
      DataFlow::exprNode(assign.getValue()) = sink and
      target.getIndex().(StringLiteral).getText() = "To"
    )
  }
}

module EmailHeaderInjectionFlow = TaintTracking::Global<EmailHeaderInjectionConfig>;

from EmailHeaderInjectionFlow::PathNode source, EmailHeaderInjectionFlow::PathNode sink
where EmailHeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Email header injection: $@ flows to email headers or SMTP.", source.getNode(), "untrusted data"
