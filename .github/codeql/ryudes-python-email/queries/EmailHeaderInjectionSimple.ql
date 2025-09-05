/**
 * @name Email header injection
 * @description Detects untrusted data flowing into email headers or SMTP recipients
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.0
 * @precision high
 * @id ryudes/email-header-injection
 * @tags security
 *       external/cwe/cwe-117
 *       external/cwe/cwe-93
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
    or
    // Function parameters
    exists(DataFlow::ParameterNode param |
      source = param and
      param.getParameter().getName().regexpMatch("(?i)(user|input|name|email|recipient)")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // SMTP sendmail calls - second argument (to_addrs)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
      sink = call.getArg(1)
    )
    or
    // Simplified approach: Any assignment to a subscript where the value is from our source
    // This catches msg["To"] = tainted_value
    exists(DataFlow::CfgNode assign |
      assign.asCfgNode().getNode().(Assign).getValue() = sink.asCfgNode().getNode()
    )
  }
}

module EmailHeaderInjectionFlow = TaintTracking::Global<EmailHeaderInjectionConfig>;

from EmailHeaderInjectionFlow::PathNode source, EmailHeaderInjectionFlow::PathNode sink
where EmailHeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Email header injection vulnerability: $@ flows to email headers or SMTP calls.", source.getNode(), "untrusted data"
