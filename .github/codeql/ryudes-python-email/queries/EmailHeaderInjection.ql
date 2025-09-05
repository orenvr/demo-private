/**
 * @name Email  override predicate isSource(DataFlow::Node source) {
    // Environment variables - primary attack vector
    exists(DataFlow::CallCfgNode call, DataFlow::ModuleVariableNode moduleVar |
      source = call and
      call.getFunction().(DataFlow::AttrRead).getObject() = moduleVar and
      moduleVar.getVariable().getId() = "os" and
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "environ"
    )
    or
    // os.getenv() calls
    exists(DataFlow::CallCfgNode call, DataFlow::ModuleVariableNode moduleVar |
      source = call and
      call.getFunction().(DataFlow::AttrRead).getObject() = moduleVar and
      moduleVar.getVariable().getId() = "os" and
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "getenv"
    )
    oron
 * @description Detects untrusted data flowing into email headers or SMTP recipient lists
 * @kind path-problem
 * @id ryudes/email-header-injection
 * @severity error
 * @security-severity 5.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-117
 *       external/cwe/cwe-93
 */

import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import python

module EmailHeaderInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Environment variables - primary attack vector
    exists(DataFlow::CallCfgNode call, DataFlow::ModuleVariableNode moduleVar |
      source = call and
      call.getFunction().(DataFlow::AttrRead).getObject() = moduleVar and
      moduleVar.getVariable().getId() = "os" and
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "environ"
    )
    or
    // os.getenv() calls
    exists(DataFlow::CallCfgNode call, DataFlow::ModuleVariableNode moduleVar |
      source = call and
      call.getFunction().(DataFlow::AttrRead).getObject() = moduleVar and
      moduleVar.getVariable().getId() = "os" and
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "getenv"
    )
    or
    // input() function calls
    exists(DataFlow::CallCfgNode call |
      source = call and
      call.getFunction().asExpr().(Name).getId() = "input"
    )
    or
    // Function parameters with email-related names
    exists(DataFlow::ParameterNode param |
      source = param and
      param.getParameter().getName().regexpMatch("(?i)(name|email|recipient|addr|address|to|from|subject)")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // SMTP sendmail calls - recipients argument (position 1)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "sendmail" and
      sink = call.getArg(1)
    )
    or
    // SMTP send_message calls - message argument (position 0)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "send_message" and
      sink = call.getArg(0)
    )
    or
    // Email header assignments: msg["To"] = value (the value is the sink)
    exists(AssignStmt assign, Subscript target |
      assign.getATarget() = target and
      DataFlow::exprNode(assign.getValue()) = sink and
      target.getIndex().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender|return-path)")
    )
    or
    // Header method calls: msg.add_header("To", value) (the value is the sink)
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() = "add_header" and
      sink = call.getArg(1) and
      call.getArg(0).asExpr().(StringLiteral).getText().regexpMatch("(?i)(to|cc|bcc|from|reply-to|sender|return-path)")
    )
  }
}

module EmailHeaderInjectionFlow = TaintTracking::Global<EmailHeaderInjectionConfig>;

from EmailHeaderInjectionFlow::PathNode source, EmailHeaderInjectionFlow::PathNode sink
where EmailHeaderInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Email header injection vulnerability: $@ flows to email headers or SMTP calls.", source.getNode(), "untrusted data"
