/**
 * @name Untrusted data flows into email headers/SMTP (RyuDes) - Simple
 * @description Flags flows where untrusted input reaches email headers
 *              (To/Cc/Bcc/Subject/Reply-To) or SMTP recipient list without
 *              passing through recognized sanitizers/typed builders.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-74, external/cwe/cwe-93
 * @id py/ryudes-email-header-injection-simple
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** Activate only when emailservice code exists (feature/project scope). */
predicate intentActive() {
  exists(File f | f.getRelativePath().regexpMatch("^src/(emailservice|.*email).*\\.py$"))
}

/** Taint configuration for email header injection. */
private module EmailHeaderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Simple source: any parameter
    source = DataFlow::parameterNode(_)
  }

  predicate isSink(DataFlow::Node sink) {
    // Simple sink: any call to smtplib email sending functions
    exists(Call call |
      (call.getFunc().(Attribute).getAttr() = "sendmail" or
       call.getFunc().(Attribute).getAttr() = "send_message") and
      sink.asExpr() = call.getAnArg()
    )
  }
}

module EmailHeaderFlow = TaintTracking::Global<EmailHeaderConfig>;

from EmailHeaderFlow::PathNode source, EmailHeaderFlow::PathNode sink
where intentActive() and EmailHeaderFlow::flowPath(source, sink)
select sink.getNode(),
  "Untrusted input flows into an email header/SMTP without header-safe sanitization.",
  source, "Source here."