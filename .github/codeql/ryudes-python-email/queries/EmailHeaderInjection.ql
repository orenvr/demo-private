/**
 * @name Untrusted data flows into email headers/SMTP (RyuDes)
 * @description Flags flows where untrusted input reaches email headers
 *              (To/Cc/Bcc/Subject/Reply-To) or SMTP recipient list without
 *              passing through recognized sanitizers/typed builders.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-74, external/cwe/cwe-93
 * @id py/ryudes-email-header-injection
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs
private import semmle.python.ApiGraphs as API

/** Activate only when emailservice code exists (feature/project scope). */
predicate intentActive() {
  exists(File f | f.getRelativePath().regexpMatch("^src/(emailservice|.*email).*\\.py$"))
}

/** Heuristic: parameter names commonly used for people/addresses. */
private predicate hasEmailishParamName(Parameter p) {
  p.getName().regexpMatch("^(name|to_name|email|to_email|display_name|recipient)$")
}

/** Heuristic: expression text hints at request/payload-like data. */
private predicate looksLikeRequestish(Expr e) {
  e.toString().regexpMatch("(?i)(request|payload|body|data|json)")
}

/** Sinks: Email header setters and SMTP recipient arguments, modeled via API Graphs. */
private predicate isHeaderSetCall(DataFlow::CallCfgNode c) {
  // Message.__setitem__(header, value)  => msg["Header"] = value
  c = API::moduleImport("email").getMember("message").getMember("Message").getASubclass*().getMember("__setitem__").getACall()
  or
  // Message.add_header("Header", value)
  c = API::moduleImport("email").getMember("message").getMember("Message").getASubclass*().getMember("add_header").getACall()
}

private predicate isSmtpSendCall(DataFlow::CallCfgNode c) {
  c = API::moduleImport("smtplib").getMember("SMTP").getASubclass*().getMember("sendmail").getACall()
  or c = API::moduleImport("smtplib").getMember("LMTP").getASubclass*().getMember("sendmail").getACall()
  or c = API::moduleImport("smtplib").getMember("SMTP").getASubclass*().getMember("send_message").getACall()
  or c = API::moduleImport("smtplib").getMember("LMTP").getASubclass*().getMember("send_message").getACall()
}

/** Acceptable header names (case-insensitive). */
private predicate interestingHeader(string h) {
  h.regexpMatch("(?i)^(to|cc|bcc|subject|reply-to)$")
}

/** Sanitizers: reject CR/LF; typed Address builders; project sanitizer. */
predicate isSanitizedExpr(Expr e) {
  // Project sanitizer (local function)
  exists (DataFlow::CallCfgNode c |
    c.getFunction().getName() = "sanitize_header" and c.getArg(0).asExpr() = e
  )
  or
  // Typed header builders: headerregistry.Address/Group
  exists (DataFlow::CallCfgNode c |
    (c = API::moduleImport("email").getMember("headerregistry").getMember("Address").getACall() or
     c = API::moduleImport("email").getMember("headerregistry").getMember("Group").getACall())
    and e = c.asExpr()
  )
  or
  // Regex guard that (crudely) does not allow \r or \n
  exists (DataFlow::CallCfgNode c |
    c = API::moduleImport("re").getMember("fullmatch").getACall() and
    // re.fullmatch(pattern, string)
    c.getArg(1).asExpr() = e and
    not c.getArg(0).toString().regexpMatch("\\\\r|\\\\n")
  )
}

/** Taint configuration tying sources/sinks/sanitizers together. */
module EmailHeaderConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    // Heuristic request/payload/data/json symbols
    exists(Expr e | looksLikeRequestish(e) and n.asExpr() = e)
    or
    // Email-ish parameter names
    exists(Parameter p | hasEmailishParamName(p) and n.asParameter() = p)
  }

  predicate isSink(DataFlow::Node n) {
    // msg["Hdr"] = value  OR  msg.add_header("Hdr", value)
    exists (DataFlow::CallCfgNode c |
      isHeaderSetCall(c) and
      // header name in arg0, value in arg1
      n = c.getArg(1) and
      exists (string h | c.getArg(0).toString() = h and interestingHeader(h))
    )
    or
    // SMTP recipients
    exists (DataFlow::CallCfgNode c |
      isSmtpSendCall(c) and
      (
        // sendmail(from_addr, to_addrs, msg)
        n = c.getArg(1)
        or
        // send_message(msg, from_addr=None, to_addrs=None)
        n = c.getArgByName("to_addrs")
      )
    )
  }

  predicate isSanitizer(DataFlow::Node n) {
    exists (Expr e | n.asExpr() = e and isSanitizedExpr(e))
  }
}

module EmailHeaderFlow = TaintTracking::Global<EmailHeaderConfig>;

/** Report flows only when the feature/project scope is present. */
from DataFlow::PathNode src, DataFlow::PathNode snk
where intentActive() and EmailHeaderFlow::flowPath(src, snk)
select snk.getNode(),
  "Untrusted input flows into an email header/SMTP without header-safe sanitization.",
  src, "Source here."
