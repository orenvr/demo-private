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
import semmle.python.ApiGraphs as API

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
private predicate isHeaderSetCall(API::CallNode c) {
  // Message.__setitem__(header, value)  => msg["Header"] = value
  c = API::call("email.message.Message.__setitem__").getACall()
  or
  // Message.add_header("Header", value)
  c = API::call("email.message.Message.add_header").getACall()
}

private predicate isSmtpSendCall(API::CallNode c) {
  c = API::call("smtplib.SMTP.sendmail").getACall()
  or c = API::call("smtplib.LMTP.sendmail").getACall()
  or c = API::call("smtplib.SMTP.send_message").getACall()
  or c = API::call("smtplib.LMTP.send_message").getACall()
}

/** Acceptable header names (case-insensitive). */
private predicate interestingHeader(string h) {
  h.regexpMatch("(?i)^(to|cc|bcc|subject|reply-to)$")
}

/** Sanitizers: reject CR/LF; typed Address builders; project sanitizer. */
predicate isSanitizedExpr(Expr e) {
  // Project sanitizer (local function)
  exists (API::CallNode c |
    c.getCallee().getName() = "sanitize_header" and c.getArgument(0).asExpr() = e
  )
  or
  // Typed header builders: headerregistry.Address/Group
  exists (API::CallNode c |
    (c = API::call("email.headerregistry.Address").getACall() or
     c = API::call("email.headerregistry.Group").getACall())
    and e = c.asExpr()
  )
  or
  // Regex guard that (crudely) does not allow \r or \n
  exists (API::CallNode c |
    c = API::call("re.fullmatch").getACall() and
    // re.fullmatch(pattern, string)
    c.getArgument(1).asExpr() = e and
    not c.getArgument(0).toString().regexpMatch("\\\\r|\\\\n")
  )
}

/** Taint configuration tying sources/sinks/sanitizers together. */
class EmailHeaderCfg extends TaintTracking::Configuration {
  EmailHeaderCfg() { this = "ryudes-email-header" }

  override predicate isSource(DataFlow::Node n) {
    // Heuristic request/payload/data/json symbols
    exists(Expr e | looksLikeRequestish(e) and n = TaintTracking::exprNode(e))
    or
    // Email-ish parameter names
    exists(Parameter p | hasEmailishParamName(p) and n = TaintTracking::parameterNode(p))
  }

  override predicate isSink(DataFlow::Node n) {
    // msg["Hdr"] = value  OR  msg.add_header("Hdr", value)
    exists (API::CallNode c |
      isHeaderSetCall(c) and
      // header name in arg0, value in arg1
      n.asExpr() = c.getArgument(1).asExpr() and
      exists (string h | c.getArgument(0).toString() = h and interestingHeader(h))
    )
    or
    // SMTP recipients
    exists (API::CallNode c |
      isSmtpSendCall(c) and
      (
        // sendmail(from_addr, to_addrs, msg)
        n.asExpr() = c.getArgument(1).asExpr()
        or
        // send_message(msg, from_addr=None, to_addrs=None)
        n.asExpr() = c.getKwArgument("to_addrs").asExpr()
      )
    )
  }

  override predicate isSanitizer(DataFlow::Node n) {
    exists (Expr e | n = TaintTracking::exprNode(e) and isSanitizedExpr(e))
  }
}

/** Report flows only when the feature/project scope is present. */
from EmailHeaderCfg cfg, DataFlow::PathNode src, DataFlow::PathNode snk
where intentActive() and cfg.hasFlowPath(src, snk)
select snk.getNode(),
  "Untrusted input flows into an email header/SMTP without header-safe sanitization.",
  src, "Source here."
