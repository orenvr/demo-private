/**
 * @name Untrusted data flows into email headers/SMTP (RyuDes)
 * @description Flags flows where untrusted input reaches email headers
 *              (To/Cc/Bcc/Subject/Reply-To) or SMTP recipient list without
 *              passing through recognized sanitizers/typed builders.
 * @kind path-problem
 * @problem.severity error
 * @tags security, external/cwe/cwe-74, external/cwe/cwe-93
 * @id py/ryudes-email-header-injection/**
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

/** Heuristic source: parameter names commonly used for people/addresses. */
private predicate hasEmailishParamName(Parameter p) {
  ["name", "to_name", "email", "to_email", "display_name", "recipient"].any(p.getName())
}

/** Heuristic source: expression text hints at request/payload. */
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
  // Project sanitizer (customize if you have a different name)
  exists(API::CallNode c |
    c.getCallee().getName() = "sanitize_header" and c.getArgument(0).asExpr() = e
  )
  or
  // Typed header builders: headerregistry.Address/Group
  exists(API::CallNode c |
    c = API::call("email.headerregistry.Address").getACall() and e = c.asExpr()
    or
    c = API::call("email.headerregistry.Group").getACall() and e = c.asExpr()
  )
  or
  // Regex guard that (crudely) does not allow \r or \n
  exists(API::CallNode c |
    c = API::call("re.fullmatch").getACall() and
    c.getArgument(1).asExpr() = e and
    // pattern is arg0; reject obvious CR/LF allowance
    not c.getArgument(0).toString().regexpMatch("\\\\r|\\\\n")
  )
}

/** Taint configuration tying sources/sinks/sanitizers together. */
class EmailHeaderCfg extends TaintTracking::Configuration {
  EmailHeaderCfg() { this = "ryudes-email-header" }

  override predicate isSource(DataFlow::Node n) {
    // CLI args
    n = TaintTracking::exprNode(Sources::CommandLineArgument().getAnAccess())
    or
    // Heuristic request/payload/data/json symbols
    exists(Expr e | looksLikeRequestish(e) and n = TaintTracking::exprNode(e))
    or
    // Email-ish parameter names
    exists(Parameter p | hasEmailishParamName(p) and n = TaintTracking::parameterNode(p))
  }

  override predicate isSink(DataFlow::Node n) {
    // msg["Hdr"] = value  OR  msg.add_header("Hdr", value)
    exists(API::CallNode c |
      isHeaderSetCall(c) and
      // header name in arg0, value in arg1
      n.asExpr() = c.getArgument(1).asExpr() and
      exists(string h | c.getArgument(0).toString() = h and interestingHeader(h))
    )
    or
    // SMTP recipients
    exists(API::CallNode c |
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
    exists(Expr e | n = TaintTracking::exprNode(e) and isSanitizedExpr(e))
  }
}

/** Report flows only when the feature/project scope is present. */
from EmailHeaderCfg cfg, DataFlow::PathNode src, DataFlow::PathNode snk
where intentActive() and cfg.hasFlowPath(src, snk)
select snk.getNode(),
  "Untrusted input flows into an email header/SMTP without header-safe sanitization.",
  src, "Source here."

 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs


/** Activate only when emailservice code exists (feature/project scope).
 *  You can tighten/loosen this later. */
predicate intentActive() {
  exists(File f | f.getRelativePath().regexpMatch("^src/(emailservice|.*email).*\\.py$"))
}

/** Sources: CLI args, HTTP/JSON-like payloads, and common email/name parameters. */
class Src extends TaintTracking::SourceNode {
  Src() {
    // CLI / argv
    this = Sources::CommandLineArgument()
    or
    // Heuristic: values coming from request/payload/data/json dicts
    exists(Expr e |
      e.toString().regexpMatch("(?i)(request|payload|body|data|json)") and
      this = TaintTracking::exprNode(e)
    )
    or
    // Parameters with typical names
    exists(Parameter p |
      ["name", "to_name", "email", "to_email", "display_name", "recipient"].any(p.getName()) and
      this = TaintTracking::parameterNode(p)
    )
  }
}

/** Sinks: header assignment/add_header, raw MIME header strings, SMTP recipients. */
class Snk extends TaintTracking::SinkNode {
  Snk() {
    // msg["To"] = value (and friends)
    exists(IndexExpr ie, Expr val |
      ie.getQualifier().getType().hasQualifiedName("email.message", "Message") and
      ie.getIndex().toString().regexpMatch("(?i)^(\"?)(to|cc|bcc|subject|reply-to)\\1$") and
      // value is the RHS of the assignment
      exists(Assign a | a.getAnAssignedValue() = val and a.getTarget() = ie) and
      this = TaintTracking::exprNode(val)
    )
    or
    // msg.add_header("To", value)
    exists(Call c |
      c.getFunc().toString().regexpMatch("\\.add_header$") and
      c.getArgument(0).toString().regexpMatch("(?i)^(\"?)(to|cc|bcc|subject|reply-to)\\1$") and
      this = TaintTracking::exprNode(c.getArgument(1))
    )
    or
    // Raw MIME: "Bcc: {user}" or format strings building header lines
    exists(Expr s |
      s.toString().regexpMatch("(?s)(^|\\n)(To|Cc|Bcc|Subject|Reply-To):\\s*.*\\{.*\\}") and
      this = TaintTracking::exprNode(s)
    )
    or
    // smtplib SMTP recipients (bcc spray)
    exists(Call c |
      c.getFunc().getQualifiedName().regexpMatch("smtplib\\.(SMTP|LMTP)\\.(sendmail|send_message)$") and
      (
        // sendmail(from_addr, to_addrs, msg)
        this = TaintTracking::exprNode(c.getArgument(1))
        or
        // send_message(msg, from_addr=None, to_addrs=None)
        this = TaintTracking::exprNode(c.getKwArgument("to_addrs"))
      )
    )
  }
}

/** Sanitizers: reject CR/LF; typed Address builders; project sanitizer function. */
predicate isSanitized(Expr e) {
  // Project sanitizer (if you add one)
  exists(Call c | c.getFunc().getName() = "sanitize_header" and c.getArgument(0) = e)
  or
  // Typed header builders are considered safe
  exists(Call c |
    c.getFunc().getQualifiedName().matches("email\\.headerregistry\\.(Address|Group)") and
    e = c
  )
  or
  // Regex-based CR/LF guard (common pattern)
  exists(Call c |
    c.getFunc().getQualifiedName().matches("re\\.fullmatch") and
    c.getArgument(0) = e and
    // crude check that pattern does not allow \r or \n
    not c.getAnArgument().toString().regexpMatch("\\\\r|\\\\n")
  )
}

/** Taint config ties it all together. */
class Cfg extends TaintTracking::Configuration {
  Cfg() { this = "ryudes-email-header" }

  override predicate isSource(Node n) { n instanceof Src }
  override predicate isSink(Node n)   { n instanceof Snk }
  override predicate isSanitizer(Node n) {
    exists(Expr e | n = TaintTracking::exprNode(e) and isSanitized(e))
  }
}

/** Report flows only when the feature/project scope is present. */
from Cfg cfg, DataFlow::PathNode s, DataFlow::PathNode t
where intentActive() and cfg.hasFlowPath(s, t)
select t, "Untrusted input flows into an email header/SMTP without header-safe sanitization.", s, "Source here."
