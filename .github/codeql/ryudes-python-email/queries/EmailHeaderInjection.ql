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
import DataFlow::PathGraph
import semmle.python.security.dataflow.Sources
import semmle.python.security.dataflow.TaintTracking

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
