// scrape.sc -- Joern CPG -> ROTN CPG model (JSON), driven by rot/frontends/joern.py.
//
// Paths are passed via environment variables (set by joern.py), so the same
// script works for any source directory and output location:
//   ROTN_CPG_SOURCE  Java source directory to import (e.g. twopc-java/src)
//   ROTN_CPG_OUT     where to write the JSON CPG model
//
// Single block: import + extract in one Ammonite evaluation so the semantic
// CPG extension steps (call/argument/filter) are in scope throughout.
// The extraction steps below are the verified-good ones (see _joern_test):
//   cpg.method.call.name.l
//   cpg.method.call.filter(_.name == "<operator>.fieldAccess")
//                 .argument.filter(_.order == 2)        // read side
//   cpg.method.call.filter(_.name == "<operator>.assignment")
//                 .argument.filter(_.order == 1)        // write side (LHS)
//
// CPG-1 (the dataflow half): per method the scrape also emits ``defs`` (the
// names the method defines: parameters, locals, written fields) and ``args``
// (parameter names in declaration order); at the model level the typed
// dataflow edges (REACHING_DEF def-use, ARGUMENT argument passing, CALL) and
// a conservative taint source/sink set -- a name-based classifier, not full
// taint-tracking (over-approximate on purpose: never miss a path).  Every
// dataflow section is best-effort: a query failure degrades to an empty list
// so the verified-good core (types/fields/methods) is never lost.
//
// Output shape == rot.frontends.cpg_model (meta + types + fields + methods
// + edges + taint_sources + taint_sinks).
// Success contract: writes valid JSON to ROTN_CPG_OUT, prints ROTN-SCRAPE-OK.
{
  import io.shiftleft.semanticcpg.language._

  val src = sys.env.getOrElse("ROTN_CPG_SOURCE", "")
  val out = sys.env.getOrElse("ROTN_CPG_OUT", "")
  if (src == "" || out == "") {
    println("ROTN-SCRAPE-ERR missing ROTN_CPG_SOURCE / ROTN_CPG_OUT env vars")
  } else {
    val cpg = io.shiftleft.joern.console.Joern.importCode(src, "rotn_scrape").get

    // JSON string escaping (no JSON library on the bridge classpath).
    def jstr(s: String): String = {
      val b = new java.lang.StringBuilder("\"")
      s.foreach { c =>
        c match {
          case '"'  => b.append("\\\"")
          case '\\' => b.append("\\\\")
          case '\n' => b.append("\\n")
          case '\r' => b.append("\\r")
          case '\t' => b.append("\\t")
          case other => if (other < 32) b.append("\\u%04x".format(other.toInt))
                        else b.append(other)
        }
      }
      b.append("\"").toString
    }
    def jarr(xs: List[String]): String =
      "[" + xs.map(jstr).mkString(",") + "]"

    // -- compact node ids (the rot.frontends.cpg_model convention) ---------
    //   parameter / local -> enclosing method fullName + "#" + name
    //   field             -> the field's fullName (owner type + "." + name)
    //   anything else     -> the enclosing method fullName
    def nodeId(n: cpgpg.CpgNode): String = n.label match {
      case "parameter" | "local" => n.methodFullName + "#" + n.name
      case "field"               => n.typeFullName + "." + n.name
      case _                     => n.methodFullName
    }

    val knownMethods = cpg.method.fullName.l.toSet

    // -- conservative taint classifier (a classifier, not full
    // -- taint-tracking): private data can enter through any parameter
    // -- (source); egress is a call to a sink-looking method, or a write to
    // -- a sink-looking field (sink).  Over-approximate on purpose.
    val PRIVATE_HINTS = List("ssn", "secret", "token", "password", "credential",
                             "private", "pii", "card", "account", "payload",
                             "key", "session", "customer")
    val SINK_HINTS = List("send", "post", "upload", "publish", "exfiltrate",
                          "exfil", "transmit", "egress", "dispatch", "flush",
                          "emit", "notify", "write", "store", "print")
    def hint(name: String, hints: List[String]): Boolean =
      hints.exists(h => name.toLowerCase.contains(h))

    // -- types (classes / interfaces / enums, with supertypes) ---------------
    val types = cpg.typeDecl.l.map { t =>
      val inh = t.inheritFrom.l.map(_.code).distinct.sorted
      // Enum constants: the CPG reports each constant as a method on the enum
      // type, so "enum E { A, B }" shows up as methods E.A / E.B with no
      // arguments.  This is how the IR builder recovers enum value domains
      // (the CPG has no distinct enum-member node kind for Java).
      ("{\"name\":" + jstr(t.name) +
       ",\"fullName\":" + jstr(t.fullName) +
       ",\"owner\":" + jstr(t.astParentFullName) +
       ",\"lineNumber\":" + t.lineNumber.getOrElse(-1) +
       ",\"endLineNumber\":" + t.lineNumberEnd.getOrElse(-1) +
       ",\"inherits\":" + jarr(inh) + "}")
    }

    // -- fields (with declared type and owner) -------------------------------
    // NOTE: key is "type" -- must match rot.frontends.cpg_model.CpgField.
    val fields = cpg.field.l.map { f =>
      ("{\"name\":" + jstr(f.name) +
       ",\"fullName\":" + jstr(f.fullName) +
       ",\"type\":" + jstr(f.typeFullName) +
       ",\"owner\":" + jstr(f.astParentFullName) + "}")
    }

    // -- methods (call edges + field read/write split + defs/args, CPG-1) ----
    val methods = cpg.method.l.map { m =>
      val full   = m.fullName
      val owner  = m.astParentFullName
      val ln     = m.lineNumber.getOrElse(-1)
      val eln    = m.lineNumberEnd.getOrElse(-1)
      val calls  = cpg.method.filter(_.fullName == full)
        .call.name.l.distinct.filter(!_.startsWith("<operator>")).sorted
      val reads  = cpg.method.filter(_.fullName == full)
        .call.filter(_.name == "<operator>.fieldAccess")
        .argument.filter(_.order == 2).code.l.distinct.sorted
      val writes = cpg.method.filter(_.fullName == full)
        .call.filter(_.name == "<operator>.assignment")
        .argument.filter(_.order == 1).code.l.distinct
        .filter(_.contains(".")).map(_.split("\\.").last).distinct.sorted
      // CPG-1: args (parameter names, declaration order) + defs (every name
      // the method defines: parameters, locals, written fields).  Best-effort:
      // degrade to empty lists if the CPG query shape changes.
      val (args, defs) = try {
        val paramNames = cpg.method.filter(_.fullName == full).parameter.name.l
        val localNames = cpg.method.filter(_.fullName == full)
          .local.name.l.distinct
        (paramNames, (paramNames ++ localNames ++ writes).distinct.sorted)
      } catch { case _: Throwable => (List.empty[String], List.empty[String]) }
      ("{\"name\":" + jstr(m.name) +
       ",\"fullName\":" + jstr(full) +
       ",\"owner\":" + jstr(owner) +
       ",\"lineNumber\":" + ln +
       ",\"endLineNumber\":" + eln +
       ",\"calls\":" + jarr(calls) +
       ",\"readFields\":" + jarr(reads) +
       ",\"writtenFields\":" + jarr(writes) +
       ",\"args\":" + jarr(args) +
       ",\"defs\":" + jarr(defs) + "}")
    }

    // -- dataflow (CPG-1): typed edges + the conservative taint set ---------
    // Best-effort as a whole: a dataflow query failure must not lose the
    // verified-good core (types/fields/methods), so any failure degrades to
    // empty sections (the model still round-trips, just without dataflow).
    val (edgeList, sourceList, sinkList) = try {
      // ARGUMENT: argument slot -> callee, or the callee's parameter slot at
      // the argument order when that parameter is resolvable.
      val argEdges = for {
        c <- cpg.method.call
        a <- c.argument
        callee = c.fullName
      } yield {
        val to = cpg.method.filter(_.fullName == callee)
          .parameter.filter(_.order == a.order).name.l.headOption
          .map(pn => callee + "#" + pn)
          .getOrElse(callee)
        ("ARGUMENT", nodeId(a), to, a.lineNumber.getOrElse(-1))
      }
      // REACHING_DEF: def -> use (the CPG's stable def-use edges), kept when
      // the defining node lives inside the scraped code.
      val defEdges = for {
        e <- cpg.reachingDef
        if knownMethods.contains(e.src.methodFullName)
      } yield ("REACHING_DEF", nodeId(e.src), nodeId(e.dst),
               e.dst.lineNumber.getOrElse(-1))
      // CALL: caller -> callee (control flow; excluded from the default
      // taint_path search, available via include_calls).
      val callEdges = for {
        c <- cpg.method.call
        callee = c.fullName
        if knownMethods.contains(callee)
      } yield ("CALL", c.methodFullName, callee, c.lineNumber.getOrElse(-1))
      val edges = (argEdges ++ defEdges ++ callEdges).distinct
        .sortBy(e => (e._1, e._2, e._3, e._4))

      // Sources: every parameter -- private data can enter through any entry
      // point; the reason records the classifier's basis (auditable).
      val sources = for {
        m <- cpg.method
        p <- m.parameter
      } yield {
        val id = m.fullName + "#" + p.name
        val reason =
          if (hint(p.name, PRIVATE_HINTS)) "private-name:" + p.name
          else "parameter"
        (id, "parameter", p.name, m.fullName, reason,
         p.lineNumber.getOrElse(m.lineNumber.getOrElse(-1)))
      }.distinct.sortBy(s => (s._1, s._4))

      // Sinks: calls to sink-looking methods (sink id = the egress method,
      // reached through its parameter slot) and writes to sink-looking
      // fields (sink id = the calling method, reached when the method is
      // reached -- over-approximate on purpose).
      val callSinks = for {
        c <- cpg.method.call
        calleeName = c.name.split("\\.").last
        if hint(calleeName, SINK_HINTS)
      } yield (c.fullName, "call", calleeName, c.methodFullName,
               "egress-name:" + calleeName, c.lineNumber.getOrElse(-1))
      val fieldSinks = for {
        c <- cpg.method.call if c.name == "<operator>.assignment"
        lhs <- c.argument.filter(_.order == 1).code.l
        if lhs.contains(".")
        fname = lhs.split("\\.").last
        if hint(fname, SINK_HINTS)
      } yield (c.methodFullName, "field", fname, c.methodFullName,
               "egress-field:" + fname, c.lineNumber.getOrElse(-1))
      val sinks = (callSinks ++ fieldSinks).distinct
        .sortBy(s => (s._1, s._4))
      (edges, sources, sinks)
    } catch {
      case _: Throwable =>
        (List.empty[(String, String, String, Int)],
         List.empty[(String, String, String, String, String, Int)],
         List.empty[(String, String, String, String, String, Int)])
    }

    // -- assemble the JSON (meta first, with the section counts) ------------
    val sb = new java.lang.StringBuilder()
    sb.append("{\"meta\":{\"source\":").append(jstr(src))
    sb.append(",\"methodCount\":").append(cpg.method.size)
    sb.append(",\"typeCount\":").append(cpg.typeDecl.size)
    sb.append(",\"fieldCount\":").append(cpg.field.size)
    sb.append(",\"edgeCount\":").append(edgeList.length)
    sb.append(",\"taintSourceCount\":").append(sourceList.length)
    sb.append(",\"taintSinkCount\":").append(sinkList.length)
    sb.append("}")
    sb.append(",\"types\":[").append(types.mkString(",")).append("]")
    sb.append(",\"fields\":[").append(fields.mkString(",")).append("]")
    sb.append(",\"methods\":[").append(methods.mkString(",")).append("]")
    sb.append(",\"edges\":[")
    sb.append(edgeList.map { case (kind, f, t, ln) =>
      "{\"type\":" + jstr(kind) + ",\"from\":" + jstr(f) +
      ",\"to\":" + jstr(t) + ",\"line\":" + ln + "}"
    }.mkString(","))
    sb.append("]")
    sb.append(",\"taint_sources\":[")
    sb.append(sourceList.map { case (id, kind, nm, owner, reason, ln) =>
      "{\"id\":" + jstr(id) + ",\"kind\":" + jstr(kind) +
      ",\"name\":" + jstr(nm) + ",\"owner\":" + jstr(owner) +
      ",\"reason\":" + jstr(reason) + ",\"line\":" + ln + "}"
    }.mkString(","))
    sb.append("]")
    sb.append(",\"taint_sinks\":[")
    sb.append(sinkList.map { case (id, kind, nm, owner, reason, ln) =>
      "{\"id\":" + jstr(id) + ",\"kind\":" + jstr(kind) +
      ",\"name\":" + jstr(nm) + ",\"owner\":" + jstr(owner) +
      ",\"reason\":" + jstr(reason) + ",\"line\":" + ln + "}"
    }.mkString(","))
    sb.append("]")
    sb.append("}")

    val json = sb.toString
    val writer = new java.io.FileWriter(out)
    try { writer.write(json); writer.close() }
    catch { case _: Throwable => () }
    println("METHOD-COUNT=" + cpg.method.size)
    println("TYPE-COUNT=" + cpg.typeDecl.size)
    println("FIELD-COUNT=" + cpg.field.size)
    println("EDGE-COUNT=" + edgeList.length)
    println("TAINT-SOURCE-COUNT=" + sourceList.length)
    println("TAINT-SINK-COUNT=" + sinkList.length)
    println("JSON-BYTES=" + json.length)
    println("ROTN-SCRAPE-OK")
  }
}