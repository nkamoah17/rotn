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
// Output shape == rot.frontends.cpg_model (meta + types + fields + methods).
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
    def jstrs(xs: List[String]): String =
      "[" + xs.map(jstr).mkString(",") + "]"

    val sb = new java.lang.StringBuilder()
    sb.append("{\"meta\":{\"source\":").append(jstr(src))
    sb.append(",\"methodCount\":").append(cpg.method.size)
    sb.append(",\"typeCount\":").append(cpg.typeDecl.size)
    sb.append(",\"fieldCount\":").append(cpg.field.size)
    sb.append("}")

    // -- types (classes / interfaces / enums, with supertypes) ---------------
    sb.append(",\"types\":[")
    val types = cpg.typeDecl.l.map { t =>
      val inh = t.inheritFrom.l.map(_.code).distinct.sorted
      // Enum constants: the CPG reports each constant as a method on the enum
      // type, so "enum E { A, B }" shows up as methods E.A / E.B with no
      // arguments.  This is how the IR builder recovers enum value domains
      // (the CPG has no distinct enum-member node kind for Java).
      val consts = cpg.method
        .filter(_.astParentFullName == t.fullName)
        .filter(_.parameter.isEmpty)
        .name.l.distinct.sorted
      ("{\"name\":" + jstr(t.name) +
       ",\"fullName\":" + jstr(t.fullName) +
       ",\"owner\":" + jstr(t.astParentFullName) +
       ",\"lineNumber\":" + t.lineNumber.getOrElse(-1) +
       ",\"endLineNumber\":" + t.lineNumberEnd.getOrElse(-1) +
       ",\"inherits\":" + jarr(inh) + "}")
    }
    sb.append(types.mkString(",")).append("]")

    // -- fields (with declared type and owner) -------------------------------
    // NOTE: key is "type" -- must match rot.frontends.cpg_model.CpgField.
    sb.append(",\"fields\":[")
    val fields = cpg.field.l.map { f =>
      ("{\"name\":" + jstr(f.name) +
       ",\"fullName\":" + jstr(f.fullName) +
       ",\"type\":" + jstr(f.typeFullName) +
       ",\"owner\":" + jstr(f.astParentFullName) + "}")
    }
    sb.append(fields.mkString(",")).append("]")

    // -- methods (with call edges + field read/write split) ------------------
    sb.append(",\"methods\":[")
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
      ("{\"name\":" + jstr(m.name) +
       ",\"fullName\":" + jstr(full) +
       ",\"owner\":" + jstr(owner) +
       ",\"lineNumber\":" + ln +
       ",\"endLineNumber\":" + eln +
       ",\"calls\":" + jarr(calls) +
       ",\"readFields\":" + jarr(reads) +
       ",\"writtenFields\":" + jarr(writes) + "}")
    }
    sb.append(methods.mkString(",")).append("]")
    sb.append("}")

    val json = sb.toString
    val writer = new java.io.FileWriter(out)
    try { writer.write(json); writer.close() }
    catch { case _: Throwable => () }
    println("METHOD-COUNT=" + cpg.method.size)
    println("TYPE-COUNT=" + cpg.typeDecl.size)
    println("FIELD-COUNT=" + cpg.field.size)
    println("JSON-BYTES=" + json.length)
    println("ROTN-SCRAPE-OK")
  }
}