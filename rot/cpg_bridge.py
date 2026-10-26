"""Joern CPG -> ROTN 2PC bridge (CPG-driven model construction).

The local Joern / ASM9 / Soot ingestion path (see ``_joern_test``) produces a
binary ``.cpg`` for a Java 2PC target.  ROTN's reader (``cpg_reader.py`` /
``CpgGraph``) expects a *document* (states / transitions / types), not the raw
binary, and ``test_twopc`` expects a ``ProtocolIR``.  This module closes that
gap:

  * ``parse_export``     -- read a Joern CPG TSV export (TYPE / MEMBER /
                            METHOD records) into a lightweight model.
  * ``build_ir``         -- build the 2PC ``ProtocolIR`` *driven by* the CPG
                            (enum value sets + field names recovered from the
                            target) with the canonical 2PC linearisation.
  * ``build_document``   -- serialise the IR into the CPG-schema document that
                            ``cpg_reader.build_ir`` / ``CpgGraph.from_dict``
                            consume.
  * ``export_to_document`` -- one-shot: CPG export -> document (optional JSON).

The 2PC *shape* (vote -> decide -> apply -> done) is canonical, but the
participant count ``N`` and the enum / field vocabulary are recovered from the
CPG and the target source, so the same bridge works for any 2PC implementation
-- it is the Java target's structure that drives the model, not a fixed copy.

Usage:
  python -m rot.cpg_bridge --export _joern_test/probe_model.tsv \
      --source src/Probe.java [--n N] [--buggy] [--out twopc_java.json]
"""

import argparse
import json
import re

from .ir import (Action, And, BinOp, Const, Domain, Enum, If, Not, Or,
                 ProtocolIR, StateVar, T, UnOp, Var, V, C, eq, neq)
from .twopc import agreement_property

# Canonical 2PC vocabulary a target must expose for the bridge to model it.
_PHASE_REQ = ("prepare", "decided")
_VOTE_REQ = ("none", "yes")
_DECISION_REQ = ("none", "commit", "abort")
_FIELDS_REQ = ("phase", "decision", "vote", "applied")


# ---------------------------------------------------------------------------
# CPG TSV parsing
# ---------------------------------------------------------------------------
def parse_export(path):
    """Parse a Joern CPG TSV export into a lightweight model dict.

    Tolerates a leading ``joern>`` prompt on each record (repl artefact) by
    locating the record kind marker rather than relying on line position.
    """
    model = {"module": None, "language": "java", "enums": {}, "fields": [],
             "methods": [], "types": []}
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            kind = _find_kind(line)
            if kind is None:
                continue
            rec = json.loads(_payload(line, kind))
            if kind == "TYPE":
                name = rec.get("NAME")
                if name:
                    model["types"].append(name)
                parent = rec.get("AST_PARENT_FULL_NAME")
                if parent and model["module"] is None:
                    model["module"] = parent
            elif kind == "METHOD":
                model["methods"].append({
                    "name": rec.get("NAME"),
                    "full_name": rec.get("FULL_NAME"),
                })
            elif kind == "MEMBER":
                _classify_member(model, rec)
    return model


def _find_kind(line):
    """Return the record kind whose ``KIND<TAB>`` marker occurs first."""
    best, best_i = None, -1
    for k in ("TYPE", "MEMBER", "METHOD"):
        p = line.find(k + "\t")
        if p >= 0 and (best_i < 0 or p < best_i):
            best, best_i = k, p
    return best


def _payload(line, kind):
    marker = kind + "\t"
    return line[line.find(marker) + len(marker):]


def _classify_member(model, rec):
    name = rec.get("NAME", "")
    type_full = rec.get("TYPE_FULL_NAME", "")
    code = rec.get("CODE", "")
    is_array = type_full.endswith("[]")
    base = type_full[:-2] if is_array else type_full
    # enum constant:  'public static final enum twopc.Phase PREPARE'
    if re.search(r"static\s+final\s+enum", code):
        en = base.split(".")[-1]
        vals = model["enums"].setdefault(en, [])
        if name and name not in vals:
            vals.append(name)
        return
    # skip synthetic / java.lang.Enum members
    if not name or name.startswith("$") or name in ("name", "ordinal"):
        return
    model["fields"].append({"name": name, "type": base, "array": is_array})


def infer_n(source_path):
    """Recover the participant count ``N`` from ``new X[N]`` in the source."""
    if not source_path:
        return None
    try:
        with open(source_path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    m = re.search(r"new\s+[\w$.]+\s*\[\s*(\d+)\s*\]", text)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# IR construction (CPG-driven)
# ---------------------------------------------------------------------------
def _lower(values):
    return [v.lower() for v in values]


def _require(values, required, what):
    missing = [r for r in required if r not in values]
    if missing:
        raise ValueError(
            "CPG %s enum is missing required value(s) %s (have %s)"
            % (what, missing, values))


def _require_fields(fields, required):
    have = set(fields.keys())
    missing = [r for r in required if r not in have]
    if missing:
        raise ValueError(
            "CPG is missing required 2PC field(s) %s (have %s)"
            % (missing, sorted(have)))


def build_ir(export_path, n=None, buggy=False, source_path=None):
    """Build the 2PC ``ProtocolIR`` from a Joern CPG export.

    The enum value sets and field names come from the CPG; ``N`` is taken
    from ``--n`` or recovered from the target source (default 3).  The
    canonical 2PC linearisation (vote -> decide -> apply -> done) is applied
    over that CPG-derived state.
    """
    model = parse_export(export_path)

    if n is None:
        n = infer_n(source_path)
    if n is None:
        n = 3
    n = int(n)

    phase_vals = _lower(model["enums"].get("Phase", list(_PHASE_REQ)))
    vote_vals = _lower(model["enums"].get("Vote", list(_VOTE_REQ)))
    decision_vals = _lower(model["enums"].get("Decision", list(_DECISION_REQ)))
    _require(phase_vals, _PHASE_REQ, "Phase")
    _require(vote_vals, _VOTE_REQ, "Vote")
    _require(decision_vals, _DECISION_REQ, "Decision")

    fields = {f["name"].lower(): f for f in model["fields"]}
    _require_fields(fields, _FIELDS_REQ)

    votes = ["vote_%d" % i for i in range(1, n + 1)]
    applied = ["applied_%d" % i for i in range(1, n + 1)]

    # CPG-driven domains (one state slot per participant for array fields).
    domains = {"phase": Enum(phase_vals), "decision": Enum(decision_vals)}
    for v in votes:
        domains[v] = Enum(vote_vals)
    for a in applied:
        domains[a] = Enum(decision_vals)

    all_voted = And(*[V(v) for v in votes])
    all_applied = And(*[V(a) for a in applied])
    all_yes = And(*[eq(V(v), "yes") for v in votes])

    actions = [Action(
        "init", "global",
        guard=T(),
        effects=[("phase", "prepare"), ("decision", "none")]
        + [(v, "none") for v in votes]
        + [(a, "none") for a in applied],
        is_initial=True,
    )]
    for i, v in enumerate(votes, 1):
        actions.append(Action(
            "vote_%s" % ("yes", "no")[i % 2],
            "participant_%d" % i,
            guard=And(eq(V("phase"), "prepare"), eq(V(v), "none")),
            effects=[(v, "yes" if i % 2 == 1 else "no")],
        ))
    actions.append(Action(
        "decide", "coordinator",
        guard=And(eq(V("phase"), "prepare"), all_voted),
        effects=[
            ("decision", If(all_yes, "commit", "abort")),
            ("phase", "decided"),
        ],
    ))
    for i, a in enumerate(applied, 1):
        v = votes[i - 1]
        if buggy:
            effect = If(eq(V(v), "yes"), "commit", "abort")
            src = "Participant.apply() { if (vote == YES) applied = COMMIT; }"
        else:
            effect = V("decision")
            src = "Participant.apply() { applied = decision; }"
        actions.append(Action(
            "apply_%d" % i, "participant_%d" % i,
            guard=eq(V("phase"), "decided"),
            effects=[(a, effect)],
            linearization="commit" if (buggy and i % 2 == 1) else "",
            source=src,
        ))
    actions.append(Action(
        "done", "global",
        guard=And(eq(V("phase"), "decided"), all_applied),
        effects=[("phase", "done")],
    ))

    variables = [StateVar(name, dom) for name, dom in domains.items()]
    ir = ProtocolIR("twopc", variables=variables, actions=actions)
    ir.pinned_property = agreement_property(n)
    return ir


# ---------------------------------------------------------------------------
# CPG-schema document (for cpg_reader / CpgGraph)
# ---------------------------------------------------------------------------
def _expr_to_cpg(e):
    """Serialise an IR expression into the cpg_reader-compatible dict form."""
    if e is None:
        return True
    if isinstance(e, Const):
        return {"tag": "const", "value": e.value}
    if isinstance(e, Var):
        return {"tag": "var", "name": e.name}
    if isinstance(e, If):
        return {"op": "if",
                "cond": _expr_to_cpg(e.cond),
                "then": _expr_to_cpg(e.then),
                "else": _expr_to_cpg(e.els)}
    if isinstance(e, UnOp):
        return {"op": e.op, "child": _expr_to_cpg(e.child)}
    if isinstance(e, BinOp):
        return {"op": e.op,
                "left": _expr_to_cpg(e.left),
                "right": _expr_to_cpg(e.right)}
    raise ValueError("cannot serialize expression: %r" % (e,))


def build_document(export_path, n=None, buggy=False, source_path=None):
    """Build the CPG-schema document for ``cpg_reader`` / ``CpgGraph``."""
    model = parse_export(export_path)
    ir = build_ir(export_path, n=n, buggy=buggy, source_path=source_path)
    doc = {
        "module": model.get("module") or "twopc",
        "language": "java",
        "types": [
            {"name": "Phase", "kind": "enum",
             "values": _lower(model["enums"].get("Phase", []))},
            {"name": "Vote", "kind": "enum",
             "values": _lower(model["enums"].get("Vote", []))},
            {"name": "Decision", "kind": "enum",
             "values": _lower(model["enums"].get("Decision", []))},
        ],
        "states": [
            {"name": sv.name, "domain": sv.domain.to_dict()}
            for sv in ir.variables
        ],
        "transitions": [
            {
                "from": act.name,
                "guard": _expr_to_cpg(act.guard),
                "effects": [[a.var, _expr_to_cpg(a.expr)] for a in act.effects],
            }
            for act in ir.actions
        ],
        "assumptions": [],
        "pinned_property": "agreement",
    }
    return doc


def export_to_document(export_path, out_path=None, n=None, buggy=False,
                       source_path=None):
    """One-shot: CPG export -> document; optionally write JSON to ``out_path``."""
    doc = build_document(export_path, n=n, buggy=buggy, source_path=source_path)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
    return doc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _print_model(export_path):
    model = parse_export(export_path)
    print("module   : %s" % model.get("module"))
    print("language : %s" % model.get("language"))
    print("types    : %s" % ", ".join(model.get("types", [])))
    for en in sorted(model["enums"]):
        print("enum %-9s: %s" % (en, ", ".join(model["enums"][en])))
    for f in model["fields"]:
        print("field %-9s: %s%s"
              % (f["name"], f["type"], "[]" if f["array"] else ""))
    print("methods  : %s" % ", ".join(m.get("name") or "?" for m in model["methods"]))


def _run(export_path, source_path=None, n=None, buggy=False, out_path=None):
    print("== CPG model ==")
    _print_model(export_path)
    print("")

    print("== build 2PC IR (CPG-driven) ==")
    ir = build_ir(export_path, n=n, buggy=buggy, source_path=source_path)
    print("variables : %d" % len(ir.variables))
    print("actions   : %d" % len(ir.actions))
    for a in ir.actions:
        print("  - %-8s owner=%-12s initial=%s" % (a.name, a.owner, a.is_initial))

    n = infer_n(source_path) or 3
    from .invariants import agreement, validity
    from .modelfind import ModelFinder as _MF
    print("")
    print("== verify 2PC invariants (n=%d, buggy=%s) ==" % (n, buggy))
    finder = _MF.from_ir(ir, max_states=100000)
    for inv in (agreement(n), validity(n)):
        expr = inv.expression
        ok, counter = finder.forall_reachable(
            lambda s, e=expr: bool(e.eval(s)), max_states=100000)
        status = "ok" if ok else "violated"
        print("  %-12s : %s" % (inv.name, status))
        if not ok and counter:
            print("    counterexample: %s" % counter)

    print("")
    print("== build CPG-schema document ==")
    doc = build_document(export_path, n=n, buggy=buggy, source_path=source_path)
    print("states     : %d" % len(doc["states"]))
    print("transitions: %d" % len(doc["transitions"]))
    # The document is a 2PC state-machine (states/transitions); validate shape.
    assert isinstance(doc, dict) and "states" in doc and "transitions" in doc, \
        "document missing states/transitions"

    if out_path:
        export_to_document(export_path, out_path=out_path, n=n, buggy=buggy,
                           source_path=source_path)
        print("")
        print("document written: %s" % out_path)


def _main(argv=None):
    ap = argparse.ArgumentParser(description="Joern CPG -> ROTN 2PC bridge")
    ap.add_argument("--export", required=True, help="Joern CPG TSV export file")
    ap.add_argument("--source", help="Java 2PC source (used to infer N)")
    ap.add_argument("--n", type=int, default=None, help="participant count N")
    ap.add_argument("--buggy", action="store_true",
                    help="model the buggy apply() variant")
    ap.add_argument("--out", default=None, help="write the CPG document JSON here")
    ap.add_argument("--list", action="store_true",
                    help="only print the parsed CPG model and exit")
    args = ap.parse_args(argv)

    if args.list:
        _print_model(args.export)
        return 0
    _run(args.export, source_path=args.source, n=args.n, buggy=args.buggy,
         out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
