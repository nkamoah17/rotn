# -*- coding: utf-8 -*-
"""cpg_reader.py -- read a Code Property Graph (CPG) artifact into a trusted IR.

The CPG is the output of an external code-analysis tool (e.g. a Joern/CPG export
of the Java target). We do NOT re-derive code structure here; we *read* a
well-formed CPG document and lower it to the :class:`rot.ir.ProtocolIR` that the
rest of the pipeline (linearization, symbolic, emitter, TLC, CEGAR) consumes.
This is the leftmost stage:

    CPG  --(cpg_reader)-->  ProtocolIR

Document shape (schema-driven, so a real Joern/CPG export can be adapted with a
small transformer). ``variables`` carry a domain (``enum``/``int``/``bool``);
``functions`` carry ``calls`` (call edges) and ``branches`` (control-flow
transitions with a ``guard`` and ``effects``); ``messages`` are message/data-flow
edges. Guards/effects use the *canonical IR expression* form (the same
``to_dict`` shape from :mod:`rot.ir`), so this reader maps them straight through
:func:`rot.ir.Expr.from_dict` -- lossless for const/var/bin/un/if/allof/anyof.

``functions``/``calls``/``messages`` are preserved on the resulting IR's
``metadata`` so the emitter and reports can show *provenance* (which function /
message edge each transition came from) -- the link back to the concrete Java
code that CEGAR and the verdict layer rely on.

Pure stdlib, Python 3.6 compatible.
"""

import json

from .ir import (ProtocolIR, StateVar, Enum, IntRange, Bool,
                 Assignment, Action, Expr, T)


class CpgError(Exception):
    """Raised when a CPG document is malformed."""


def _parse_domain(d, name):
    if not isinstance(d, dict) or "kind" not in d:
        raise CpgError("variable %r: missing domain.kind" % (name,))
    kind = d["kind"]
    if kind == "enum":
        if "values" not in d or not d["values"]:
            raise CpgError("variable %r: enum domain needs non-empty values" % (name,))
        return Enum(list(d["values"]))
    if kind == "int":
        return IntRange(int(d["lo"]), int(d["hi"]))
    if kind == "bool":
        return Bool()
    raise CpgError("variable %r: unsupported domain kind %r" % (name, kind))


def _parse_expr(e, where):
    if e is None:
        return T()
    if isinstance(e, Expr):
        return e
    try:
        return Expr.from_dict(e)
    except Exception as ex:
        raise CpgError("bad expression %r (%s)" % (e, ex))


class CpgGraph(object):
    """An in-memory, validated CPG document (functions, edges, variables)."""

    def __init__(self, module, language, source_file, description,
                 variables, functions, messages):
        self.module = module
        self.language = language
        self.source_file = source_file
        self.description = description
        self.variables = list(variables)
        self.functions = list(functions)
        self.messages = list(messages)

    @classmethod
    def from_dict(cls, d):
        return cls(
            module=d.get("module", "module"),
            language=d.get("language", ""),
            source_file=d.get("source_file", ""),
            description=d.get("description", ""),
            variables=d.get("variables", []),
            functions=d.get("functions", []),
            messages=d.get("messages", []),
        )

    @classmethod
    def from_json(cls, path):
        with open(path, "r") as f:
            return cls.from_dict(json.load(f))

    def to_dict(self):
        return {
            "module": self.module,
            "language": self.language,
            "source_file": self.source_file,
            "description": self.description,
            "variables": self.variables,
            "functions": self.functions,
            "messages": self.messages,
        }

    def all_branches(self):
        """Flatten every branch (transition) across all functions, in order."""
        out = []
        for fn in self.functions:
            for br in fn.get("branches", []):
                br = dict(br)
                br.setdefault("source", fn.get("name", ""))
                out.append(br)
        return out

    def call_edges(self):
        out = []
        for fn in self.functions:
            for c in fn.get("calls", []):
                out.append((fn.get("name", ""), c))
        return out

    def message_edges(self):
        return list(self.messages)


def _validate(doc):
    errs = []
    for v in doc.get("variables", []):
        if "name" not in v:
            errs.append("variable without name: %r" % (v,))
        elif "domain" not in v:
            errs.append("variable %r without domain" % (v["name"],))
    names = set(v.get("name") for v in doc.get("variables", []))
    init_seen = False
    for br in CpgGraph.from_dict(doc).all_branches():
        if br.get("initial"):
            init_seen = True
        for e in br.get("effects", []):
            if e.get("var") not in names:
                errs.append("effect writes unknown variable %r (branch %r)"
                            % (e.get("var"), br.get("id")))
    if doc.get("functions") and not init_seen:
        errs.append("no branch is marked initial (need an Init transition)")
    return errs


def build_ir(cpg):
    """Lower a :class:`CpgGraph` into a :class:`rot.ir.ProtocolIR`.

    * variables -> StateVar list
    * branches  -> Action list (guard/effects via Expr.from_dict)
    * the ``initial`` branch becomes the ``is_initial`` action
    * functions / calls / messages are preserved on ``metadata`` for provenance
    """
    variables = []
    for v in cpg.variables:
        variables.append(StateVar(
            name=v["name"],
            domain=_parse_domain(v["domain"], v["name"]),
            mode=v.get("mode", "precise"),
            owner=v.get("owner", "global"),
            desc=v.get("desc", "")))

    actions = []
    for br in cpg.all_branches():
        guard = _parse_expr(br.get("guard"), "guard of %r" % (br.get("id"),)) \
            if br.get("guard") is not None else T()
        effects = [
            Assignment(e["var"],
                       _parse_expr(e["expr"], "effect of %r" % (br.get("id"),)))
            for e in br.get("effects", [])
        ]
        actions.append(Action(
            name=br.get("id", "action_%d" % len(actions)),
            owner=br.get("owner", "global"),
            guard=guard,
            effects=effects,
            linearization=br.get("linearization", ""),
            env_free=bool(br.get("env_free", False)),
            is_initial=bool(br.get("initial", False)),
            source=br.get("source", ""),
        ))

    return ProtocolIR(
        name=cpg.module,
        variables=variables,
        actions=actions,
        init=T(),
        assumptions=[],
        source_path=cpg.source_file,
        metadata={
            "language": cpg.language,
            "description": cpg.description,
            "functions": cpg.functions,
            "call_edges": [[a, b] for a, b in cpg.call_edges()],
            "message_edges": cpg.message_edges(),
        },
    )


def read_cpg(path):
    """Read a CPG JSON file at ``path`` and return a validated ProtocolIR."""
    doc = CpgGraph.from_json(path).to_dict()
    errs = _validate(doc)
    if errs:
        raise CpgError("CPG validation failed:\n  " + "\n  ".join(errs))
    return build_ir(CpgGraph.from_dict(doc))


__all__ = ["CpgGraph", "CpgError", "build_ir", "read_cpg", "_parse_domain",
           "_parse_expr", "_validate"]
