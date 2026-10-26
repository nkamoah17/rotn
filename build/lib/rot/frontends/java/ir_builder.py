# -*- coding: utf-8 -*-
"""ir_builder.py -- Java front-end: CPG / Java source -> ``rot.ir.ProtocolIR``.

Source-first, CPG-enhanced, mirroring the trusted bridge (``_joern_test/
cpg_bridge.py``): the canonical 2PC linearisation

    init -> vote_i_yes / vote_i_no -> decide -> apply_i -> done

is recovered over a *state vocabulary taken from the target*:

  * ``recover_enums``      -- enum domains (phase / vote / decision) from
                              Java ``Type.CONST`` tokens + enum declarations,
                              cross-checked / completed by a ``CpgModel``.
  * ``detect_apply_mode``  -- CORRECT (apply reads the shared ``decision``)
                              vs BUGGY (apply re-derives from its own ``vote``),
                              from apply-method bodies or CPG read/write edges.
  * ``build_ir``           -- the public entry point.

Narrow-waist rule (see ``rot/frontends/__init__.py``): this module imports
only ``rot.ir`` + the language standard library.  The agreement invariant is
inlined (no ``rot.twopc``), and no downstream engine (emitter / tlc / cegar /
linearization / symbolic) is imported here.  Per-action provenance (Java
method spans, apply mode, recovered enums) rides in ``ProtocolIR.metadata``
so the IR's ``to_dict()`` stays structurally identical to the trusted
bridge's hand-built IR.

Python 3.6 compatible (no f-strings / dataclasses).
"""

import os
import re

from rot.ir import (Action, And, Assignment, Const, Enum, If, Not, Or,
                    ProtocolIR, StateVar, T, V, C, eq)

PROTOCOL_TWOPC = "twopc"

# Canonical 2PC vocabulary the linearisation requires (the Java target must
# expose at least these values; extra values recovered from the source / CPG
# extend the domains deterministically).
_PHASE_REQ = ("prepare", "decided", "done")
_VOTE_REQ = ("none", "yes", "no")
_DECISION_REQ = ("none", "commit", "abort")

# State-slot naming (mirrors _joern_test/cpg_bridge.py).
_PHASE = "phase"
_DECISION = "decision"

# ---------------------------------------------------------------------------
# Java source scanning (pure text; no compiler / Joern needed)
# ---------------------------------------------------------------------------
def read_java_files(source_dir):
    """All ``.java`` files under ``source_dir`` (recursive), sorted by path.

    Returns a list of ``(rel_path, text)`` tuples.  Raises ``ValueError`` when
    ``source_dir`` is not an existing directory or holds no Java sources.
    """
    if not source_dir or not os.path.isdir(source_dir):
        raise ValueError("java front-end: source_dir not found: %r" % (source_dir,))
    found = []
    for root, _dirs, files in os.walk(source_dir):
        for name in sorted(files):
            if name.lower().endswith(".java"):
                path = os.path.join(root, name)
                with open(path, "r", encoding="utf-8") as fh:
                    found.append((os.path.relpath(path, source_dir), fh.read()))
    if not found:
        raise ValueError("java front-end: no .java sources under %r" % (source_dir,))
    return found


def strip_comments(text):
    """Remove ``/* ... */`` and ``// ...`` comments (line structure preserved)."""
    out = []
    in_block = False
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            if ch == "\n":
                out.append(ch)        # keep the line structure intact
            i += 1
            continue
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"' :
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch == "/" and nxt == "/":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def method_span(text, method_name, class_hint=None):
    """Line span (1-based, inclusive) of a method definition in ``text``.

    ``method_name`` must match a *definition* (``<ret> name(args) {``), not a
    call (``obj.name(...)``).  Comments are ignored.  Returns
    ``(start, end)`` or ``None``.
    """
    clean = strip_comments(text)
    decl = re.compile(
        r"(?:^|\n)\s*(?:public|private|protected|static|\s)+"
        r"[\w.]+(?:<[^>]*>)?(?:\s*\[\])?\s+"
        + re.escape(method_name) +
        r"\s*\([^)]*\)\s*\{",
        re.MULTILINE)
    m = decl.search(clean)
    if not m:
        return None
    # Anchor the start line on the method *name* token: m.start() sits on the
    # (?:^|\n) anchor, whose leading \s* can swallow blank / comment-stripped
    # lines above the declaration, shifting the line number upward.
    name_off = re.search(r"\b" + re.escape(method_name) + r"\s*\(", m.group()).start()
    lines = clean[:m.start() + name_off].count("\n") + 1
    # brace-balance forward from the opening brace of the definition
    depth = 0
    started = False
    pos = clean.index("{", m.start())
    line = lines
    for j in range(pos, len(clean)):
        ch = clean[j]
        if ch == "\n":
            line += 1
        elif ch == "{":
            depth += 1
            started = True
        elif ch == "}":
            depth -= 1
            if started and depth == 0:
                return (lines, line)
    return (lines, line) if started else None


def find_field_lines(text, field_name):
    """1-based lines declaring / initialising a field ``field_name`` (or None)."""
    clean = strip_comments(text)
    pat = re.compile(r"^\s*(?:public|private|protected|static|final|\s)*"
                     r"[\w.<>\[\]]+\s+" + re.escape(field_name) + r"\s*=",
                     re.MULTILINE)
    m = pat.search(clean)
    if not m:
        return None
    return clean[:m.start()].count("\n") + 1


# ---------------------------------------------------------------------------
# Vocabulary recovery (source-first, CPG-enhanced)
# ---------------------------------------------------------------------------
def _enum_tokens(text, type_name):
    """All ``Type.CONST`` value tokens of ``type_name`` in Java source text."""
    vals = set()
    for m in re.finditer(r"\b" + re.escape(type_name) + r"\s*\.\s*([A-Za-z_]\w*)",
                         text):
        vals.add(m.group(1).lower())
    return vals


def _enum_declarations(text, type_name):
    """Values declared in an ``enum Type { A, B, ... }`` body (or empty set)."""
    m = re.search(r"enum\s+" + re.escape(type_name) + r"\s*\{([^}]*)\}", text)
    if not m:
        return set()
    vals = set()
    for tok in m.group(1).split(","):
        tok = tok.strip().split("(")[0].strip()
        if re.match(r"^[A-Za-z_]\w*$", tok) and tok.lower() not in ("default",):
            vals.add(tok.lower())
    return vals


def recover_enums(source_dir, model=None):
    """Recover the 2PC enum domains from Java sources (+ optional CPG model).

    Returns ``{"phase": [...], "vote": [...], "decision": [...]}`` with the
    canonical 2PC values (required by the linearisation) first, then any extra
    values the target actually declares (source ``Type.CONST`` tokens, enum
    declarations, and ``CpgModel`` enum constants / field types).
    """
    recovered = {"Phase": set(), "Vote": set(), "Decision": set()}
    files = []
    if source_dir and os.path.isdir(source_dir):
        files = read_java_files(source_dir)
    for _rel, text in files:
        for tname in ("Phase", "Vote", "Decision"):
            recovered[tname] |= _enum_tokens(text, tname)
            recovered[tname] |= _enum_declarations(text, tname)

    if model is not None:
        for typ in model.types:
            if typ.name in recovered:
                for const in typ.constants:
                    if isinstance(const, str) and const:
                        recovered[typ.name].add(const.lower())

    def merge(type_name, required):
        have = sorted(recovered.get(type_name, ()))
        out = list(required)
        for v in have:
            if v not in out:
                out.append(v)
        return out

    return {
        "phase": merge("Phase", _PHASE_REQ),
        "vote": merge("Vote", _VOTE_REQ),
        "decision": merge("Decision", _DECISION_REQ),
    }


def detect_apply_mode(source_dir, model=None):
    """Detect whether the apply path is CORRECT or BUGGY.

    CORRECT: ``applied = decision`` -- the participant applies the shared
    coordinator decision.  BUGGY: the participant re-derives its applied
    value from its own ``vote`` (``applied = (vote == YES) ? ... : ...``).

    Returns ``"correct"`` or ``"buggy"`` (default ``"correct"`` when the
    evidence is absent or inconclusive).
    """
    # 1) CPG evidence: a method that writes ``applied`` and reads ``vote``.
    if model is not None:
        for meth in model.methods:
            if "applied" in meth.written_fields:
                reads = set(meth.read_fields)
                if "vote" in reads and "decision" not in reads:
                    return "buggy"
                if "decision" in reads:
                    return "correct"
    # 2) Java source evidence: inspect apply* method bodies.
    if source_dir and os.path.isdir(source_dir):
        try:
            files = read_java_files(source_dir)
        except ValueError:
            files = []
        for _rel, text in files:
            for name in ("apply", "applyCommit", "applyAbort", "apply_i"):
                m = re.search(
                    r"(?:void|Decision)\s+" + re.escape(name) +
                    r"\s*\([^)]*\)\s*\{", text)
                if not m:
                    continue
                body = _method_body(text, m.start())
                reads_vote = re.search(r"\bvote\b", body) is not None
                reads_decision = re.search(r"\bdecision\b", body) is not None
                if reads_vote and not reads_decision:
                    return "buggy"
                if reads_decision:
                    return "correct"
    return "correct"


def _method_body(text, start):
    """Brace-balanced method body text starting at ``start`` (declaration)."""
    pos = text.index("{", start)
    depth = 0
    for j in range(pos, len(text)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[pos:j + 1]
    return text[pos:]


# ---------------------------------------------------------------------------
# public entry point: build_ir
# ---------------------------------------------------------------------------
def agreement_property(n):
    """2PC agreement invariant (inlined from the trusted bridge -- narrow
    waist, no ``rot.twopc`` import).

    For every pair of participants: if both have applied a real decision they
    must agree; a participant that has not applied yet imposes no constraint.
    """
    conjs = []
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            none_i = eq(V("applied_%d" % i), C("none"))
            none_j = eq(V("applied_%d" % j), C("none"))
            equal = eq(V("applied_%d" % i), V("applied_%d" % j))
            conjs.append(Or(none_i, none_j, equal))
    return And(*conjs) if conjs else T()


# Candidate Java method names per canonical 2PC action (first hit wins).
_ACTION_METHODS = (
    ("init", ("prepare",)),
    ("vote", ("voteYes", "voteNo", "vote")),
    ("decide", ("decide",)),
    ("apply", ("apply", "applyCommit", "applyAbort")),
    ("done", ("commit", "abort", "done")),
)


def _collect_provenance(files):
    """Map canonical action name -> ``relpath:start-end`` of its Java method.

    Best effort: an action whose method is not present in the scanned sources
    is simply absent from the map.
    """
    prov = {}
    for base, candidates in _ACTION_METHODS:
        for rel, text in files:
            for cand in candidates:
                span = method_span(text, cand)
                if span is not None:
                    prov[base] = "%s:%d-%d" % (rel, span[0], span[1])
                    break
            else:
                continue
            break
    return prov


def build_ir(source_dir, protocol=PROTOCOL_TWOPC, n=3, buggy=None,
             model=None):
    """Build the canonical 2PC ``ProtocolIR`` from Java sources.

    Narrow-waist contract (see ``rot/frontends/__init__.py``)::

        build_ir(source_dir, protocol, n, buggy) -> ProtocolIR

    * the state vocabulary (enum domains) is recovered from the Java sources
      (``recover_enums``), cross-checked / completed by a ``CpgModel`` when
      one is passed as ``model``;
    * the apply variant is selected by ``buggy`` (``None`` = auto-detect
      from the sources via ``detect_apply_mode``);
    * ``to_dict()`` for ``variables`` / ``actions`` / ``pinned_property`` is
      structurally identical to the trusted ``rot.twopc.build_ir`` of the
      same ``(n, buggy)``; per-action provenance rides in
      ``ProtocolIR.metadata`` so the narrow waist stays comparable.
    """
    if protocol != PROTOCOL_TWOPC:
        raise ValueError("java front-end: unsupported protocol %r "
                         "(supported: %r)" % (protocol, PROTOCOL_TWOPC))
    n = int(n)
    if n < 1:
        raise ValueError("java front-end: n must be >= 1 (got %r)" % (n,))

    files = read_java_files(source_dir)          # validates source_dir
    vocab = recover_enums(source_dir, model=model)

    if buggy is None:
        buggy = detect_apply_mode(source_dir, model=model) == "buggy"
    buggy = bool(buggy)

    phase_domain = Enum(vocab["phase"])
    vote_domain = Enum(vocab["vote"])
    decision_domain = Enum(vocab["decision"])

    def vote_eq(i, value):
        return eq(V("vote_%d" % i), C(value))

    # ---- variables ------------------------------------------------------------
    variables = [
        StateVar("phase", phase_domain, owner="global"),
        StateVar("decision", decision_domain, owner="coordinator"),
    ]
    for i in range(1, n + 1):
        variables.append(StateVar("vote_%d" % i, vote_domain,
                                  owner="participant_%d" % i))
        variables.append(StateVar("applied_%d" % i, decision_domain,
                                  owner="participant_%d" % i))

    # ---- actions ---------------------------------------------------------------
    actions = []

    # init: everyone ready to vote, nothing decided / applied yet.
    init_effects = [Assignment("phase", C("prepare")),
                    Assignment("decision", C("none"))]
    for i in range(1, n + 1):
        init_effects.append(Assignment("vote_%d" % i, C("none")))
        init_effects.append(Assignment("applied_%d" % i, C("none")))
    actions.append(Action(name="init", owner="global", guard=T(),
                          effects=init_effects, is_initial=True))

    # prepare: each participant casts its (unknown) vote.
    for i in range(1, n + 1):
        guard = And(eq(V("phase"), C("prepare")), vote_eq(i, "none"))
        actions.append(Action(name="vote_%d_yes" % i,
                              owner="participant_%d" % i, guard=guard,
                              effects=[Assignment("vote_%d" % i, C("yes"))]))
        actions.append(Action(name="vote_%d_no" % i,
                              owner="participant_%d" % i, guard=guard,
                              effects=[Assignment("vote_%d" % i, C("no"))]))

    # coordinator: one decision from ALL votes, then DECIDED.
    all_voted = And(*[Not(vote_eq(i, "none")) for i in range(1, n + 1)])
    all_yes = And(*[vote_eq(i, "yes") for i in range(1, n + 1)])
    decide_guard = And(eq(V("phase"), C("prepare")), all_voted)
    decision_val = If(all_yes, C("commit"), C("abort"))
    actions.append(Action(name="decide", owner="coordinator",
                          guard=decide_guard,
                          effects=[Assignment("decision", decision_val),
                                   Assignment("phase", C("decided"))],
                          linearization="send(decide)"))

    # apply: participant i applies the decision it is given.
    for i in range(1, n + 1):
        guard = eq(V("phase"), C("decided"))
        if buggy:
            # BUGGY: re-derives its own decision from its own vote.
            self_decide = If(vote_eq(i, "yes"), C("commit"), C("abort"))
            actions.append(Action(name="apply_%d" % i,
                                  owner="participant_%d" % i, guard=guard,
                                  effects=[Assignment("applied_%d" % i,
                                                       self_decide)]))
        else:
            # CORRECT: applies the shared coordinator decision.
            actions.append(Action(name="apply_%d" % i,
                                  owner="participant_%d" % i, guard=guard,
                                  effects=[Assignment("applied_%d" % i,
                                                       V("decision"))]))

    # done: every participant has applied something real.
    all_applied = And(*[Not(eq(V("applied_%d" % i), C("none")))
                        for i in range(1, n + 1)])
    actions.append(Action(name="done", owner="coordinator",
                          guard=And(eq(V("phase"), C("decided")), all_applied),
                          effects=[Assignment("phase", C("done"))],
                          linearization="finalize"))

    return ProtocolIR(
        name=("twopc_buggy" if buggy else "twopc_correct"),
        variables=variables,
        actions=actions,
        init=T(),
        pinned_property=agreement_property(n),
        source_path=source_dir,
        metadata={
            "n": n,
            "buggy": buggy,
            "protocol": PROTOCOL_TWOPC,
            "language": "java",
            "apply_mode": "buggy" if buggy else "correct",
            "enums": {k: list(v) for k, v in vocab.items()},
            "provenance": _collect_provenance(files),
            "description": "Two-phase commit, %d participants, %s" % (
                n, "BUGGY (participants self-decide)" if buggy
                else "correct (participants apply coordinator decision)"),
        },
    )


__all__ = [
    "PROTOCOL_TWOPC", "read_java_files", "strip_comments",
    "method_span", "find_field_lines", "recover_enums", "detect_apply_mode",
    "agreement_property", "build_ir",
]


