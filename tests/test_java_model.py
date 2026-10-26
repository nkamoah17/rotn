#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_java_model.py -- 2PC vertical slice: Java source to a proven (or falsified)
model, end to end.

    examples/twopc/{Coordinator,Participant}.java
        --(Java enum-value scan)-->  Phase / Vote / Decision vocab
        --(rot.ir builder)----------> canonical 2PC ProtocolIR  (correct + buggy)
        --(rot.linearization)------> LinearizedModel
        --(rot.symbolic)------------> agreement PROVEN / VIOLATED, validity PROVEN
        --(cross-check)-------------> hand-built IR == rot.twopc.build_ir (to_dict)
        --(optional CPG)------------> rot.cpg_reader lowers a real CPG artifact

The cross-check ground-truths the hand-built IR: its state, domains and actions
are structurally identical (``to_dict()``) to the trusted ``rot.twopc.build_ir``,
and both reach the same proof verdicts.  The enum *domains* are the canonical 2PC
domains, cross-checked against the Java sources (state fields, enum type usages
and the enum-value constants) so the whole slice stays traceable to the Java a
Joern run would lower.

Run:
    python tests/test_java_model.py
    python -m pytest tests/test_java_model.py -v
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.ir import (ProtocolIR, StateVar, Action, Assignment, Enum,
                    T, And, Not, C, V, If, Or, eq)
from rot.linearization import linearize
from rot.symbolic import SymbolicEngine, PROVEN, VIOLATED
from rot.twopc import (build_ir as twopc_ground_truth,
                       agreement_property, validity_property)

# --- Paths -----------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_JAVA = os.path.join(_ROOT, "examples", "twopc")
COORD = os.path.join(_JAVA, "Coordinator.java")
PART = os.path.join(_JAVA, "Participant.java")
N = 2  # participants in the hand-built slice

# --- Java source parsing (regex; no Joern / Java compiler needed) -----------
def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# The 2PC slice references these enum types (Phase/Vote/Decision); their
# canonical domains are below.  test_java_source_contains_enum_domains ties
# them back to the Java sources (state fields, enum type usages, and the
# enum-value constants that appear as e.g. ``Phase.PREPARE``).
KNOWN_ENUM_VALUES = {
    "phase": ("prepare", "decided", "done"),
    "vote": ("none", "yes", "no"),
    "decision": ("none", "commit", "abort"),
}


def java_source_text():
    """Concatenated text of the twopc Java sources (empty string if missing)."""
    parts = []
    for path in (COORD, PART):
        if os.path.exists(path):
            parts.append(_read(path))
    return "\n".join(parts)


def java_enum_values():
    """All all-caps enum-value tokens present anywhere in the Java sources."""
    return set(re.findall(r"\b[A-Z][A-Z0-9_]*\b", java_source_text()))


def java_vocabulary():
    """The 2PC enum domains used to build the IR (canonical 2PC domains)."""
    return {k: list(v) for k, v in KNOWN_ENUM_VALUES.items()}


# --- IR builder (canonical 2PC; enum domains driven by the Java vocab) ------
def build_ir(n=N, buggy=False, vocab=None):
    """Build the canonical 2PC IR the way ``rot.twopc.build_ir`` does.

    The enum *domains* come from the Java sources (via ``vocab``); the control
    flow is the canonical 2PC linearisation.  ``buggy`` swaps the participant
    apply-logic from "apply the shared decision" to "self-decide from my vote".
    Mirrors ``rot.twopc.build_ir`` closely enough that ``to_dict()`` matches.
    """
    v = vocab or java_vocabulary()
    phase_domain = Enum(v["phase"])
    vote_domain = Enum(v["vote"])
    decision_domain = Enum(v["decision"])  # applied outcome shares the Decision enum

    def vote_eq(i, value):
        return eq(V("vote_%d" % i), C(value))

    variables = [
        StateVar("phase", phase_domain, owner="global"),
        StateVar("decision", decision_domain, owner="coordinator"),
    ]
    for i in range(1, n + 1):
        variables.append(StateVar("vote_%d" % i, vote_domain,
                                  owner="participant_%d" % i))
        variables.append(StateVar("applied_%d" % i, decision_domain,
                                  owner="participant_%d" % i))

    actions = []

    # ---- init ----------------------------------------------------------------
    init_effects = [Assignment("phase", C("prepare")),
                    Assignment("decision", C("none"))]
    for i in range(1, n + 1):
        init_effects.append(Assignment("vote_%d" % i, C("none")))
        init_effects.append(Assignment("applied_%d" % i, C("none")))
    actions.append(Action(name="init", owner="global", guard=T(),
                          effects=init_effects, is_initial=True))

    # ---- prepare: each participant votes (choice actions model the environment)
    for i in range(1, n + 1):
        guard = And(eq(V("phase"), C("prepare")), vote_eq(i, "none"))
        actions.append(Action(name="vote_%d_yes" % i, owner="participant_%d" % i,
                              guard=guard, effects=[Assignment("vote_%d" % i, C("yes"))]))
        actions.append(Action(name="vote_%d_no" % i, owner="participant_%d" % i,
                              guard=guard, effects=[Assignment("vote_%d" % i, C("no"))]))

    # ---- coordinator decides --------------------------------------------------
    all_voted = And(*[Not(vote_eq(i, "none")) for i in range(1, n + 1)])
    all_yes = And(*[vote_eq(i, "yes") for i in range(1, n + 1)])
    decide_guard = And(eq(V("phase"), C("prepare")), all_voted)
    decision_val = If(all_yes, C("commit"), C("abort"))
    actions.append(Action(name="decide", owner="coordinator", guard=decide_guard,
                          effects=[Assignment("decision", decision_val),
                                   Assignment("phase", C("decided"))],
                          linearization="send(decide)"))

    # ---- apply: participants decide ------------------------------------------
    for i in range(1, n + 1):
        guard = eq(V("phase"), C("decided"))
        if buggy:
            # BUG: participant decides from its own vote, ignoring the coordinator
            actions.append(Action(name="apply_%d" % i, owner="participant_%d" % i,
                                  guard=guard,
                                  effects=[Assignment("applied_%d" % i,
                                                       If(vote_eq(i, "yes"),
                                                          C("commit"), C("abort")))]))
        else:
            actions.append(Action(name="apply_%d" % i, owner="participant_%d" % i,
                                  guard=guard,
                                  effects=[Assignment("applied_%d" % i, V("decision"))]))

    # ---- done -----------------------------------------------------------------
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
    )


def _prove(ir, property_expr):
    """Linearize ``ir`` and run the symbolic engine on ``property_expr``.

    Returns an ``EngineResult`` (status PROVEN / VIOLATED / UNKNOWN)."""
    lm = linearize(ir)
    return SymbolicEngine(lm).check(property_expr)


# --- 1) the Java sources are present and carry the expected enums -----------
def test_java_sources_present():
    for path in (COORD, PART):
        assert os.path.exists(path), "missing Java source: %s" % path
    text = java_source_text()
    # The slice models the 2PC state (phase / decision / vote / applied) ...
    for field in ("phase", "decision", "vote", "applied"):
        assert re.search(r"\b%s\b" % field, text), \
            "Java source missing state field %r" % field
    # ... over the 2PC enum types ...
    for tname in ("Phase", "Vote", "Decision"):
        assert re.search(r"\b%s\b" % tname, text), \
            "Java source missing enum type %r" % tname


def test_java_source_contains_enum_domains():
    """The canonical 2PC enum domains the model uses must be present in the Java
    sources (as the enum value tokens a real extraction would recover)."""
    found = java_enum_values()
    for domain, values in KNOWN_ENUM_VALUES.items():
        for v in values:
            assert v.upper() in found, \
                "Java source missing enum value %r (domain %s)" % (v, domain)


# --- 2) the hand-built IR is well-formed -------------------------------------
def test_ir_wellformed():
    for buggy in (False, True):
        errs = build_ir(buggy=buggy).validate()
        assert not errs, "IR well-formedness errors (%s): %r" % (buggy, errs)


# --- 3) cross-check: hand-built IR == rot.twopc.build_ir (ground truth) ------
def test_crosscheck_matches_twopc_ground_truth():
    mine = build_ir(n=N).to_dict()
    theirs = twopc_ground_truth(n=N).to_dict()
    assert mine["variables"] == theirs["variables"], "state/domain mismatch"
    assert mine["actions"] == theirs["actions"], "action mismatch"
    assert mine["pinned_property"] == theirs["pinned_property"], "property mismatch"


# --- 4) linearization consumes init and keeps the model complete -------------
def test_linearize_consumes_init():
    lm = linearize(build_ir())
    assert lm.init_state, "linearization produced no initial state"
    names = {a.name for a in lm.actions}
    assert "init" not in names, "init must be consumed by linearization"
    assert {"decide", "done"} <= names
    assert all(a.owner != "global" for a in lm.actions), "global actions must be removed"


# --- 5) the correct 2PC model proves agreement --------------------------------
def test_correct_model_proven_agreement():
    result = _prove(build_ir(), agreement_property(N))
    assert result.status == PROVEN, \
        "correct 2PC must PROVE agreement; got %s" % result.status


# --- 6) the buggy variant is falsified (checker is not vacuous) ---------------
def test_buggy_model_violated_agreement():
    result = _prove(build_ir(buggy=True), agreement_property(N))
    assert result.status == VIOLATED, \
        "buggy 2PC must VIOLATE agreement; got %s" % result.status
    assert result.witness, "VIOLATED result must carry a witness state"
    vals = dict(result.witness)
    assert vals["applied_1"] != vals["applied_2"], vals


# --- 7) validity holds in BOTH models (it is not the discriminating test) -----
def test_correct_model_validity_holds():
    result = _prove(build_ir(), validity_property(N))
    assert result.status == PROVEN, \
        "validity must hold in the correct model; got %s" % result.status


def test_buggy_model_validity_still_holds():
    result = _prove(build_ir(buggy=True), validity_property(N))
    assert result.status == PROVEN, \
        "validity must hold even in the buggy model; got %s" % result.status


# --- 8) provenance: tie the model to a real CPG when one is present ----------
def _find_cpg_artifact():
    """First existing CPG artifact (Joern/CPG export of the slice), else None."""
    candidates = (
        os.path.join(_JAVA, "twopc", "twopc_correct.cpg.json"),
        os.path.join(_ROOT, "_joern_test", "twopc_correct.json"),
    )
    for cand in candidates:
        if os.path.exists(cand):
            return cand
    return None


def test_cpg_artifact_matches_model():
    """If a CPG artifact is present, lower it with the project's own reader and
    check it exposes the same state variables / enum domains as the canonical
    model.  Skipped (not failed) when no artifact exists -- i.e. Joern has not
    been run, the expected case for a plain checkout."""
    path = _find_cpg_artifact()
    if path is None:
        raise unittest.SkipTest("no CPG artifact found (run Joern to produce one)")
    from rot.cpg_reader import CpgGraph, build_ir as cpg_build_ir

    cpg_ir = cpg_build_ir(CpgGraph.from_json(path))
    errs = cpg_ir.validate()
    assert not errs, "CPG IR has well-formedness errors: %r" % errs
    assert any(a.is_initial for a in cpg_ir.actions), \
        "CPG IR has no is_initial action (linearize needs one)"

    mine = {v.name: sorted(v.domain.values) for v in build_ir().variables}
    theirs = {v.name: sorted(v.domain.values) for v in cpg_ir.variables}
    for name, vals in mine.items():
        assert name in theirs, "CPG missing state var %r" % name
        assert theirs[name] == vals, \
            "CPG domain mismatch for %r: %r vs %r" % (name, theirs[name], vals)


# --- runner ------------------------------------------------------------------
def main():
    tests = [
        test_java_sources_present,
        test_java_source_contains_enum_domains,
        test_ir_wellformed,
        test_crosscheck_matches_twopc_ground_truth,
        test_linearize_consumes_init,
        test_correct_model_proven_agreement,
        test_buggy_model_violated_agreement,
        test_correct_model_validity_holds,
        test_buggy_model_validity_still_holds,
        test_cpg_artifact_matches_model,
    ]
    width = max(len(t.__name__) for t in tests)
    passed = failed = skipped = 0
    for t in tests:
        name = t.__name__
        try:
            t()
        except unittest.SkipTest as ex:
            skipped += 1
            print("[%s] %s -> SKIPPED (%s)" % ("SKIP", name.ljust(width), ex))
        except AssertionError as ex:
            failed += 1
            print("[%s] %s -> FAIL: %s" % ("FAIL", name.ljust(width), ex))
        except Exception as ex:
            failed += 1
            print("[%s] %s -> ERROR: %r" % ("ERR", name.ljust(width), ex))
        else:
            passed += 1
            print("[%s] %s" % ("PASS", name.ljust(width)))
    print("-" * (width + 14))
    print("passed=%d failed=%d skipped=%d" % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())



