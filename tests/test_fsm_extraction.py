# -*- coding: utf-8 -*-
"""FSM-extraction gate (``rot.fsmextract``): recovers ``(Q, Sigma, delta,
s0, F)`` for 2PC / ZAB / PBFT and synthesises a valid IR.

This is the gate for **Phase 1** (``§2.4`` + ``§2.5``) of the Joern-primary
rework (``docs/joern-primary-ab-plan.md``) -- the *FSM extraction* lift.  It
builds on CPG-1 (dataflow) + CPG-2 (producer) of the integration plan.  It
feeds :class:`rot.frontends.cpg_model.CpgModel` artifacts (with the control
half -- FILE / NAMESPACE / METHOD_PARAMETER / LOCAL / BLOCK / CONTROL_STRUCTURE
/ CALL plus the CDG / DOMINATE / CONTAINS edges -- populated) through
:func:`rot.fsmextract.extract_fsm` and asserts:

  * **2PC** -- the paper's flagship case: the extractor recovers
    ``Q = {prepare, decided, done}``, ``Sigma = {vote_1, vote_2, vote_3}``,
    ``s0 = prepare``, ``F = {done}``, the two transitions, shape ``2PC``, and a
    :class:`rot.ir.ProtocolIR` that ``validate()``s, round-trips, carries
    ``alphabet``/``final_states``, and from which every final state is
    reachable from ``s0`` (the liveness half the FSM adds over the dataflow
    model);
  * **ZAB** / **PBFT** -- the other two protocol shapes are recognised by the
    E2/E3 shape heuristic (structural, not fixture-memorized: the state /
    input vocabularies differ from 2PC);
  * **fallbacks** -- a method with no loop, or with no bounded discrete state
    variable, is ``OUT_OF_SCOPE``; a candidate whose transitions leave the
    state domain is ``REJECTED`` (the sound fallback: surface to a human,
    never a silent UNKNOWN / broken FSM);
  * **narrow waist** -- ``rot/fsmextract.py`` imports only ``rot.ir`` + stdlib.

The fixtures are built in-memory (the control-half records are the unit under
test) and the 2PC one is also committed as ``tests/fixtures/cpg/twopc.cpg.json``
for provenance; the round-trip test pins that the committed artifact matches
the in-memory model.  Pure stdlib, Python 3.6 compatible.

Run: python -m pytest tests/test_fsm_extraction.py -v
"""

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rot.frontends.cpg_model import (CpgBlock, CpgEdge, CpgLocal, CpgMethod,
                                     CpgModel, CpgParam, CpgType,
                                     EDGE_CDG, EDGE_CONTAINS, EDGE_REACHING_DEF)
import rot.fsmextract as fe
from test_narrow_waist import scan_source

FIX_2PC = os.path.join(_ROOT, "tests", "fixtures", "cpg", "twopc.cpg.json")


# ---------------------------------------------------------------------------
# fixture builder (the control-half records are the unit under test)
# ---------------------------------------------------------------------------
def _fsm_cpg(owner, enum_name, type_owner, states, inputs, transitions):
    """A CPG model whose method ``run`` is an FSM over ``states``.

    ``transitions`` is a list of ``(from, to, input)`` triples (``"*"`` /
    ``"epsilon"`` for the ANY_STATE / no-input sentinels).  The model carries
    the full control half: an enum ``type`` (Q), an IN ``param`` per input
    (Sigma), a reassignable ``local`` state variable (Q2), a ``WHILE`` loop
    (Q1), an ``IF`` branch per transition (Q4), and the CONTAINS / REACHING_DEF
    / CDG edges (Q3 alphabet + Q4 transitions + Q5 s0/F).
    """
    M = owner + ".run"
    types = [CpgType(enum_name, type_owner + "." + enum_name, owner=type_owner,
                     constants=list(states))]
    params = [CpgParam(i, M + "#" + i, type_name="boolean", owner=M,
                       argument_index=k, direction="IN")
              for k, i in enumerate(inputs)]
    locals_ = [CpgLocal("phase", M + "#phase", type_name=enum_name, owner=M,
                        constant=None)]
    loop = M + "#loop"
    blocks = [CpgBlock(CpgBlock.KIND_CONTROL_STRUCTURE, "loop", loop, owner=M,
                       cs_type="WHILE", line=10)]
    edges = [CpgEdge(EDGE_CONTAINS, M, loop)]
    for i in inputs:
        edges.append(CpgEdge(EDGE_REACHING_DEF, i, loop))
    for idx, (frm, to, inp) in enumerate(transitions):
        b = M + "#if%d" % idx
        blocks.append(CpgBlock(CpgBlock.KIND_CONTROL_STRUCTURE, "if%d" % idx,
                               b, owner=M, cs_type="IF", line=20 + idx))
        edges.append(CpgEdge(EDGE_CONTAINS, loop, b))
        if frm != fe.ANY_STATE:
            edges.append(CpgEdge(EDGE_REACHING_DEF, frm, b))
        if inp != fe.EPSILON:
            edges.append(CpgEdge(EDGE_REACHING_DEF, inp, b))
        edges.append(CpgEdge(EDGE_CDG, b, to))
    methods = [CpgMethod("run", M, owner=owner, line=5, end_line=60, calls=[],
                         read_fields=[], written_fields=[], defs=["phase"],
                         args=list(inputs), ret_type="void")]
    return CpgModel(meta={"source": owner + ".java"}, types=types, fields=[],
                    methods=methods, params=params, locals_=locals_,
                    blocks=blocks, calls=[], edges=edges, taint_sources=[],
                    taint_sinks=[])
def _twopc_cpg():
    """2PC: a prepare/decided/done phase machine driven by the participant
    votes (the paper's flagship case study)."""
    return _fsm_cpg(
        "org.rotn.twopc.Coordinator", "Phase", "org.rotn.twopc",
        states=["prepare", "decided", "done"],
        inputs=["vote_1", "vote_2", "vote_3"],
        transitions=[("prepare", "decided", "vote_1"),
                     ("decided", "done", fe.EPSILON)])


def _zab_cpg():
    """ZAB: an epoch/apply phase machine driven by the leader + log entries."""
    return _fsm_cpg(
        "org.rotn.zab.Follower", "ZabPhase", "org.rotn.zab",
        states=["idle", "epoch", "apply"],
        inputs=["leader", "log_entry"],
        transitions=[("idle", "epoch", "leader"),
                     ("epoch", "apply", "log_entry")])


def _pbft_cpg():
    """PBFT: a prepare/commit phase machine driven by quorum + messages."""
    return _fsm_cpg(
        "org.rotn.pbft.Node", "PbftPhase", "org.rotn.pbft",
        states=["idle", "prepare", "commit"],
        inputs=["message", "quorum"],
        transitions=[("idle", "prepare", "message"),
                     ("prepare", "commit", "quorum")])


def _no_loop_cpg():
    """A method with a state variable but NO loop -> OUT_OF_SCOPE (Q1)."""
    M = "org.rotn.noloop.S.run"
    return CpgModel(
        meta={"source": "noloop/S.java"},
        types=[CpgType("Phase", "org.rotn.noloop.Phase",
                       owner="org.rotn.noloop", constants=["a", "b"])],
        methods=[CpgMethod("run", M, owner="org.rotn.noloop.S", line=5,
                           end_line=8, calls=[], read_fields=[],
                           written_fields=[], defs=["phase"], args=[],
                           ret_type="void")],
        params=[],
        locals_=[CpgLocal("phase", M + "#phase", type_name="Phase",
                          owner=M, constant=None)],
        blocks=[], calls=[], edges=[],
        taint_sources=[], taint_sinks=[])


def _no_state_var_cpg():
    """A loop with NO bounded discrete state variable -> OUT_OF_SCOPE (Q2)."""
    M = "org.rotn.nostate.S.run"
    return CpgModel(
        meta={"source": "nostate/S.java"},
        types=[CpgType("Util", "org.rotn.nostate.Util",
                       owner="org.rotn.nostate")],
        methods=[CpgMethod("run", M, owner="org.rotn.nostate.S", line=5,
                           end_line=8, calls=[], read_fields=[],
                           written_fields=[], defs=["count"], args=[],
                           ret_type="void")],
        params=[],
        locals_=[CpgLocal("count", M + "#count", type_name="int", owner=M,
                          constant=None)],
        blocks=[CpgBlock(CpgBlock.KIND_CONTROL_STRUCTURE, "loop", M + "#loop",
                         owner=M, cs_type="WHILE", line=6)],
        calls=[],
        edges=[CpgEdge(EDGE_CONTAINS, M, M + "#loop")],
        taint_sources=[], taint_sinks=[])


def _rejected_cpg():
    """A loop + state variable but NO transition advances the state ->
    REJECTED (Q4)."""
    M = "org.rotn.rej.S.run"
    return CpgModel(
        meta={"source": "rej/S.java"},
        types=[CpgType("Phase", "org.rotn.rej.Phase", owner="org.rotn.rej",
                       constants=["a", "b"])],
        methods=[CpgMethod("run", M, owner="org.rotn.rej.S", line=5,
                           end_line=8, calls=[], read_fields=[],
                           written_fields=[], defs=["phase"], args=["x"],
                           ret_type="void")],
        params=[CpgParam("x", M + "#x", type_name="boolean", owner=M,
                         argument_index=0, direction="IN")],
        locals_=[CpgLocal("phase", M + "#phase", type_name="Phase",
                          owner=M, constant=None)],
        blocks=[CpgBlock(CpgBlock.KIND_CONTROL_STRUCTURE, "loop", M + "#loop",
                         owner=M, cs_type="WHILE", line=6),
                CpgBlock(CpgBlock.KIND_CONTROL_STRUCTURE, "if0", M + "#if0",
                         owner=M, cs_type="IF", line=7)],
        calls=[],
        edges=[CpgEdge(EDGE_CONTAINS, M, M + "#loop"),
               CpgEdge(EDGE_CONTAINS, M + "#loop", M + "#if0"),
               CpgEdge(EDGE_REACHING_DEF, "x", M + "#loop")],
        taint_sources=[], taint_sinks=[])
class TwopcGateTest(unittest.TestCase):
    """The 2PC flagship case: the extractor recovers the full 5-tuple and the
    shape is recognised as 2PC (E2/E3)."""

    def setUp(self):
        self.result = fe.extract_fsm(_twopc_cpg())

    def test_extracted_status(self):
        self.assertEqual(self.result.status, fe.EXTRACTED,
                         "reason: %s" % self.result.reason)

    def test_shape_is_2pc(self):
        self.assertEqual(self.result.shape, fe.SHAPE_2PC)

    def test_states(self):
        self.assertEqual(sorted(self.result.fs["q"]),
                         ["decided", "done", "prepare"])

    def test_alphabet(self):
        self.assertEqual(self.result.fs["sigma"],
                         ["vote_1", "vote_2", "vote_3"])

    def test_transitions(self):
        delta = {(t["from"], t["to"], t["input"]) for t in self.result.fs["delta"]}
        self.assertIn(("prepare", "decided", "vote_1"), delta)
        self.assertIn(("decided", "done", fe.EPSILON), delta)

    def test_initial_state(self):
        self.assertEqual(self.result.fs["s0"], "prepare")

    def test_final_states(self):
        self.assertEqual(self.result.fs["f"], ["done"])


class ShapeRecognitionTest(unittest.TestCase):
    """The other two protocol shapes are recognised structurally (E3): the
    state/input vocabularies differ from 2PC, so recognition is not
    fixture-memorized."""

    def test_zab_shape(self):
        r = fe.extract_fsm(_zab_cpg())
        self.assertEqual(r.status, fe.EXTRACTED, "reason: %s" % r.reason)
        self.assertEqual(r.shape, fe.SHAPE_ZAB)
        self.assertEqual(sorted(r.fs["q"]), ["apply", "epoch", "idle"])
        self.assertEqual(r.fs["s0"], "idle")
        self.assertEqual(r.fs["f"], ["apply"])

    def test_pbft_shape(self):
        r = fe.extract_fsm(_pbft_cpg())
        self.assertEqual(r.status, fe.EXTRACTED, "reason: %s" % r.reason)
        self.assertEqual(r.shape, fe.SHAPE_PBFT)
        self.assertEqual(sorted(r.fs["q"]), ["commit", "idle", "prepare"])
        self.assertEqual(r.fs["s0"], "idle")
        self.assertEqual(r.fs["f"], ["commit"])


class FallbackTest(unittest.TestCase):
    """The sound fallbacks (E2): OUT_OF_SCOPE / REJECTED with a reason --
    never a silent UNKNOWN or a broken FSM."""

    def test_no_loop_is_out_of_scope(self):
        r = fe.extract_fsm(_no_loop_cpg())
        self.assertEqual(r.status, fe.OUT_OF_SCOPE)
        self.assertIsNotNone(r.reason)
        self.assertIsNone(r.fs)
        self.assertIsNone(r.ir)

    def test_no_state_var_is_out_of_scope(self):
        r = fe.extract_fsm(_no_state_var_cpg())
        self.assertEqual(r.status, fe.OUT_OF_SCOPE)
        self.assertIsNotNone(r.reason)
        self.assertIsNone(r.fs)

    def test_no_transitions_is_rejected(self):
        r = fe.extract_fsm(_rejected_cpg())
        self.assertEqual(r.status, fe.REJECTED)
        self.assertIsNotNone(r.reason)
        self.assertIsNone(r.fs)
        self.assertIsNone(r.ir)


class IrSynthesisTest(unittest.TestCase):
    """The synthesised IR is valid, round-trips, carries the 5-tuple's
    Sigma + F, and F is reachable from s0 (the liveness half)."""

    def setUp(self):
        self.result = fe.extract_fsm(_twopc_cpg())
        self.ir = self.result.ir

    def test_ir_validates(self):
        self.assertEqual(self.ir.validate(), [],
                         "IR validation errors: %s" % self.ir.validate())

    def test_ir_round_trips(self):
        import rot.ir as ir
        self.assertEqual(self.ir, ir.ProtocolIR.from_dict(self.ir.to_dict()))

    def test_ir_carries_alphabet(self):
        self.assertEqual(self.ir.alphabet, ["vote_1", "vote_2", "vote_3"])

    def test_ir_carries_final_states(self):
        self.assertEqual(self.ir.final_states, ["done"])

    def test_ir_carries_s0_in_metadata(self):
        self.assertEqual(self.ir.metadata["s0"], "prepare")
        self.assertEqual(self.ir.metadata["F"], ["done"])

    def test_final_reachable_from_s0(self):
        """BFS over delta from s0 must reach every state in F (liveness)."""
        delta = self.result.fs["delta"]
        adj = {}
        for t in delta:
            frm = t["from"] if t["from"] != fe.ANY_STATE else None
            if frm is None:
                # an ANY_STATE transition is reachable from every state
                for s in self.result.fs["q"]:
                    adj.setdefault(s, set()).add(t["to"])
            else:
                adj.setdefault(frm, set()).add(t["to"])
        start = self.result.fs["s0"]
        seen, stack = set(), [start]
        while stack:
            s = stack.pop()
            if s in seen:
                continue
            seen.add(s)
            stack.extend(adj.get(s, ()))
        for f in self.result.fs["f"]:
            self.assertIn(f, seen, "final state %r not reachable from %r"
                          % (f, start))
class NarrowWaistTest(unittest.TestCase):
    """``rot/fsmextract.py`` respects the narrow waist: it imports only
    ``rot.ir`` + the standard library (no front-end / solver / emitter)."""

    def test_fsmextract_imports_only_ir_and_stdlib(self):
        path = os.path.join(_ROOT, "rot", "fsmextract.py")
        with open(path, "r") as fh:
            for (line, target) in scan_source(fh.read()):
                self.fail("rot/fsmextract.py:%d imports %r -- crossed the "
                          "narrow waist" % (line, target))


class CommittedFixtureTest(unittest.TestCase):
    """The committed 2PC CPG artifact (``tests/fixtures/cpg/twopc.cpg.json``)
    round-trips and, loaded from disk, extracts to the same FSM as the
    in-memory model (provenance + artifact stability)."""

    def test_fixture_round_trips(self):
        self.assertTrue(os.path.exists(FIX_2PC),
                        "committed fixture missing: %s" % FIX_2PC)
        from_disk = CpgModel.from_file(FIX_2PC)
        self.assertEqual(from_disk.to_dict(), _twopc_cpg().to_dict(),
                         "committed 2PC fixture drifted from the in-memory "
                         "model")

    def test_loaded_fixture_extracts_2pc(self):
        from_disk = CpgModel.from_file(FIX_2PC)
        r = fe.extract_fsm(from_disk)
        self.assertEqual(r.status, fe.EXTRACTED, "reason: %s" % r.reason)
        self.assertEqual(r.shape, fe.SHAPE_2PC)
        self.assertEqual(sorted(r.fs["q"]), ["decided", "done", "prepare"])
        self.assertEqual(r.fs["s0"], "prepare")
        self.assertEqual(r.fs["f"], ["done"])


if __name__ == "__main__":
    unittest.main(verbosity=2)