# -*- coding: utf-8 -*-
"""CPG-3 gate: the static <-> formal soundness cross-check (condition (S)).

The CPG is the ground truth (``G``); the lowered ``ProtocolIR`` is the
abstraction (``A(G)``); the engine verdict is the formal claim.  This gate
exercises ``rot.cpg_crosscheck`` -- the check that a verdict is *compatible
with the ground truth*:

    taintPath(G, P)  =>  not Proven(M(A(G)), P)

i.e. if the ground-truth CPG carries a taint-critical path that threatens the
pinned property, the abstraction must NOT prove that property.  A PROVEN built
on a dropped taint-critical dataflow edge is a silent false negative; the
cross-check downgrades it to UNKNOWN (advisory ``unsound_abstraction``) and
names the dropped edge.  The cross-check never *hides* a real violation: a
VIOLATED whose threat the static single-path analysis cannot see is tagged
``concurrency_only`` (the model checker's value-add) and stands.

Two layers are tested:

* **the pure function** -- :func:`check_abstraction_soundness` +
  :func:`apply_soundness` run on hand-built verdicts and the CPG-2 fixture
  models (no engine), covering every cell of the 2x2 (threat present/absent x
  PROVEN/VIOLATED) for both P1 shapes, plus the not-applicable cells;
* **the gate** -- the same verdicts flow through ``verify_candidate(cpg=...)``
  (the real engine) and carry the result on
  ``evidence["abstraction_soundness"]``.

The fixture models come from ``test_cpg_extraction`` (the CPG-2 gate), so this
gate reuses the same ground-truth scrapes -- one structural vocabulary.

Run: python -m pytest tests/test_cpg_crosscheck.py -v
"""

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rot.config import Config
from rot.cegar import verify_candidate
from rot.frontends.code import PATTERN_BUDGET, PATTERN_LABEL_FLOW
from rot.frontends.cpg import extract_cpg
from rot.lower import lower_candidate
from rot.verdicts import (Verdict, PROVEN, VIOLATED, UNKNOWN,
                          UNSOUND_ABSTRACTION, CONCURRENCY_ONLY)
# SoundnessResult *status* codes (the 2x2 cells) -- aliased ``SS_*`` to keep
# them distinct from the verdict advisory codes of the same name.
from rot.cpg_crosscheck import (AGREEMENT, NOT_APPLICABLE,
                                UNSOUND as SS_UNSOUND,
                                CONCURRENCY_ONLY as SS_CONCURRENCY_ONLY,
                                check_abstraction_soundness, apply_soundness)
from test_cpg_extraction import (_cpg_model, _bypassable_budget_model,
                                 _guarded_label_flow_model, _no_control_model)

CFG = Config(max_states=100000)


class _FakeIR(object):
    """A stand-in for a lowered ``ProtocolIR``: the cross-check reads only
    its ``metadata['pattern']`` (the P1 shape), so a namespace is enough for
    the pure-function tests."""

    def __init__(self, pattern):
        self.metadata = {"pattern": pattern}
        self.name = pattern


def _ir(pattern):
    return _FakeIR(pattern)


def _proven(name="control"):
    return Verdict.proven(name, "symbolic")


def _violated(name="control", counterexample=None):
    return Verdict.violated(name, "symbolic",
                            counterexample=counterexample
                            or {"witness": True})


def _unknown(name="control"):
    return Verdict.unknown(name, "symbolic")


# The four ground-truth scrapes (from the CPG-2 gate), keyed by the (shape,
# threat) quadrant they represent:
#   * bypassable budget   -> budget,      threat present
#   * enforced budget     -> budget,      threat absent
#   * bypassable label/flow -> label_flow, threat present
#   * enforced label/flow  -> label_flow, threat absent
BUDGET_THREAT = _bypassable_budget_model
BUDGET_SAFE = _cpg_model            # its budget control is ENFORCED
LABEL_THREAT = _cpg_model           # its label/flow control is BYPASSABLE
LABEL_SAFE = _guarded_label_flow_model
NO_CONTROL = _no_control_model


class SoundnessCheckTest(unittest.TestCase):
    """``check_abstraction_soundness`` -- the pure (S) check, no engine.

    For each P1 shape and each threat quadrant (threat present / absent), the
    check maps the verdict to the right 2x2 cell:

    ===============  ==================  ==================
    verdict          threat present      threat absent
    ===============  ==================  ==================
    PROVEN           UNSOUND             AGREEMENT
    VIOLATED         AGREEMENT           CONCURRENCY_ONLY
    ===============  ==================  ==================
    """

    def _check(self, model, shape, verdict):
        return check_abstraction_soundness(model, _ir(shape), verdict,
                                           shape=shape)

    # -- budget shape ---------------------------------------------------------
    def test_budget_threat_proven_is_unsound(self):
        r = self._check(BUDGET_THREAT(), PATTERN_BUDGET, _proven())
        self.assertEqual(r.status, SS_UNSOUND)
        self.assertTrue(r.threat)
        self.assertIsNotNone(r.dropped_edge, "the dropped edge must be named")

    def test_budget_threat_violated_is_agreement(self):
        r = self._check(BUDGET_THREAT(), PATTERN_BUDGET, _violated())
        self.assertEqual(r.status, AGREEMENT)
        self.assertTrue(r.threat)
        self.assertIsNone(r.dropped_edge)

    def test_budget_safe_proven_is_agreement(self):
        r = self._check(BUDGET_SAFE(), PATTERN_BUDGET, _proven())
        self.assertEqual(r.status, AGREEMENT)
        self.assertFalse(r.threat)

    def test_budget_safe_violated_is_concurrency_only(self):
        r = self._check(BUDGET_SAFE(), PATTERN_BUDGET, _violated())
        self.assertEqual(r.status, SS_CONCURRENCY_ONLY)
        self.assertFalse(r.threat)

    # -- label/flow shape -----------------------------------------------------
    def test_label_threat_proven_is_unsound(self):
        r = self._check(LABEL_THREAT(), PATTERN_LABEL_FLOW, _proven())
        self.assertEqual(r.status, SS_UNSOUND)
        self.assertTrue(r.threat)
        self.assertIsNotNone(r.dropped_edge, "the dropped edge must be named")

    def test_label_threat_violated_is_agreement(self):
        r = self._check(LABEL_THREAT(), PATTERN_LABEL_FLOW, _violated())
        self.assertEqual(r.status, AGREEMENT)
        self.assertTrue(r.threat)

    def test_label_safe_proven_is_agreement(self):
        r = self._check(LABEL_SAFE(), PATTERN_LABEL_FLOW, _proven())
        self.assertEqual(r.status, AGREEMENT)
        self.assertFalse(r.threat)

    def test_label_safe_violated_is_concurrency_only(self):
        r = self._check(LABEL_SAFE(), PATTERN_LABEL_FLOW, _violated())
        self.assertEqual(r.status, SS_CONCURRENCY_ONLY)
        self.assertFalse(r.threat)

    # -- not-applicable cells -------------------------------------------------
    def test_undecided_verdict_is_not_applicable(self):
        # (S) constrains only decided verdicts; UNKNOWN is recorded, untouched.
        r = self._check(BUDGET_THREAT(), PATTERN_BUDGET, _unknown())
        self.assertEqual(r.status, NOT_APPLICABLE)
        self.assertTrue(r.threat, "the threat is still recorded for context")

    def test_no_control_in_cpg_is_not_applicable(self):
        r = self._check(NO_CONTROL(), PATTERN_BUDGET, _proven())
        self.assertEqual(r.status, NOT_APPLICABLE)
        self.assertIsNone(r.threat, "no control in G => cannot judge")

    def test_no_control_in_cpg_label_is_not_applicable(self):
        r = self._check(NO_CONTROL(), PATTERN_LABEL_FLOW, _proven())
        self.assertEqual(r.status, NOT_APPLICABLE)
        self.assertIsNone(r.threat)

    # -- input discipline -----------------------------------------------------
    def test_rejects_non_cpg(self):
        with self.assertRaises(TypeError):
            check_abstraction_soundness(object(), _ir(PATTERN_BUDGET),
                                        _proven(), shape=PATTERN_BUDGET)

    def test_rejects_non_verdict(self):
        with self.assertRaises(TypeError):
            check_abstraction_soundness(BUDGET_SAFE(), _ir(PATTERN_BUDGET),
                                        object(), shape=PATTERN_BUDGET)

    def test_rejects_unknown_shape(self):
        with self.assertRaises(ValueError):
            self._check(BUDGET_SAFE(), "bogus", _proven())

    def test_shape_from_ir_metadata(self):
        # ``shape`` omitted: the P1 shape is read from ir.metadata['pattern'].
        r = check_abstraction_soundness(BUDGET_SAFE(), _ir(PATTERN_BUDGET),
                                        _proven())
        self.assertEqual(r.status, AGREEMENT)
        self.assertEqual(r.shape, PATTERN_BUDGET)


class ApplySoundnessTest(unittest.TestCase):
    """``apply_soundness`` -- the fail-closed application of a result."""

    def _result(self, model, shape, verdict):
        return check_abstraction_soundness(model, _ir(shape), verdict,
                                           shape=shape)

    def test_unsound_downgrades_proven_to_unknown(self):
        v = _proven()
        r = self._result(BUDGET_THREAT(), PATTERN_BUDGET, v)
        out = apply_soundness(v, r)
        self.assertEqual(out.status, UNKNOWN)
        self.assertNotEqual(out, v, "a fresh verdict, not the original")
        self.assertIn(UNSOUND_ABSTRACTION, out.advisories)
        self.assertIsNone(out.counterexample, "no proof, no counterexample")
        self.assertIn("dropped", (out.note or "").lower(),
                      "the note names the dropped edge")

    def test_unsound_does_not_fire_on_non_proven(self):
        # The (S) cell it forbids is PROVEN-only; a VIOLATED is untouched.
        v = _violated()
        r = self._result(BUDGET_THREAT(), PATTERN_BUDGET, v)  # AGREEMENT here
        self.assertEqual(apply_soundness(v, r), v)

    def test_concurrency_only_tags_violated(self):
        ce = {"completed": 0, "inflight": 3}
        v = _violated(counterexample=ce)
        r = self._result(BUDGET_SAFE(), PATTERN_BUDGET, v)
        out = apply_soundness(v, r)
        self.assertEqual(out.status, VIOLATED, "the violation stands")
        self.assertIn(CONCURRENCY_ONLY, out.advisories)
        self.assertEqual(out.counterexample, ce, "the witness is preserved")

    def test_concurrency_only_does_not_fire_on_proven(self):
        v = _proven()
        r = self._result(BUDGET_SAFE(), PATTERN_BUDGET, v)  # AGREEMENT here
        self.assertEqual(apply_soundness(v, r), v)

    def test_agreement_is_identity(self):
        v = _proven()
        r = self._result(BUDGET_SAFE(), PATTERN_BUDGET, v)
        self.assertEqual(apply_soundness(v, r), v)

    def test_not_applicable_is_identity(self):
        v = _proven()
        r = self._result(NO_CONTROL(), PATTERN_BUDGET, v)
        self.assertEqual(apply_soundness(v, r), v)

    def test_unsound_result_serializable(self):
        r = self._result(BUDGET_THREAT(), PATTERN_BUDGET, _proven())
        d = r.to_dict()
        self.assertEqual(d["status"], SS_UNSOUND)
        self.assertTrue(d["threat"])
        self.assertIn("dropped_edge", d)
        self.assertIn("detail", d)
        self.assertIn("note", d)


class CrossCheckGateTest(unittest.TestCase):
    """The cross-check wired into ``verify_candidate(cpg=...)`` -- the real
    engine, with the result stamped on ``evidence["abstraction_soundness"]``.

    These exercise the *agreement* cells end-to-end: the engine's verdict and
    the ground truth agree (the common case), and the evidence carries the
    cross-check record.  (The UNSOUND cell is a property of the *abstraction*
    dropping an edge; it is pinned by :class:`ApplySoundnessTest` on the pure
    functions, since a faithful CPG->IR lowering does not drop the edge.)
    """

    def _gate(self, model, shape):
        cand = extract_cpg(model, shape=shape)
        if cand.out_of_scope:
            return Verdict.out_of_scope("cpg", "symbolic", reason=cand.reason)
        ir = lower_candidate(cand)
        return verify_candidate(ir, CFG, cpg=model)

    def _ss(self, v):
        return v.evidence["abstraction_soundness"]

    def test_budget_enforced_proven_agreement(self):
        v = self._gate(BUDGET_SAFE(), PATTERN_BUDGET)
        self.assertTrue(v.is_proven())
        self.assertEqual(self._ss(v)["status"], AGREEMENT)
        self.assertFalse(self._ss(v)["threat"])

    def test_budget_bypassable_violated_agreement(self):
        v = self._gate(BUDGET_THREAT(), PATTERN_BUDGET)
        self.assertTrue(v.is_violated())
        self.assertEqual(self._ss(v)["status"], AGREEMENT)
        self.assertTrue(self._ss(v)["threat"])

    def test_label_bypassable_violated_agreement(self):
        v = self._gate(LABEL_THREAT(), PATTERN_LABEL_FLOW)
        self.assertTrue(v.is_violated())
        self.assertEqual(self._ss(v)["status"], AGREEMENT)
        self.assertTrue(self._ss(v)["threat"])

    def test_label_enforced_proven_agreement(self):
        v = self._gate(LABEL_SAFE(), PATTERN_LABEL_FLOW)
        self.assertTrue(v.is_proven())
        self.assertEqual(self._ss(v)["status"], AGREEMENT)
        self.assertFalse(self._ss(v)["threat"])

    def test_out_of_scope_has_no_soundness(self):
        v = self._gate(NO_CONTROL(), PATTERN_BUDGET)
        self.assertTrue(v.is_out_of_scope())
        self.assertNotIn("abstraction_soundness", v.evidence)

    def test_without_cpg_no_soundness(self):
        # The cross-check only runs when the caller passes the ground truth.
        cand = extract_cpg(BUDGET_SAFE(), shape=PATTERN_BUDGET)
        v = verify_candidate(lower_candidate(cand), CFG)
        self.assertTrue(v.is_proven())
        self.assertNotIn("abstraction_soundness", v.evidence)