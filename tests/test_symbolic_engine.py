# -*- coding: utf-8 -*-
"""Tests for ``rot.smtz3.SymbolicSpendcap`` -- the SMT leg with SYMBOLIC
(uninterpreted) ``AMOUNT`` / ``CAP`` (Phase 2 items 2 + 3).

Unlike the concrete ``SMTBackend`` (which pins ``AMOUNT=100`` / ``CAP=200``),
the symbolic leg re-encodes the spend-cap shape with ``AMOUNT`` and ``CAP`` as
*free* Z3 ``Int`` constants, so the proof holds for **all values** of the
amount and the cap.  Two discharges are covered here:

  * item 2 (``bounded_check``)   -- the obligation for all ``H``-step traces,
    all values (bounded in trace length, unbounded in amount/cap);
  * item 3 (``inductive_check``) -- the pinned property is an inductive
    invariant, i.e. PROVEN for **any number of concurrent requests**.

The safe (request-sum / ``correct``) variant is PROVEN; the buggy
(response-sum) variant is VIOLATED with a concrete counterexample.  The
verdicts carry the ``smtz3-symbolic`` engine label (the "which engine minted
it" requirement).

Run: python tests/test_symbolic_engine.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.spendcap import build_ir
from rot.invariants import spendcap_within_cap
from rot.smtz3 import SMTBackend, SYMBOLIC_ENGINE, SymbolicSpendcap

try:
    import z3  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SymbolicSpendcapSafetyTest(unittest.TestCase):
    """The combined symbolic SMT leg (``verify_safety_symbolic``)."""

    def _leg(self, buggy):
        ir = build_ir(buggy=buggy)
        prop = spendcap_within_cap()
        return SymbolicSpendcap(ir).verify_safety_symbolic(prop)

    def test_correct_variant_is_proven(self):
        verdict = self._leg(buggy=False)
        self.assertEqual(verdict.status, "proven")
        self.assertEqual(verdict.engine, SYMBOLIC_ENGINE)
        self.assertEqual(verdict.property_name, "spendcap_within_cap")
        self.assertIsNone(verdict.counterexample)
        self.assertEqual(verdict.property_kind, "safety")

    def test_buggy_variant_is_violated(self):
        verdict = self._leg(buggy=True)
        self.assertEqual(verdict.status, "violated")
        self.assertEqual(verdict.engine, SYMBOLIC_ENGINE)
        self.assertEqual(verdict.violation_code, "POLICY_DENIAL")
        self.assertIsInstance(verdict.counterexample, dict)
        self.assertIn("completed", verdict.counterexample)
        self.assertIn("inflight", verdict.counterexample)

    def test_proven_is_unbounded_in_concurrency(self):
        """Item 3: the PROVEN note is the unbounded (inductive) result."""
        verdict = self._leg(buggy=False)
        self.assertEqual(verdict.status, "proven")
        self.assertIn("ANY number of concurrent requests", verdict.note)
        self.assertIn("inductive", verdict.note)

    def test_buggy_note_names_the_open_guard(self):
        verdict = self._leg(buggy=True)
        self.assertEqual(verdict.status, "violated")
        self.assertIn("spend_ok", verdict.note)
        self.assertIn("inductive", verdict.note)

    def test_symbolic_constants_are_free(self):
        """The proof is for ALL values, not just the pinned 100/200."""
        for buggy in (False, True):
            verdict = self._leg(buggy=buggy)
            joined = " ".join(verdict.assumptions or [])
            self.assertIn("AMOUNT", joined)
            self.assertIn("CAP", joined)
            self.assertIn("uninterpreted",
                          " ".join(verdict.soundness or []))
            self.assertEqual(verdict.evidence.get("symbolic_constants"),
                             ["AMOUNT", "CAP"])

    def test_bounded_crosscheck_recorded(self):
        """Item 2's answer is recorded as the bounded cross-check."""
        # Buggy: the bounded cross-check is VIOLATED (Z3 finds the small race).
        verdict = self._leg(buggy=True)
        self.assertEqual(verdict.evidence.get("bounded_crosscheck"), "violated")
        # Correct: the bounded leg is a cross-check -- it must NEVER be
        # VIOLATED for the safe shape (a contradiction); it is PROVEN (unsat)
        # or UNKNOWN (z3 timeout) on the all-values encoding.  The primary
        # proof is the inductive invariant (PROVEN), which is asserted above.
        verdict = self._leg(buggy=False)
        self.assertIn(verdict.evidence.get("bounded_crosscheck"),
                      ("proven", "unknown"))

    def test_buggy_counterexample_is_violating_witness(self):
        """The witness is a real violating state (for its recorded values)."""
        verdict = self._leg(buggy=True)
        self.assertEqual(verdict.status, "violated")
        ce = verdict.counterexample
        a = verdict.evidence.get("witness_amount")
        cap = verdict.evidence.get("witness_cap")
        self.assertIsNotNone(a)
        self.assertIsNotNone(cap)
        # The witness state violates 'settled + in-flight <= cap' for the
        # recorded (model) AMOUNT / CAP -- a concrete, reproducible witness.
        self.assertGreater(ce["completed"] + ce["inflight"] * a, cap)

    def test_verdict_serializes_to_json(self):
        for buggy in (False, True):
            verdict = self._leg(buggy=buggy)
            payload = json.dumps(verdict.to_dict(), sort_keys=True)
            self.assertIsInstance(payload, str)
            self.assertIn('"status"', payload)
            self.assertIn(SYMBOLIC_ENGINE, payload)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SymbolicItem2BoundedTest(unittest.TestCase):
    """Item 2: the bounded unroll with symbolic ``AMOUNT`` / ``CAP``.

    The bounded leg is a *cross-check*: it is an existential SAT query (find a
    trace + values that violate).  For the safe shape that is UNSAT (proving
    "no values violate"), which is hard for Z3 and may time out to UNKNOWN --
    an honest result.  For the buggy shape it is SAT and Z3 finds the small
    race reliably.  The primary, unbounded proof is the inductive invariant
    (item 3), which is asserted in the other test classes.
    """

    def test_correct_is_never_violated(self):
        """For the safe shape the bounded leg must never be VIOLATED."""
        ir = build_ir(buggy=False)
        v = SymbolicSpendcap(ir).bounded_check()
        # PROVEN (unsat) or UNKNOWN (z3 timeout on the all-values UNSAT) --
        # but never VIOLATED (that would contradict the inductive proof).
        self.assertIn(v.status, ("proven", "unknown"))
        if v.status == "proven":
            self.assertIn("ALL values", v.note)
            self.assertIn("unbounded in amount/cap", v.note)

    def test_buggy_is_violated_with_witness(self):
        ir = build_ir(buggy=True)
        v = SymbolicSpendcap(ir).bounded_check()
        # SAT is easy for Z3 (it finds the small race); UNKNOWN only on timeout.
        self.assertIn(v.status, ("violated", "unknown"))
        if v.status == "violated":
            self.assertIsInstance(v.counterexample, dict)
            self.assertIn("inflight", v.counterexample)
            ce = v.counterexample
            a = v.evidence.get("witness_amount")
            cap = v.evidence.get("witness_cap")
            self.assertIsNotNone(a)
            self.assertIsNotNone(cap)
            self.assertGreater(ce["completed"] + ce["inflight"] * a, cap)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SymbolicItem3InductiveTest(unittest.TestCase):
    """Item 3: the inductive-invariant discharge (unbounded in concurrency)."""

    def test_correct_invariant_is_inductive(self):
        ir = build_ir(buggy=False)
        v = SymbolicSpendcap(ir).inductive_check()
        self.assertEqual(v.status, "proven")
        self.assertIn("ANY number of concurrent requests", v.note)
        self.assertIn("inductive", v.note)

    def test_buggy_invariant_is_not_closed(self):
        ir = build_ir(buggy=True)
        v = SymbolicSpendcap(ir).inductive_check()
        self.assertEqual(v.status, "violated")
        self.assertIn("NOT closed under", v.note)
        self.assertIn("spend_ok", v.note)

    def test_buggy_closure_failure_witness_is_violating(self):
        """The closure-failure witness breaks 'settled + in-flight <= cap'."""
        ir = build_ir(buggy=True)
        v = SymbolicSpendcap(ir).inductive_check()
        self.assertEqual(v.status, "violated")
        ce = v.counterexample
        self.assertIn("completed", ce)
        self.assertIn("inflight", ce)
        a = v.evidence.get("witness_amount")
        cap = v.evidence.get("witness_cap")
        self.assertIsNotNone(a)
        self.assertIsNotNone(cap)
        self.assertGreater(ce["completed"] + ce["inflight"] * a, cap)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SMTBackendSymbolicFacadeTest(unittest.TestCase):
    """``SMTBackend.verify_safety_symbolic`` -- the facade entry point."""

    def test_facade_correct_is_proven_symbolic(self):
        ir = build_ir(buggy=False)
        v = SMTBackend(ir).verify_safety_symbolic(spendcap_within_cap())
        self.assertEqual(v.status, "proven")
        self.assertEqual(v.engine, SYMBOLIC_ENGINE)

    def test_facade_buggy_is_violated_symbolic(self):
        ir = build_ir(buggy=True)
        v = SMTBackend(ir).verify_safety_symbolic(spendcap_within_cap())
        self.assertEqual(v.status, "violated")
        self.assertEqual(v.engine, SYMBOLIC_ENGINE)

    def test_facade_non_spendcap_ir_is_unknown(self):
        """The symbolic leg is spend-cap specific; other IRs degrade."""
        # A count-window IR is not a SPENDCAP protocol.
        from rot.shapes import build_count_window_ir
        try:
            other_ir = build_count_window_ir(3)
        except Exception:
            self.skipTest("no non-spendcap IR fixture available")
        v = SMTBackend(other_ir).verify_safety_symbolic(spendcap_within_cap())
        self.assertEqual(v.status, "unknown")
        self.assertEqual(v.engine, SYMBOLIC_ENGINE)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SymbolicVsConcreteAgreementTest(unittest.TestCase):
    """The symbolic leg must agree with the concrete bounded leg.

    The concrete engine pins ``AMOUNT=100`` / ``CAP=200``; the symbolic leg
    proves for all values.  On the spendcap slice they must reach the same
    verdict (PROVEN for the safe shape, VIOLATED for the buggy shape).
    """

    def test_agree_on_correct_variant(self):
        prop = spendcap_within_cap()
        ir = build_ir(buggy=False)
        concrete = SMTBackend(ir).verify_safety(prop)
        symbolic = SMTBackend(ir).verify_safety_symbolic(prop)
        self.assertEqual(concrete.status, "proven")
        self.assertEqual(symbolic.status, "proven")

    def test_agree_on_buggy_variant(self):
        prop = spendcap_within_cap()
        ir = build_ir(buggy=True)
        concrete = SMTBackend(ir).verify_safety(prop)
        symbolic = SMTBackend(ir).verify_safety_symbolic(prop)
        self.assertEqual(concrete.status, "violated")
        self.assertEqual(symbolic.status, "violated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
