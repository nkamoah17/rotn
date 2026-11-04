# -*- coding: utf-8 -*-
"""GAP 2 (rigor parity) -- the cross-check is decisive for every APW class.

The ``CrossChecker`` join is shape-aware by default (``mode=auto``):

* **APW-1** (spendcap) joins ``strict`` -- all three engines must agree
  (the policy-direct model family applies, so the strongest join is still
  decisive).
* **APW-2/3/4/5/6** (non-spendcap) join ``primary`` -- the two independent
  model checkers (SMT/Z3 + TLC) decide; the spendcap-specific policy-direct
  leg is structurally ``UNKNOWN`` for these shapes and is only the offline
  fallback, so it can no longer force the whole join to ``UNKNOWN``.

These tests pin, for **each** APW class, that under the **default** engine
path (no explicit ``mode``) the cross-check is *decisive* (the correct
oracle is PROVEN, the buggy oracle is VIOLATED) -- i.e. not forced to
``UNKNOWN`` by the policy-direct leg.  The engine seams are stubbed so the
tests run without Z3 or a TLC jar; the stubs mirror the real per-shape
behaviour of each leg (policy-direct is ``UNKNOWN`` for a non-spendcap IR).

Run: python tests/test_crosscheck_apw.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.crosscheck import (CrossChecker, MODE_PRIMARY, MODE_STRICT,
                            default_mode_for, spendcap_params)
from rot import invariants
from rot.spendcap import build_ir as build_spendcap_ir
from rot.shapes import (build_approval_replay_ir, build_taint_egress_ir,
                        build_distinct_count_ir, build_scoped_cap_ir,
                        build_window_boundary_ir)
from rot.symbolic import EngineResult
from rot.verdicts import Verdict

PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"

# The six APW classes: (label, is_spendcap, buggy-oracle-builder,
# correct-oracle-builder).  APW-1 is spendcap; APW-2..6 are non-spendcap
# temporal shapes (approval-replay, taint-egress, distinct-count, scoped-cap,
# window-boundary).
APW_CLASSES = [
    ("APW-1", True,
     lambda: build_spendcap_ir(buggy=True),
     lambda: build_spendcap_ir(buggy=False)),
    ("APW-2", False,
     lambda: build_approval_replay_ir(buggy=True),
     lambda: build_approval_replay_ir(buggy=False)),
    ("APW-3", False,
     lambda: build_taint_egress_ir(buggy=True),
     lambda: build_taint_egress_ir(buggy=False)),
    ("APW-4", False,
     lambda: build_distinct_count_ir(buggy=True),
     lambda: build_distinct_count_ir(buggy=False)),
    ("APW-5", False,
     lambda: build_scoped_cap_ir(buggy=True, cap=3),
     lambda: build_scoped_cap_ir(buggy=False, cap=3)),
    ("APW-6", False,
     lambda: build_window_boundary_ir(buggy=True, cap=3),
     lambda: build_window_boundary_ir(buggy=False, cap=3)),
]


def _prop_for(ir, label):
    """A faithful pinned invariant for ``ir`` (the ``Invariant`` ``check()``
    expects -- it reads ``.name`` and ``.kind``)."""
    return invariants.Invariant(
        name="apw_%s" % label.lower(),
        description="APW %s cross-check" % label,
        expression=ir.pinned_property,
        kind="safety",
        label=invariants.LABEL_BOUNDED,
        pinned=True,
    )


def _stubbed_checker(ir, label, decision):
    """A **default-mode** (``auto``) ``CrossChecker`` for ``ir`` whose engine
    seams are stubbed to mirror the real per-shape behaviour of each leg on a
    ``decision`` (``PROVEN`` for the correct oracle, ``VIOLATED`` for the
    buggy oracle):

    * SMT/Z3 and TLC decide (they check the IR state-machine model);
    * policy-direct decides for a spendcap IR (the model applies) and is
      structurally ``UNKNOWN`` for a non-spendcap IR (it does not apply).

    No engine is installed (all seams are stubbed), so the test pins the
    *join* and the *shape-aware mode* -- the GAP 2 concern -- without Z3/TLC.
    """
    is_spendcap = spendcap_params(ir) is not None
    prop = _prop_for(ir, label)
    ce = None if decision == PROVEN else {"state": "attack", "class": label}
    checker = CrossChecker(ir, None, prop, None)  # default (auto) mode
    checker._smt_verdict = lambda: Verdict(
        status=decision, property_name=prop.name, engine="smtz3",
        counterexample=ce, note="smt/z3")
    checker._tlc_result = lambda: EngineResult(
        status=decision, witness=ce, note="tlc")
    # The policy-direct leg: decisive for a spendcap IR (the model applies),
    # structurally UNKNOWN for a non-spendcap shape (it does not apply) --
    # exactly the real behaviour of ``CrossChecker._policy_direct_verdict``.
    pd_status = decision if is_spendcap else UNKNOWN
    checker._policy_direct_verdict = lambda: EngineResult(
        status=pd_status,
        witness=ce if is_spendcap else None,
        note=("policy-direct" if is_spendcap
              else "policy_direct: IR is not a spendcap IR; the direct "
                   "policy model does not apply"))
    return checker


class ModeResolutionTests(unittest.TestCase):
    """The default join mode is shape-aware (GAP 2, rigor parity)."""

    def test_spendcap_apw1_resolves_to_strict(self):
        label, is_spendcap, buggy, _correct = APW_CLASSES[0]
        self.assertTrue(is_spendcap)
        self.assertEqual(default_mode_for(buggy()), MODE_STRICT)

    def test_non_spendcap_apw2_to_6_resolve_to_primary(self):
        for label, is_spendcap, buggy, _correct in APW_CLASSES[1:]:
            self.assertFalse(is_spendcap, label)
            self.assertEqual(default_mode_for(buggy()), MODE_PRIMARY,
                             label)

    def test_crosschecker_default_mode_matches_shape(self):
        # The default (no explicit mode) resolves to the shape-aware mode.
        for label, is_spendcap, buggy, _correct in APW_CLASSES:
            checker = CrossChecker(buggy(), None,
                                   _prop_for(buggy(), label), None)
            expected = MODE_STRICT if is_spendcap else MODE_PRIMARY
            self.assertEqual(checker.mode, expected, label)

    def test_explicit_mode_still_overrides(self):
        # An explicit strict/primary still wins (the APW-1 spendcap case
        # keeps its strongest join; a non-spendcap can be forced to strict).
        label, is_spendcap, buggy, _correct = APW_CLASSES[1]
        self.assertEqual(CrossChecker(buggy(), None,
                                      _prop_for(buggy(), label), None,
                                      mode=MODE_STRICT).mode, MODE_STRICT)
        self.assertEqual(CrossChecker(buggy(), None,
                                      _prop_for(buggy(), label), None,
                                      mode=MODE_PRIMARY).mode, MODE_PRIMARY)

    def test_unknown_mode_raises(self):
        label, _is, buggy, _correct = APW_CLASSES[0]
        with self.assertRaises(ValueError):
            CrossChecker(buggy(), None, _prop_for(buggy(), label), None,
                         mode="bogus")


class DecisiveCrosscheckTests(unittest.TestCase):
    """Under the **default** engine path, every APW class's cross-check is
    decisive (not forced to ``UNKNOWN``) -- the GAP 2 requirement."""

    def test_correct_oracle_is_decisive_proven(self):
        # For every APW class, the correct oracle cross-checks to PROVEN
        # under the default (shape-aware) engine path.
        for label, is_spendcap, _buggy, correct in APW_CLASSES:
            with self.subTest(apw=label):
                verdict = _stubbed_checker(correct(), label, PROVEN).check()
                self.assertEqual(verdict.status, PROVEN)
                self.assertIsNone(verdict.counterexample)

    def test_buggy_oracle_is_decisive_violated(self):
        # For every APW class, the buggy oracle cross-checks to VIOLATED
        # (with a counterexample) under the default engine path -- not the
        # structural UNKNOWN the old strict-default produced for APW-2..6.
        for label, is_spendcap, buggy, _correct in APW_CLASSES:
            with self.subTest(apw=label):
                verdict = _stubbed_checker(buggy(), label, VIOLATED).check()
                self.assertEqual(verdict.status, VIOLATED)
                self.assertIsNotNone(verdict.counterexample)

    def test_non_spendcap_decisive_despite_policy_direct_unknown(self):
        # The crux of the GAP 2 fix: for each non-spendcap class the
        # policy-direct leg is structurally UNKNOWN (the spendcap-specific
        # direct policy model does not apply) yet the join is STILL decisive,
        # because the shape-aware default is ``primary`` (the two independent
        # model checkers decide).  Under the old strict-default this exact
        # scenario was forced to UNKNOWN -- the "3 independent engines"
        # over-claim for 5 of the 6 classes.
        for label, is_spendcap, buggy, correct in APW_CLASSES[1:]:
            with self.subTest(apw=label, decision="proven"):
                checker = _stubbed_checker(correct(), label, PROVEN)
                self.assertEqual(checker.mode, MODE_PRIMARY)
                self.assertEqual(checker._policy_direct_verdict().status,
                                 UNKNOWN)  # not applicable for this shape
                self.assertEqual(checker.check().status, PROVEN)
            with self.subTest(apw=label, decision="violated"):
                checker = _stubbed_checker(buggy(), label, VIOLATED)
                self.assertEqual(checker.mode, MODE_PRIMARY)
                self.assertEqual(checker._policy_direct_verdict().status,
                                 UNKNOWN)
                self.assertEqual(checker.check().status, VIOLATED)

    def test_spendcap_apw1_still_requires_all_three(self):
        # APW-1 stays strict: with all three engines agreeing the verdict is
        # decisive, and a policy-direct UNKNOWN (e.g. Z3 unavailable) still
        # forces UNKNOWN -- the conservative behaviour we keep for spendcap.
        label, is_spendcap, buggy, correct = APW_CLASSES[0]
        self.assertTrue(is_spendcap)
        verdict = _stubbed_checker(correct(), label, PROVEN).check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(verdict.evidence["crosscheck"]["mode"], MODE_STRICT)


class GapRegressionTests(unittest.TestCase):
    """The gap the fix closes: a non-spendcap class is forced to ``UNKNOWN``
    under ``strict`` (the policy-direct leg is not applicable) but is
    decisive under the shape-aware default (``primary``)."""

    def _non_spendcap(self):
        label, is_spendcap, buggy, _correct = APW_CLASSES[1]
        self.assertFalse(is_spendcap)
        return label, buggy()

    def test_strict_forces_unknown_when_policy_direct_unknown(self):
        # With policy-direct UNKNOWN (not applicable) and the two MCs
        # agreeing, ``strict`` cannot mint a verdict -> UNKNOWN.
        label, ir = self._non_spendcap()
        checker = CrossChecker(ir, None, _prop_for(ir, label), None,
                               mode=MODE_STRICT)
        checker._smt_verdict = lambda: Verdict(
            status=VIOLATED, property_name=_prop_for(ir, label).name,
            engine="smtz3", counterexample={"state": "attack"},
            note="smt/z3")
        checker._tlc_result = lambda: EngineResult(
            status=VIOLATED, witness={"state": "attack"}, note="tlc")
        checker._policy_direct_verdict = lambda: EngineResult(
            status=UNKNOWN, note="policy_direct: not a spendcap IR")
        self.assertEqual(checker.check().status, UNKNOWN)

    def test_default_is_decisive_when_policy_direct_unknown(self):
        # Same engines, same non-applicable policy-direct leg -- but the
        # shape-aware default (primary) lets the two independent model
        # checkers mint a decisive VIOLATED.
        label, ir = self._non_spendcap()
        checker = _stubbed_checker(ir, label, VIOLATED)
        self.assertEqual(checker.mode, MODE_PRIMARY)
        self.assertEqual(checker.check().status, VIOLATED)


if __name__ == "__main__":
    unittest.main(verbosity=2)

