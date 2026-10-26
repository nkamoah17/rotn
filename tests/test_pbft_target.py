# -*- coding: utf-8 -*-
"""End-to-end checks on the PBFT prepare/commit vertical-slice target: IR
sanity, the property-directed abstraction, and the quorum invariant
hold/violate via the bounded model finder (an independent oracle ahead of TLC).

Also checks the target registry wiring (names/properties/default) and that the
MR gate blocks the correct -> buggy regression on the pinned ``pbft_quorum``
invariant.

Run: python tests/test_pbft_target.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.pbft import (build_ir, quorum_property,
                      prepare_before_commit_property)
from rot.abstraction import derive_abstraction
from rot.modelfind import ModelFinder
import rot.targets as targets
from rot.mr_gate import PASS, BLOCK, evaluate_mr


def _prop_holds_all_reachable(prop, ir):
    """(ok, witness) where ok is True iff prop holds in every reachable state."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.forall_reachable(lambda s: prop.eval(s))
    if status is True:
        return True, None
    if status is False:
        return False, witness
    raise AssertionError("model finder returned UNKNOWN; state space too large for slice")


def _prop_violation(prop, ir):
    """(has_violation, witness_state) over reachable states."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.exists_reachable(lambda s: (not prop.eval(s)))
    if status == "SAT":
        return True, witness
    return False, None


class PbftTargetTests(unittest.TestCase):
    def test_ir_is_well_formed(self):
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            # ProtocolIR.validate() returns the list of well-formedness errors;
            # an empty list (falsy) means the IR is well-formed.
            self.assertFalse(ir.validate(), msg=str(ir.validate()))
            self.assertTrue(any(a.is_initial for a in ir.actions))

    def test_correct_holds_quorum(self):
        ir = build_ir(n=3, buggy=False)
        prop = quorum_property(3)
        ok, witness = _prop_holds_all_reachable(prop, ir)
        self.assertTrue(ok, "correct PBFT should satisfy pbft_quorum, "
                            "but found: %s" % witness)

    def test_buggy_violates_quorum(self):
        ir = build_ir(n=3, buggy=True)
        prop = quorum_property(3)
        has, witness = _prop_violation(prop, ir)
        self.assertTrue(has, "buggy PBFT should violate pbft_quorum, "
                             "but it held in all reachable states")

    def test_prepare_before_commit_holds_in_both(self):
        # "committed only if prepared" holds in both variants (the bug is
        # premature commit, not committing before preparing)
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            prop = prepare_before_commit_property(3)
            ok, witness = _prop_holds_all_reachable(prop, ir)
            self.assertTrue(ok, "prepare_before_commit should hold (buggy=%s), "
                                "witness=%s" % (buggy, witness))

    def test_abstraction_keeps_relevant_vars(self):
        ir = build_ir(n=3, buggy=False)
        prop = quorum_property(3)
        ab = derive_abstraction(ir, prop, "pbft_quorum", participant_bound=3)
        # pbft_quorum depends on committed_i and quorum_i; the fixpoint must
        # keep them plus the prepared vars that influence the quorum.
        for v in ("committed_1", "quorum_1"):
            self.assertIn(v, ab.keep)
        self.assertTrue(ab.assumptions)

    def test_property_serializes(self):
        prop = quorum_property(3)
        d = prop.to_dict()
        # Canonical IR serialization: a conjunction is a binary "and" node.
        self.assertEqual(d["tag"], "bin")
        self.assertEqual(d["op"], "and")


class PbftTargetRegistryTests(unittest.TestCase):
    def test_both_targets_registered(self):
        for name in ("pbft-correct", "pbft-buggy"):
            self.assertIn(name, targets.names())
            spec = targets.get(name)
            self.assertEqual(spec.protocol, "PBFT")
            self.assertEqual(spec.properties, ["pbft_quorum",
                                               "pbft_prepare_before_commit"])
            self.assertEqual(spec.default_property, "pbft_quorum")

    def test_build_and_get_property(self):
        ir = targets.build("pbft-correct", n=3)
        self.assertFalse(ir.validate(), msg=str(ir.validate()))
        inv = targets.get_property("pbft-correct", "pbft_quorum", n=3)
        self.assertEqual(inv.name, "pbft_quorum")
        # the invariant holds vacuously in the initial state (no node committed)
        initial = dict((v.name, False) for v in ir.variables)
        self.assertTrue(inv.expression.eval(initial))

    def test_mr_gate_blocks_regression(self):
        # correct -> buggy breaks the pinned, blocking 'pbft_quorum' invariant
        v = evaluate_mr("pbft-correct", "pbft-buggy",
                        properties=["pbft_quorum"], n=3)
        self.assertEqual(v.verdict, BLOCK)
        self.assertEqual(v.before_label, "pbft-correct")
        self.assertEqual(v.after_label, "pbft-buggy")
        q = [r for r in v.invariants if r.name == "pbft_quorum"]
        self.assertEqual(len(q), 1)
        self.assertTrue(q[0].violated_after)
        self.assertTrue(q[0].blocking)

    def test_mr_gate_passes_on_correct(self):
        v = evaluate_mr("pbft-correct", "pbft-correct",
                        properties=["pbft_quorum"], n=3)
        self.assertEqual(v.verdict, PASS)
        for r in v.invariants:
            self.assertFalse(r.violated_after)

    def test_mr_gate_scoped_nonblocking_never_blocks(self):
        # the same real change, scoped to the non-blocking invariant:
        # it must never produce a BLOCK verdict
        v = evaluate_mr("pbft-correct", "pbft-buggy",
                        properties=["pbft_prepare_before_commit"], n=3)
        self.assertNotEqual(v.verdict, BLOCK)


if __name__ == "__main__":
    unittest.main(verbosity=2)