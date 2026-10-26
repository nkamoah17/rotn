# -*- coding: utf-8 -*-
"""End-to-end checks on the 2PC vertical-slice target: IR sanity, the
property-directed abstraction, and agreement hold/violate via the bounded
model finder (an independent oracle ahead of TLC).

Run: python tests/test_twopc.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.twopc import build_ir, agreement_property, validity_property
from rot.abstraction import derive_abstraction
from rot.modelfind import ModelFinder
from rot.ir import Expr


def _agreement_holds_all_reachable(prop, ir):
    """(ok, witness) where ok is True iff prop holds in every reachable state."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.forall_reachable(lambda s: prop.eval(s))
    if status is True:
        return True, None
    if status is False:
        return False, witness
    raise AssertionError("model finder returned UNKNOWN; state space too large for slice")


def _agreement_violation(prop, ir):
    """(has_violation, witness_state) over reachable states."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.exists_reachable(lambda s: (not prop.eval(s)))
    if status == "SAT":
        return True, witness
    return False, None


class TwopcTests(unittest.TestCase):
    def test_ir_is_well_formed(self):
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            # ProtocolIR.validate() returns the list of well-formedness errors;
            # an empty list (falsy) means the IR is well-formed.
            self.assertFalse(ir.validate(), msg=str(ir.validate()))
            self.assertTrue(any(a.is_initial for a in ir.actions))

    def test_correct_model_satisfies_agreement_in_all_reachable_states(self):
        ir = build_ir(n=3, buggy=False)
        prop = agreement_property(3)
        ok, witness = _agreement_holds_all_reachable(prop, ir)
        self.assertTrue(ok, "correct 2PC should satisfy agreement, but found: %s" % witness)

    def test_buggy_model_violates_agreement(self):
        ir = build_ir(n=3, buggy=True)
        prop = agreement_property(3)
        has, witness = _agreement_violation(prop, ir)
        self.assertTrue(has, "buggy 2PC should violate agreement, but it held in all reachable states")

    def test_abstraction_keeps_property_relevant_vars(self):
        ir = build_ir(n=3, buggy=False)
        prop = agreement_property(3)
        ab = derive_abstraction(ir, prop, "agreement", participant_bound=3)
        # agreement depends on applied_1..applied_3; the fixpoint must keep
        # them plus the decision and votes that influence them
        for v in ("applied_1", "applied_2", "applied_3", "decision",
                  "vote_1", "vote_2", "vote_3", "phase"):
            self.assertIn(v, ab.keep)
        self.assertTrue(ab.assumptions)

    def test_validity_property_holds_in_both(self):
        # "commit only if all voted yes" holds in both variants (the bug is in
        # apply, not in the coordinator decision)
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            prop = validity_property(3)
            ok, witness = _agreement_holds_all_reachable(prop, ir)
            self.assertTrue(ok, "validity should hold (buggy=%s), witness=%s" % (buggy, witness))

    def test_property_serializes(self):
        prop = agreement_property(3)
        d = prop.to_dict()
        # Canonical IR serialization: a conjunction is a binary "and" node.
        self.assertEqual(d["tag"], "bin")
        self.assertEqual(d["op"], "and")


if __name__ == "__main__":
    unittest.main(verbosity=2)