# -*- coding: utf-8 -*-
"""End-to-end checks on the ZAB broadcast/commit vertical-slice target: IR
sanity, the property-directed abstraction, and no-premature-apply
hold/violate via the bounded model finder (an independent oracle ahead of TLC).

Run: python tests/test_zab_target.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.zab import (build_ir, no_premature_apply_property,
                     apply_persisted_property)
from rot.abstraction import derive_abstraction
from rot.modelfind import ModelFinder
from rot.ir import Expr


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


class ZabTargetTests(unittest.TestCase):
    def test_ir_is_well_formed(self):
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            # ProtocolIR.validate() returns the list of well-formedness errors;
            # an empty list (falsy) means the IR is well-formed.
            self.assertFalse(ir.validate(), msg=str(ir.validate()))
            self.assertTrue(any(a.is_initial for a in ir.actions))

    def test_correct_holds_no_premature_apply(self):
        ir = build_ir(n=3, buggy=False)
        prop = no_premature_apply_property(3)
        ok, witness = _prop_holds_all_reachable(prop, ir)
        self.assertTrue(ok, "correct ZAB should satisfy no_premature_apply, "
                            "but found: %s" % witness)

    def test_buggy_violates_no_premature_apply(self):
        ir = build_ir(n=3, buggy=True)
        prop = no_premature_apply_property(3)
        has, witness = _prop_violation(prop, ir)
        self.assertTrue(has, "buggy ZAB should violate no_premature_apply, "
                            "but it held in all reachable states")

    def test_apply_persisted_holds_in_both(self):
        # "applied only if persisted" holds in both variants (the bug is
        # premature apply, not apply-before-persisting)
        for buggy in (False, True):
            ir = build_ir(n=3, buggy=buggy)
            prop = apply_persisted_property(3)
            ok, witness = _prop_holds_all_reachable(prop, ir)
            self.assertTrue(ok, "apply_persisted should hold (buggy=%s), "
                               "witness=%s" % (buggy, witness))

    def test_abstraction_keeps_relevant_vars(self):
        ir = build_ir(n=3, buggy=False)
        prop = no_premature_apply_property(3)
        ab = derive_abstraction(ir, prop, "zab_no_premature_apply",
                                participant_bound=3)
        # no_premature_apply depends on applied_{i}_{j} and committed_i;
        # the fixpoint must keep them plus the persisted vars that influence apply
        for v in ("applied_1_1", "committed_1", "persisted_1_1"):
            self.assertIn(v, ab.keep)
        self.assertTrue(ab.assumptions)

    def test_property_serializes(self):
        prop = no_premature_apply_property(3)
        d = prop.to_dict()
        # Canonical IR serialization: a conjunction is a binary "and" node.
        self.assertEqual(d["tag"], "bin")
        self.assertEqual(d["op"], "and")


if __name__ == "__main__":
    unittest.main(verbosity=2)