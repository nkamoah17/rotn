# -*- coding: utf-8 -*-
"""Held-out spec check: the order-service (order + billing) business-logic
target, verified as a held-out spec beyond the core consensus protocols
(2PC/ZAB/PBFT) and the Phase-2 Payment composition demo.

The order service is composed (``composition.compose``) from two independently
modelled services:

* ``order``   -- ``placed``/``confirmed`` booleans (place, then confirm); and
* ``billing`` -- a ``charges`` counter (0/1/2) for how many times the order has
  been billed.

The correct billing action charges exactly once, only after the order is
confirmed (idempotent).  The buggy billing action drops both the confirmation
guard and the idempotency guard, so a re-issued charge double-charges the order
(``charges`` can reach 2).

The pinned property is ``no_double_charge`` (``charges <= 1``): it *holds* on
the correct variant and is reachable-and-violated on the buggy variant.  Two
ordering invariants -- ``charge_requires_place`` and ``confirm_requires_place``
-- hold in *both* variants (the seeded bug is *when* and *how many times*
billing charges, not that it charges an unplaced order or confirms an unplaced
one).

This mirrors the convention of the other vertical-slice targets
(test_zab_target.py / test_pbft_target.py): IR sanity, the property-directed
abstraction, and hold/violate via the bounded model finder (an independent
oracle ahead of TLC).

Run: python tests/test_heldout_spec.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.order_service import (
    build_ir,
    no_double_charge_property,
    charge_requires_place_property,
    confirm_requires_place_property,
)
from rot.abstraction import derive_abstraction
from rot.modelfind import ModelFinder


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


class HeldoutOrderServiceTests(unittest.TestCase):
    def test_ir_is_well_formed(self):
        for buggy in (False, True):
            ir = build_ir(buggy=buggy)
            # ProtocolIR.validate() returns the list of well-formedness errors;
            # an empty list (falsy) means the IR is well-formed.
            self.assertFalse(ir.validate(), msg=str(ir.validate()))
            self.assertTrue(any(a.is_initial for a in ir.actions))

    def test_correct_holds_no_double_charge(self):
        ir = build_ir(buggy=False)
        prop = no_double_charge_property()
        ok, witness = _prop_holds_all_reachable(prop, ir)
        self.assertTrue(ok, "correct order service should satisfy NO_DOUBLE_CHARGE, "
                            "but found: %s" % witness)

    def test_buggy_violates_no_double_charge(self):
        ir = build_ir(buggy=True)
        prop = no_double_charge_property()
        has, witness = _prop_violation(prop, ir)
        self.assertTrue(has, "buggy order service should violate NO_DOUBLE_CHARGE, "
                             "but it held in all reachable states")
        # the counterexample must be the double-charged state: charges == 2
        self.assertEqual(witness["charges"], 2)

    def test_charge_requires_place_holds_in_both(self):
        # "billing never charges an unplaced order" holds in both variants
        for buggy in (False, True):
            ir = build_ir(buggy=buggy)
            prop = charge_requires_place_property()
            ok, witness = _prop_holds_all_reachable(prop, ir)
            self.assertTrue(ok, "charge_requires_place should hold (buggy=%s), "
                                "witness=%s" % (buggy, witness))

    def test_confirm_requires_place_holds_in_both(self):
        # "order only confirms once placed" holds in both variants
        for buggy in (False, True):
            ir = build_ir(buggy=buggy)
            prop = confirm_requires_place_property()
            ok, witness = _prop_holds_all_reachable(prop, ir)
            self.assertTrue(ok, "confirm_requires_place should hold (buggy=%s), "
                                "witness=%s" % (buggy, witness))

    def test_abstraction_keeps_relevant_vars(self):
        ir = build_ir(buggy=False)
        prop = no_double_charge_property()
        ab = derive_abstraction(ir, prop, "no_double_charge")
        # the only state variables are placed, confirmed and charges; the
        # property-directed fixpoint keeps all three.
        for v in ("charges", "confirmed", "placed"):
            self.assertIn(v, ab.keep)

    def test_property_serializes(self):
        prop = no_double_charge_property()
        d = prop.to_dict()
        # Canonical IR serialization: no_double_charge is "charges <= 1", a
        # binary "<=" node over the charges variable and the constant 1.
        self.assertEqual(d["tag"], "bin")
        self.assertEqual(d["op"], "<=")
        self.assertEqual(d["left"], {"tag": "var", "name": "charges"})
        self.assertEqual(d["right"], {"tag": "const", "value": 1})


if __name__ == "__main__":
    unittest.main(verbosity=2)
