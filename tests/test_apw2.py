# -*- coding: utf-8 -*-
"""APW-2 -- Approval replay (an approval is never consumed).

The policy gates ``place_order`` on a *bare* temporal fact -- "a cart check
happened within the window" (``formerly within 1m get_cart``).  A bare ``formerly``
predicate is **sticky**: once one cart check occurs, the fact stays true for
the rest of the window, so the same approval admits *N* orders.  The fix is a
``since`` clause that *consumes* the approval: an order is admitted only since
the cart check AND no order has already responded since that check.

  * **buggy**   -- ``place_order`` fires on the bare ``approved`` fact; a
    single approval admits two orders.  VIOLATED.
  * **correct** -- an order is admitted only since the approval and only once
    (``no order already responded since the approval``).  PROVEN.

This is the commercially important class (the exact Classmethod policy,
extracted and pinned in ``samples/``).  The ``since`` operator is what the
parser work in Phase 1 unlocks.

Run: python tests/test_apw2.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven,  # noqa: E402
                        assert_oracle_match, fixture)

APW = "APW-2"
BUGGY_WITNESS = {"approved": True, "orders": 2}
BUGGY_FIXTURE = fixture("approval-replay-buggy.dw")
CORRECT_FIXTURE = fixture("approval-replay-correct.dw")
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw2-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw2-correct.dw")
# The Classmethod permit form (the ``formerly within <approval-event>``
# gating shape -- the exact shape of the public Classmethod tutorial).
PERMIT_BUGGY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "apw", "apw2-permit-buggy.dw")
PERMIT_CORRECT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "apw", "apw2-permit-correct.dw")


def _action(ir, name):
    for a in ir.actions:
        if a.name == name:
            return a
    raise AssertionError("no %s action in %s" % (name, ir.name))


class APW2OracleTests(unittest.TestCase):
    """The APW-2 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            shapes.build_approval_replay_ir(buggy=True), BUGGY_WITNESS, APW)
        # One approval -> two orders (the replay).
        self.assertEqual(res.witness["approved"], True)
        self.assertEqual(res.witness["orders"], 2)

    def test_correct_oracle_is_proven(self):
        assert_correct_proven(
            shapes.build_approval_replay_ir(buggy=False), APW)

    def test_buggy_place_order_does_not_consume_approval(self):
        """The discriminating difference: in the buggy variant, ``place_order``
        only bumps ``orders`` (1 effect) -- the approval is never consumed, so
        it can fire again."""
        buggy = shapes.build_approval_replay_ir(buggy=True)
        self.assertEqual(len(_action(buggy, "place_order").effects), 1)

    def test_correct_place_order_consumes_approval(self):
        """In the correct variant, ``place_order`` bumps ``orders`` AND clears
        ``approved`` (2 effects) -- one approval, one order."""
        correct = shapes.build_approval_replay_ir(buggy=False)
        effects = _action(correct, "place_order").effects
        self.assertEqual(len(effects), 2)
        # One of the effects must be the approval-consumption (approved -> False).
        names = [e.var for e in effects]
        self.assertIn("approved", names)


class APW2OracleMatchTests(unittest.TestCase):
    """The ``.dw`` fixture lowers to the hand-written oracle."""

    def test_buggy_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            BUGGY_FIXTURE, shapes.build_approval_replay_ir(buggy=True), APW)

    def test_correct_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            CORRECT_FIXTURE, shapes.build_approval_replay_ir(buggy=False),
            APW)


class APW2SampleTests(unittest.TestCase):
    """The catalog samples exist, parse, and match the oracle."""

    def test_samples_exist(self):
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            self.assertTrue(os.path.exists(p), "missing sample: %s" % p)

    def test_samples_lower_to_the_oracle(self):
        assert_oracle_match(
            SAMPLE_BUGGY, shapes.build_approval_replay_ir(buggy=True), APW)
        assert_oracle_match(
            SAMPLE_CORRECT,
            shapes.build_approval_replay_ir(buggy=False), APW)


class APW2PermitFormTests(unittest.TestCase):
    """The Classmethod ``permit`` form classifies as approval-replay (APW-2).

    Regression for the misclassification the gate used to hide: the bare
    ``formerly within <approval-event>`` gating shape (the exact shape of
    the public Classmethod tutorial policy) was routed to the **taint-egress
    (APW-3)** / event-ordering detectors before the approval-replay one, so
    ``apw2-permit-buggy.dw`` proved the *wrong* bug class.  The dispatcher
    now disambiguates by *policy intent*: a **permit** gated on a prior
    approval event is approval-replay (sticky fact = replayable); a
    **forbid** on egress after a confidential read is taint-egress.
    """

    def test_permit_buggy_classifies_as_approval_replay(self):
        from rot.dw import parse_file
        ir = parse_file(PERMIT_BUGGY).to_ir()
        self.assertEqual(ir.metadata.get("protocol"), "APPROVAL_REPLAY",
                         "the Classmethod permit form must classify as "
                         "approval-replay (APW-2), not taint-egress (APW-3)")
        self.assertEqual(ir.metadata.get("buggy"), True,
                         "the bare formerly fact is sticky: approval replay")

    def test_permit_correct_classifies_as_single_use(self):
        from rot.dw import parse_file
        ir = parse_file(PERMIT_CORRECT).to_ir()
        self.assertEqual(ir.metadata.get("protocol"), "APPROVAL_REPLAY")
        self.assertEqual(ir.metadata.get("buggy"), False,
                         "the !formerly consumption clause makes the "
                         "approval single-use")

    def test_permit_fixtures_lower_to_the_oracle(self):
        assert_oracle_match(
            PERMIT_BUGGY, shapes.build_approval_replay_ir(buggy=True), APW)
        assert_oracle_match(
            PERMIT_CORRECT, shapes.build_approval_replay_ir(buggy=False), APW)

    def test_forbid_form_stays_taint_egress(self):
        """The disambiguation guard: the *forbid* form of the same syntactic
        shape is the APW-3 taint-egress class (intent, not syntax, decides)."""
        from rot.dw import parse_file
        apw3 = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "samples", "apw3-buggy.dw")
        ir = parse_file(apw3).to_ir()
        self.assertEqual(ir.metadata.get("protocol"), "TAINT_EGRESS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
