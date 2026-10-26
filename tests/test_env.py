# -*- coding: utf-8 -*-
"""WP2 -- environment-fragment tests (R3: model the environment, not just the
happy path).

For each composable environment fragment in ``rot.env`` we check, via the
``rot.modelfind.ModelFinder`` oracle (the same bounded reachability engine used
for real targets):

* the **correct** variant: the pinned property holds in *every* reachable state;
* the **buggy** variant: the pinned property is *reachable and violated*.

Plus a composition check: two independent fragments composed together still
satisfy their (conjoined) invariants over the product state space.

Run:  python tests/test_env.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.env import (
    at_least_once_queue, tcp_channel, crash_recover_disk,
    idempotent_payment, compose, NO_DOUBLE_CHARGE,
)
from rot.modelfind import ModelFinder


def _holds(ir, prop):
    """True iff ``prop`` holds in every reachable state; else (False, witness)."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.forall_reachable(lambda s: prop.eval(s))
    return (status is True), witness


def _violated(ir, prop):
    """True iff some reachable state violates ``prop``; else (False, None)."""
    mf = ModelFinder.from_ir(ir)
    status, witness = mf.exists_reachable(lambda s: (not prop.eval(s)))
    return (status == "SAT"), witness


class EnvFragmentsTests(unittest.TestCase):
    def _check_correct(self, ir, label):
        self.assertFalse(ir.validate(), "%s invalid: %s" % (label, ir.validate()))
        self.assertTrue(any(a.is_initial for a in ir.actions),
                        "%s must have an init action" % label)
        ok, witness = _holds(ir, ir.pinned_property)
        self.assertTrue(ok,
                        "%s should satisfy its invariant; counter=%s" % (label, witness))

    def _check_buggy(self, ir, label):
        has, witness = _violated(ir, ir.pinned_property)
        self.assertTrue(has,
                        "%s should have a reachable invariant violation" % label)

    def test_at_least_once_queue_no_loss(self):
        self._check_correct(at_least_once_queue(buggy=False), "queue(correct)")
        self._check_buggy(at_least_once_queue(buggy=True), "queue(buggy)")

    def test_tcp_channel_in_order(self):
        self._check_correct(tcp_channel(buggy=False), "tcp(correct)")
        self._check_buggy(tcp_channel(buggy=True), "tcp(buggy)")

    def test_crash_recover_disk_durability(self):
        self._check_correct(crash_recover_disk(buggy=False), "disk(correct)")
        self._check_buggy(crash_recover_disk(buggy=True), "disk(buggy)")

    def test_idempotent_payment_no_double_charge(self):
        correct = idempotent_payment(buggy=False)
        buggy = idempotent_payment(buggy=True)
        self._check_correct(correct, "payment(correct)")
        self._check_buggy(buggy, "payment(buggy)")
        # correct: an init plus a single guarded (idempotent) charge
        self.assertEqual(
            {a.name for a in correct.actions},
            {"payment_init", "payment_charge"})
        # buggy: adds a recharge that double-charges the same order
        self.assertIn("payment_recharge", {a.name for a in buggy.actions})
        self.assertEqual(len(buggy.actions), len(correct.actions) + 1)
        # metadata pins the property name and the variant
        self.assertEqual(correct.metadata.get("property_name"), NO_DOUBLE_CHARGE)
        self.assertIs(correct.metadata.get("buggy"), False)
        self.assertIs(buggy.metadata.get("buggy"), True)
        # the pinned property is the no-double-charge invariant
        self.assertIsNotNone(correct.pinned_property)
        self.assertIsNotNone(buggy.pinned_property)

    def test_compose_two_fragments(self):
        comp = compose(tcp_channel(buggy=False), crash_recover_disk(buggy=False))
        names = {v.name for v in comp.variables}
        self.assertIn("a_delivered", names)
        self.assertIn("b_delivered", names)
        self.assertIn("disk_state", names)
        # the conjoined invariant must hold over the product state space
        ok, witness = _holds(comp, comp.pinned_property)
        self.assertTrue(ok,
                        "composed invariant should hold; counter=%s" % witness)


if __name__ == "__main__":
    unittest.main(verbosity=2)
