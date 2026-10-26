# -*- coding: utf-8 -*-
"""Verified correspondence between the model and the policy (Phase 3).

For a battery of ``(completed, inflight, per-request amount)``, assert::

    model.spend_ok_admits == (policy.sum_over_events <= cap)

for **both** event kinds (``request`` / the "correct" side, and
``response`` / the "buggy" side).

This turns "the correspondence is an argument" into "the correspondence is
**checked**" -- the model's ``spend_ok`` decision rule is *equivalent* to
the policy's sum-over-events condition, point-for-point over a concrete
state battery.

Python 3.6 compatible.
"""

import unittest

import rot.spendcap as spendcap
from rot.dw import parse_file

POLICIES = "tests/fixtures/aws_dogwood/spendcap/policies"
CORRECT = POLICIES + "/spendcap-correct.dw"
BUGGY = POLICIES + "/spendcap-buggy.dw"


# ---------------------------------------------------------------------------
# model side: evaluate the spend_ok decision rule
# ---------------------------------------------------------------------------

def _decision_rule(guard):
    """Extract the decision rule from a ``spend_ok`` guard.

    The guard is ``And(decision, structural_bound)`` where the structural
    bound is the client-side request-pool limit (``inflight < K``).  The
    :func:`rot.ir.And` helper builds the chain left-associatively::

        And(decision, bound)
        == BinOp("and", BinOp("and", Const(True), decision), bound)

    so ``guard.left`` is ``BinOp("and", Const(True), decision)``, which
    evaluates to exactly ``decision``.  If the guard is not an ``and`` node
    (defensive), return it unchanged.
    """
    if hasattr(guard, "op") and guard.op == "and":
        return guard.left
    return guard


def model_spend_ok_admits(ir, completed, inflight, amount):
    """Evaluate the model's ``spend_ok`` **decision rule** in a concrete state.

    ``completed`` -- settled amount (sum of responded requests).
    ``inflight``  -- approved-but-unsettled (in-flight) request count.
    ``amount``    -- the per-request settlement amount (the current request).

    Returns ``True`` if the model admits the request, ``False`` otherwise.
    The structural bound (``inflight < K``) is *excluded*: the correspondence
    is about the policy decision, not the resource limit.
    """
    by = dict((a.name, a) for a in ir.actions)
    guard = by["spend_ok"].guard
    rule = _decision_rule(guard)
    state = {"completed": completed, "inflight": inflight}
    result = rule.eval(state)
    return bool(result)


# ---------------------------------------------------------------------------
# policy side: evaluate the sum-over-events condition
# ---------------------------------------------------------------------------

def policy_sum_over_events(policy, completed, inflight, amount):
    """Compute the policy's ``sum`` over events for a concrete state.

    The policy's event kind determines which events fall inside the
    ``formerly within`` window:

    * ``request`` (the "correct" side) -- the event set includes the
      settled requests (``completed``), the in-flight requests
      (``inflight * amount``), and the current request (``amount``)::

          sum_over_events = completed + inflight * amount + amount

    * ``response`` (the "buggy" side) -- the event set includes the
      settled responses (``completed``) and the current response
      (``amount``); in-flight requests are *invisible* to the guard::

          sum_over_events = completed + amount

    ``completed`` is the settled amount (sum of responded requests);
    ``inflight`` is the in-flight request count; ``amount`` is the
    per-request settlement amount (the current request).
    """
    if policy.event_kind == "request":
        return completed + inflight * amount + amount
    # response (the "buggy" side): in-flight requests are invisible
    return completed + amount


# ---------------------------------------------------------------------------
# the correspondence
# ---------------------------------------------------------------------------

class TestCorrespondence(unittest.TestCase):
    """For a battery of ``(completed, inflight, amount)``, assert
    ``model.spend_ok_admits == (policy.sum_over_events <= cap)`` for both
    event kinds.

    This is the Phase 3 check: the model's ``spend_ok`` decision rule is
    *equivalent* to the policy's sum-over-events condition, point-for-point
    over a concrete state battery.  It turns "the correspondence is an
    argument" into "the correspondence is **checked**."
    """

    # A battery of (completed, inflight, amount) tuples that exercises the
    # full range of the decision plane: below the cap, at the cap, and above
    # it, for both event kinds.
    BATTERY = []
    for _completed in (0, 50, 100, 150, 200, 250, 300):
        for _inflight in (0, 1, 2, 3, 4):
            for _amount in (50, 100, 150):
                BATTERY.append((_completed, _inflight, _amount))

    def _check(self, policy_path, label):
        policy = parse_file(policy_path)
        cap = policy.cap
        mismatches = []
        for completed, inflight, amount in self.BATTERY:
            # Build the model with this specific per-request amount so the
            # decision rule charges the same amount the policy sums.
            ir = policy.to_ir(amount=amount)
            model_admits = model_spend_ok_admits(ir, completed, inflight, amount)
            policy_sum = policy_sum_over_events(policy, completed, inflight, amount)
            policy_admits = policy_sum <= cap
            if model_admits != policy_admits:
                mismatches.append(
                    "  completed=%d, inflight=%d, amount=%d: "
                    "model=%s, policy_sum=%d, cap=%d, policy=%s"
                    % (completed, inflight, amount,
                       model_admits, policy_sum, cap, policy_admits))
        self.assertEqual(
            mismatches, [],
            "%s policy: %d correspondence mismatch(es):\n%s"
            % (label, len(mismatches), "\n".join(mismatches)))

    def test_correct_policy_correspondence(self):
        """The correct policy (``request`` events) corresponds to the
        correct model: ``model.spend_ok_admits == (policy.sum <= cap)``."""
        self._check(CORRECT, "correct")

    def test_buggy_policy_correspondence(self):
        """The buggy policy (``response`` events) corresponds to the buggy
        model: ``model.spend_ok_admits == (policy.sum <= cap)``."""
        self._check(BUGGY, "buggy")

    def test_buggy_admits_parallel_fire_race(self):
        """The buggy model admits a parallel fire (``completed = 0``,
        ``inflight >= 1``) that the correct model rejects -- the race is
        *expressible* in the model and *invisible* to the buggy policy.

        This is the concrete witness that the correspondence is not vacuous:
        the two policies *diverge* exactly where the race lives.
        """
        correct = parse_file(CORRECT)
        buggy = parse_file(BUGGY)
        ir_c = correct.to_ir()
        ir_b = buggy.to_ir()
        cap = correct.cap  # 200
        amount = spendcap.AMOUNT  # 100
        # completed = 0, inflight = 2: two in-flight requests, none settled.
        # Buggy: 0 + 100 = 100 <= 200 -> admits (the race).
        # Correct: 0 + 2*100 + 100 = 300 > 200 -> rejects.
        self.assertTrue(model_spend_ok_admits(ir_b, 0, 2, amount),
                        "buggy model should admit the parallel fire")
        self.assertFalse(model_spend_ok_admits(ir_c, 0, 2, amount),
                         "correct model should reject the parallel fire")
        # And the policy side agrees:
        self.assertTrue(policy_sum_over_events(buggy, 0, 2, amount) <= cap)
        self.assertFalse(policy_sum_over_events(correct, 0, 2, amount) <= cap)


if __name__ == "__main__":
    unittest.main()

