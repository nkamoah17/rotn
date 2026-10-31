# -*- coding: utf-8 -*-
"""T0a -- the runtime/offline SOUNDNESS LINK ("the proof covers the runtime").

The core thesis is: *the LLM proposes, a deterministic core decides.*  For that
to be **sound**, the runtime guard (fast, in-path) and the offline verifier
(bounded model checking, CI/pre-deploy) must be the *same evaluation of the
same decision rule*.  If they ever diverge, "offline says safe" no longer
implies "runtime enforces safe" -- the core claim cracks.

This test pins the link at the decision-rule level.

boundary (stated, not implied)
    runtime  = fast guard evaluation, in-path, O(tools);
    offline  = bounded model checking over reachable states, CI/pre-deploy;
    same     = the SAME guard predicate (``Rule.guard()``), different engines.
    They are never conflated: the runtime is the fast enforcement of exactly
    the predicate the offline engine discharges exhaustively.

assertions
    1. one decision rule   -- the runtime rule's guard and the offline spend-cap
       model's ``spend_ok`` guard evaluate IDENTICALLY over a state battery, so
       the two planes cannot drift;
    2. decision == guard    -- ``RuntimeGuard.decide()`` is *exactly* the guard
       predicate (allow iff the guard is True) for every state in the battery;
    3. unblock names it     -- a blocked parallel-fire state yields a refusal
       whose ``to_proceed`` points at the in-flight count (the root cause).

A mutation that makes the runtime ignore ``inflight`` (or add a special case)
fails (2); a mutation that drifts the runtime rule from the offline model fails
(1).  That is the moat made load-bearing.

Python 3.6 compatible (no f-strings).
"""

import unittest

import rot.spendcap as spendcap
import rot.runtime.rules as rules
from rot.runtime.core import RuntimeGuard

# The runtime rule (rules.spendcap_rule) and the offline model are built from
# the SAME spend-cap builder with the SAME parameters (K=4, AMOUNT=100, CAP=200).
# Keep them in lock-step here so the "one decision rule" assertion is exact.
K, AMOUNT, CAP = 4, 100, 200


def _state_battery():
    """A battery of (completed, inflight) states spanning the cap boundary.

    Covers the masked (K=1) region, the parallel-fire region (inflight >= 1),
    and the over-cap region, so a regression that special-cases any of them is
    caught.
    """
    for completed in (0, 100, 200, 300):
        for inflight in (0, 1, 2, 3):
            yield {"completed": completed, "inflight": inflight}


class TestRuntimeOfflineAgreement(unittest.TestCase):
    def test_runtime_and_offline_share_one_decision_rule(self):
        """(1) The runtime rule's guard == the offline model's ``spend_ok`` guard.

        Both are built from ``spendcap.build_ir(buggy=False, ...)`` with the
        same K/AMOUNT/CAP, so they must evaluate identically in every state.
        (Expr has no ``__eq__`` -- compare *behaviorally*, not by identity.)
        """
        runtime_guard = rules.get_rule("spendcap_within_cap").guard()
        offline_guard = spendcap.build_ir(
            buggy=False, max_inflight=K, amount=AMOUNT, cap=CAP
        ).action("spend_ok").guard
        for state in _state_battery():
            self.assertEqual(
                runtime_guard.eval(state), offline_guard.eval(state),
                "runtime/offline decision rule diverges at %s" % (state,))

    def test_runtime_decision_is_exactly_the_guard(self):
        """(2) ``RuntimeGuard.decide()`` is the guard predicate, point for point.

        allow  iff  guard is True;  block  iff  guard is False or UNDEF
        (fail-closed).  This is the precise statement that the runtime
        enforces *exactly* the predicate the offline engine proves.
        """
        rule = rules.get_rule("spendcap_within_cap")
        guard = rule.guard()
        rg = RuntimeGuard(rule)
        for state in _state_battery():
            self.assertEqual(
                rg.decide(state=state).allowed,
                (guard.eval(state) is True),
                "RuntimeGuard.decide is not the guard predicate at %s" % (state,))

    def test_blocked_parallel_fire_names_inflight(self):
        """(3) A blocked parallel-fire refusal points at the in-flight count.

        ``to_proceed`` is the enabling condition read from the spec; for the
        spend-cap shape the blocking quantity is the in-flight set (what the
        settled-trace monitor cannot see), so the refusal must name it.
        """
        rule = rules.get_rule("spendcap_within_cap")
        d = RuntimeGuard(rule).decide(
            state={"completed": 100, "inflight": 2},
            request={"tool": rule.action})
        self.assertTrue(d.blocked, "the parallel-fire state must be blocked")
        self.assertFalse(d.allowed)
        tp = d.refusal.to_proceed
        self.assertTrue(("inflight" in tp) or ("in-flight" in tp),
                        "to_proceed must name the in-flight count, got %r" % (tp,))


if __name__ == "__main__":
    unittest.main()
