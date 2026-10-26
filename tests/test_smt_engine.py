# -*- coding: utf-8 -*-
"""Engine tests for ``rot.smtz3.SMTBackend`` -- the verdict-producing wrapper
over the concrete BFS engine (``rot.modelfind.ModelFinder``).

The spendcap (AWS Dogwood) vertical slice is the fixture: two variants share
the same state, actions, and the pinned safety property
``spendcap_within_cap`` (``completed + inflight * AMOUNT <= CAP``); they differ
only in the ``spend_ok`` decision rule:

  * correct -- charges in-flight requests against the cap, so the pinned
    property holds in every reachable state  -> SMTBackend proves it;
  * buggy   -- charges settled responses only, so a parallel burst of
    ``spend_ok`` grows the in-flight amount past the cap -> SMTBackend
    refutes it with a deterministic first-violating state.

Run: python tests/test_smt_engine.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.spendcap import AMOUNT, CAP, build_ir
from rot.invariants import Invariant, spendcap_within_cap
from rot.ir import BinOp, C, V
from rot.smtz3 import ENGINE, SMTBackend

try:
    import z3  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False


def _liveness_invariant(name, goal_expr, description="smt engine test goal"):
    """Build a minimal ``kind="liveness"`` invariant (goal = ``goal_expr``)."""
    return Invariant(
        name=name,
        description=description,
        expression=goal_expr,
        kind="liveness",
    )


def _goal_gte(var, value):
    return BinOp(">=", V(var), C(value))


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SMTBackendSafetyTest(unittest.TestCase):
    """Safety verdicts on the spendcap slice."""

    def test_correct_variant_is_proven(self):
        ir = build_ir(buggy=False)
        backend = SMTBackend(ir)
        prop = spendcap_within_cap()
        verdict = backend.verify_safety(prop)
        self.assertEqual(verdict.status, "proven")
        self.assertIsNone(verdict.counterexample)
        self.assertEqual(verdict.property_name, "spendcap_within_cap")
        self.assertEqual(verdict.engine, ENGINE)
        self.assertEqual(verdict.property_kind, "safety")

    def test_buggy_variant_is_violated(self):
        ir = build_ir(buggy=True)
        backend = SMTBackend(ir)
        prop = spendcap_within_cap()
        verdict = backend.verify_safety(prop)
        self.assertEqual(verdict.status, "violated")
        self.assertEqual(verdict.counterexample, {"completed": 0, "inflight": 3})
        self.assertEqual(verdict.property_kind, "safety")
        self.assertEqual(verdict.violation_code, "POLICY_DENIAL")

    def test_buggy_counterexample_actually_violates(self):
        """The counterexample must be a real violating reachable state."""
        ir = build_ir(buggy=True)
        backend = SMTBackend(ir)
        prop = spendcap_within_cap()
        verdict = backend.verify_safety(prop)
        self.assertEqual(verdict.status, "violated")
        # The pinned property evaluates to exactly False in the counterexample.
        self.assertIs(False, prop.expression.eval(verdict.counterexample))
        # The state itself is within the declared variable domains.
        self.assertEqual(verdict.counterexample["completed"], 0)
        self.assertEqual(verdict.counterexample["inflight"], 3)

    def test_buggy_counterexample_is_deterministic(self):
        """Repeated runs (fresh backends) yield the identical counterexample."""
        prop = spendcap_within_cap()
        dumps = []
        for _ in range(3):
            backend = SMTBackend(build_ir(buggy=True))
            verdict = backend.verify_safety(prop)
            self.assertEqual(verdict.status, "violated")
            dumps.append(json.dumps(verdict.counterexample, sort_keys=True))
        self.assertEqual(dumps[0], dumps[1])
        self.assertEqual(dumps[1], dumps[2])
        self.assertEqual(dumps[0], json.dumps({"completed": 0, "inflight": 3},
                                              sort_keys=True))

    def test_verdict_serializes_to_json(self):
        """Verdict.to_dict() must be JSON-serializable (report contract)."""
        prop = spendcap_within_cap()
        for buggy in (False, True):
            verdict = SMTBackend(build_ir(buggy=buggy)).verify_safety(prop)
            payload = json.dumps(verdict.to_dict(), sort_keys=True)
            self.assertIsInstance(payload, str)
            self.assertIn('"status"', payload)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SMTBackendLivenessTest(unittest.TestCase):
    """Bounded-liveness verdicts (goal reachability) on the spendcap slice."""

    def test_reachable_goal_is_proven(self):
        """``completed >= CAP`` is reachable in the correct variant (spend_ok,
        then responds settle it) -> bounded liveness holds."""
        ir = build_ir(buggy=False)
        backend = SMTBackend(ir)
        prop = _liveness_invariant("spendcap_settles_cap",
                                   _goal_gte("completed", CAP))
        verdict = backend.verify_liveness(bound=1000, prop=prop)
        self.assertEqual(verdict.status, "proven")
        self.assertEqual(verdict.property_kind, "liveness")
        self.assertIsNone(verdict.counterexample)
        witness = verdict.evidence.get("witness")
        self.assertIsInstance(witness, dict)
        # The witness must actually satisfy the goal predicate.
        self.assertIs(True, prop.expression.eval(witness))

    def test_unreachable_goal_is_violated(self):
        """``completed >= CAP + AMOUNT`` is unreachable in the correct variant
        (the in-flight-aware guard stops admitting before 300 can settle) ->
        bounded liveness fails within the horizon."""
        ir = build_ir(buggy=False)
        backend = SMTBackend(ir)
        prop = _liveness_invariant(
            "spendcap_over_cap", _goal_gte("completed", CAP + AMOUNT))
        verdict = backend.verify_liveness(bound=1000, prop=prop)
        self.assertEqual(verdict.status, "violated")
        self.assertEqual(verdict.property_kind, "liveness")
        self.assertIsNone(verdict.counterexample)
        self.assertEqual(verdict.violation_code, "LIVENESS_BOUND_EXCEEDED")

    def test_same_goal_reachable_in_buggy_variant(self):
        """Discrimination check: the over-cap goal *is* reachable in the buggy
        variant (settled-only accounting lets 300 settle) -> holds there."""
        ir = build_ir(buggy=True)
        backend = SMTBackend(ir)
        prop = _liveness_invariant(
            "spendcap_over_cap", _goal_gte("completed", CAP + AMOUNT))
        verdict = backend.verify_liveness(bound=1000, prop=prop)
        self.assertEqual(verdict.status, "proven")
        self.assertIs(True, prop.expression.eval(verdict.evidence["witness"]))


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class SMTBackendTraceTest(unittest.TestCase):
    """Counterexample trace on VIOLATED safety verdicts (5-tuple steps)."""

    @classmethod
    def setUpClass(cls):
        cls.prop = spendcap_within_cap()
        cls.verdict = SMTBackend(build_ir(buggy=True)).verify_safety(cls.prop)

    def test_buggy_verdict_has_three_step_trace(self):
        self.assertEqual(self.verdict.status, "violated")
        trace = self.verdict.trace
        self.assertIsInstance(trace, list)
        self.assertEqual(len(trace), 3)
        for step in trace:
            self.assertIsInstance(step, tuple)
            self.assertEqual(len(step), 5)

    def test_trace_steps_carry_policy_clause_and_guard(self):
        clause = self.prop.policy_clause
        self.assertIsNotNone(clause)
        for state_before, action, guard, step_clause, delta in self.verdict.trace:
            self.assertEqual(action, "spend_ok")
            self.assertEqual(step_clause, clause)
            self.assertEqual(
                guard, "completed + 100 <= 200 and inflight < 4")
            self.assertIsInstance(state_before, dict)
            self.assertIsInstance(delta, dict)

    def test_trace_replay_reaches_counterexample(self):
        state = {"completed": 0, "inflight": 0}
        for state_before, action, guard, clause, delta in self.verdict.trace:
            self.assertEqual(state, state_before)
            state = dict(state_before)
            state.update(delta)
        self.assertEqual(state, self.verdict.counterexample)

    def test_trace_markdown_contains_guard_strings(self):
        md = self.verdict.to_markdown()
        self.assertIn("## Counterexample trace", md)
        self.assertIn("1. **spend_ok**", md)
        self.assertIn(
            "- guard: `completed + 100 <= 200 and inflight < 4`", md)
        self.assertIn(
            "- policy_clause: `%s`" % self.prop.policy_clause, md)

    def test_proven_verdict_has_no_trace(self):
        verdict = SMTBackend(build_ir(buggy=False)).verify_safety(self.prop)
        self.assertEqual(verdict.status, "proven")
        self.assertIsNone(verdict.trace)


if __name__ == "__main__":
    unittest.main()
