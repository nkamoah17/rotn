# -*- coding: utf-8 -*-
"""Tests for the computed ``to_proceed`` list (rot.to_proceed) -- G7.

Covers the thesis's "computed mathematically" claim: the enabling condition of
a blocked action is read from its IR guard (the spec -- not a hand-written
string) and the currently-false conjuncts are emitted as the conditions under
which the action would become enabled, together with their negation (the
blockers).  Both the spend-cap and the exfiltration shapes are covered, which
is the acceptance bar for the generalized coach.

Run: python tests/test_to_proceed.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir  # noqa: E402
import rot.to_proceed as tp  # noqa: E402
import rot.agent_harness as agent_harness  # noqa: E402
import rot.spendcap as spendcap  # noqa: E402
import rot.coach as coach  # noqa: E402
from rot.dw import parse_file  # noqa: E402

#: The canonical buggy spend-cap .dw fixture (the ``response``-sum variant).
_POLICY_BUGGY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "aws_dogwood", "spendcap", "policies", "spendcap-buggy.dw")


def _corrected_spendcap_ir(max_inflight=3, amount=100):
    """The corrected (request-sum) spend-cap IR, as the coach builds it."""
    p = parse_file(_POLICY_BUGGY)
    return (coach._corrected_policy(p).to_ir(
        max_inflight=max_inflight, amount=amount, cap=p.cap,
        window=spendcap.MAX_WINDOW), p)


class ConjunctTests(unittest.TestCase):
    """The guard decomposition + false-conjunct selection."""

    def test_false_conjuncts_of_conjunction(self):
        e = ir.And(ir.V("a"), ir.V("b"))
        self.assertEqual(
            [c.to_dict() for c in tp.false_conjuncts(e, {"a": False, "b": True})],
            [ir.V("a").to_dict()])
        self.assertEqual(
            [c.to_dict() for c in tp.false_conjuncts(e, {"a": False, "b": False})],
            [ir.V("a").to_dict(), ir.V("b").to_dict()])
        self.assertEqual(tp.false_conjuncts(e, {"a": True, "b": True}), [])

    def test_false_conjuncts_drops_undef(self):
        # 'a' is definitely False; 'missing' is UNDEF (not a definite blocker).
        e = ir.And(ir.V("a"), ir.V("missing"))
        self.assertEqual(
            [c.to_dict() for c in tp.false_conjuncts(e, {"a": False})],
            [ir.V("a").to_dict()])

    def test_atom_is_its_own_conjunct(self):
        e = ir.Not(ir.V("holding"))
        self.assertEqual(tp.conjuncts(e), [e])

    def test_negate_double_negation(self):
        # not(not holding) -> holding (double-negation elimination).
        self.assertEqual(tp.negate(ir.Not(ir.V("holding"))).to_dict(),
                         ir.V("holding").to_dict())

    def test_negate_plain(self):
        n = tp.negate(ir.BinOp("<=", ir.V("x"), ir.C(1)))
        self.assertIsInstance(n, ir.UnOp)
        self.assertEqual(n.op, "not")


class SpendcapToProceedTests(unittest.TestCase):
    """The spend-cap shape: the enabling condition is the cap (+ pool bound)."""

    def test_blocked_in_witness(self):
        ir, _ = _corrected_spendcap_ir()
        rec = tp.compute_to_proceed(
            ir, "spend_ok", {"completed": 0, "inflight": 3})
        self.assertTrue(rec["blocked"])
        self.assertIn("completed + inflight * 100 + 100 <= 200",
                      rec["conditions"])

    def test_not_blocked_when_within_cap(self):
        ir, _ = _corrected_spendcap_ir()
        # 0 + 1*100 + 100 = 200 <= 200 and 1 < 3 -> the action is enabled.
        rec = tp.compute_to_proceed(
            ir, "spend_ok", {"completed": 0, "inflight": 1})
        self.assertFalse(rec["blocked"])
        self.assertEqual(rec["conditions"], [])

    def test_blockers_are_the_negations(self):
        ir, _ = _corrected_spendcap_ir()
        rec = tp.compute_to_proceed(
            ir, "spend_ok", {"completed": 0, "inflight": 3})
        self.assertEqual(len(rec["conditions"]), len(rec["blockers"]))
        self.assertTrue(rec["conditions"])
        self.assertTrue(all(b.startswith("not ") for b in rec["blockers"]))

    def test_guard_is_rendered_from_the_spec(self):
        ir, _ = _corrected_spendcap_ir()
        rec = tp.compute_to_proceed(
            ir, "spend_ok", {"completed": 0, "inflight": 3})
        self.assertIn("inflight * 100", rec["guard"])
        self.assertIn("<= 200", rec["guard"])


class ExfiltrationToProceedTests(unittest.TestCase):
    """The enabling condition is ``not holding_private``."""

    def test_blocked_when_holding(self):
        ir = agent_harness.exfiltrate_build_ir(buggy=False)
        rec = tp.compute_to_proceed(
            ir, "agent_take_send_unapproved",
            {"holding_private": True, "exfiltrated": True})
        self.assertTrue(rec["blocked"])
        self.assertEqual(rec["conditions"], ["not holding_private"])
        # the blocker is the double-negation-eliminated negation.
        self.assertEqual(rec["blockers"], ["holding_private"])

    def test_enabled_when_not_holding(self):
        ir = agent_harness.exfiltrate_build_ir(buggy=False)
        rec = tp.compute_to_proceed(
            ir, "agent_take_send_unapproved", {"holding_private": False})
        self.assertFalse(rec["blocked"])
        self.assertEqual(rec["conditions"], [])

    def test_none_state_is_safe(self):
        ir = agent_harness.exfiltrate_build_ir(buggy=False)
        rec = tp.compute_to_proceed(ir, "agent_take_send_unapproved", None)
        self.assertIsInstance(rec, dict)
        self.assertIn("blocked", rec)
        self.assertIsInstance(rec["conditions"], list)


class DeterminismTests(unittest.TestCase):
    """The record is a pure function of the IR + state (deterministic)."""

    def test_deterministic(self):
        ir = agent_harness.exfiltrate_build_ir(buggy=False)
        s = {"holding_private": True, "exfiltrated": True}
        self.assertEqual(
            tp.compute_to_proceed(ir, "agent_take_send_unapproved", s),
            tp.compute_to_proceed(ir, "agent_take_send_unapproved", s))

    def test_json_serialisable(self):
        import json
        ir = agent_harness.exfiltrate_build_ir(buggy=False)
        rec = tp.compute_to_proceed(
            ir, "agent_take_send_unapproved",
            {"holding_private": True, "exfiltrated": True})
        self.assertIsInstance(json.loads(json.dumps(rec)), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)