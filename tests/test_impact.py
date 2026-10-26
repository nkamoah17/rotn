# -*- coding: utf-8 -*-
"""Unit tests for rot.impact: impact-set (cone-of-influence) computation.

Covers:
  * isolated change (a single action touching a private variable)
  * per-transaction scoping on ZAB (no leak to other transactions)
  * non-isolated / fully-coupled impact on 2PC
  * unknown changed-action error
  * invariant filtering (only invars over the impact scope are flagged)
  * empty-changed-actions edge case

Run: python tests/test_impact.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.ir import (
    ProtocolIR, StateVar, Enum, Action, Assignment, V, C, eq, If, T,
)
from rot.impact import (
    ImpactSet, compute_impact, _free_vars, _action_free_vars,
)
from rot.invariants import Invariant
from rot.zab import build_ir as zab_build_ir
from rot.twopc import build_ir as twopc_build_ir


def _mini_ir():
    """Two fully independent actions over disjoint variables."""
    x = StateVar("x", Enum(["a", "b"]))
    y = StateVar("y", Enum(["p", "q"]))
    init = Action("init", "global", guard=T(),
                  effects=[Assignment("x", C("a")), Assignment("y", C("p"))],
                  is_initial=True)
    ax = Action("ax", "global", guard=eq(V("x"), C("a")),
                effects=[Assignment("x", C("b"))])
    by = Action("by", "global", guard=eq(V("y"), C("p")),
                effects=[Assignment("y", C("q"))])
    return ProtocolIR(name="mini", variables=[x, y],
                      actions=[init, ax, by], init=T())


# ---------------------------------------------------------------------------
# 1. Free-variable helpers
# ---------------------------------------------------------------------------
class FreeVarHelperTests(unittest.TestCase):

    def test_free_vars_simple(self):
        e = eq(V("x"), C("a"))
        self.assertEqual(_free_vars(e), {"x"})

    def test_free_vars_nested(self):
        e = If(eq(V("x"), C("a")), eq(V("y"), C("b")), C(True))
        self.assertEqual(_free_vars(e), {"x", "y"})

    def test_free_vars_none(self):
        self.assertEqual(_free_vars(None), set())

    def test_action_free_vars_includes_targets(self):
        a = _mini_ir().action("ax")
        fv = _action_free_vars(a)
        self.assertIn("x", fv)
        self.assertNotIn("pc", fv)


# ---------------------------------------------------------------------------
# 2. ImpactSet dataclass
# ---------------------------------------------------------------------------
class ImpactSetDataclassTests(unittest.TestCase):

    def test_sorted_unique_fields(self):
        s = ImpactSet(
            changed_actions=["b", "a", "a"],
            impacted_actions=["c", "b", "a"],
            affected_invariants=["p2", "p1"],
            scope_reason="r",
            impacted_variables=["v2", "v1"],
        )
        self.assertEqual(s.changed_actions, ["a", "b"])
        self.assertEqual(s.impacted_actions, ["a", "b", "c"])
        self.assertEqual(s.affected_invariants, ["p1", "p2"])
        self.assertEqual(s.impacted_variables, ["v1", "v2"])

    def test_indirect_and_isolated(self):
        s = ImpactSet(["ax"], ["ax", "by"], [], "r", ["x"])
        self.assertEqual(s.indirect_actions, ["by"])
        self.assertFalse(s.is_isolated)
        s2 = ImpactSet(["ax"], ["ax"], [], "r", ["x"])
        self.assertEqual(s2.indirect_actions, [])
        self.assertTrue(s2.is_isolated)

    def test_to_dict_keys(self):
        s = ImpactSet(["ax"], ["ax"], [], "r", ["x"])
        d = s.to_dict()
        for k in ("changed_actions", "impacted_actions", "indirect_actions",
                  "affected_invariants", "impacted_variables", "scope_reason",
                  "is_isolated"):
            self.assertIn(k, d)


# ---------------------------------------------------------------------------
# 3. Isolated change (minimal IR)
# ---------------------------------------------------------------------------
class IsolatedImpactTests(unittest.TestCase):

    def test_single_action_is_isolated(self):
        s = compute_impact(_mini_ir(), ["ax"], invariants=[])
        self.assertEqual(s.impacted_actions, ["ax"])
        self.assertTrue(s.is_isolated)
        self.assertEqual(s.indirect_actions, [])
        self.assertEqual(s.affected_invariants, [])

    def test_isolated_variables_only_own(self):
        s = compute_impact(_mini_ir(), ["ax"], invariants=[])
        self.assertEqual(s.impacted_variables, ["x"])

    def test_changed_action_not_init(self):
        # init is never a transition action; changing it is an error.
        with self.assertRaises(ValueError):
            compute_impact(_mini_ir(), ["init"], invariants=[])


# ---------------------------------------------------------------------------
# 4. ZAB -- per-transaction scoping (no cross-transaction leak)
# ---------------------------------------------------------------------------
class ZabImpactTests(unittest.TestCase):

    def setUp(self):
        self.ir = zab_build_ir(3)
        self.s = compute_impact(self.ir, ["apply_1_1"], invariants=[])

    def test_confined_to_transaction_1(self):
        # No transaction-2 action leaks in.
        self.assertNotIn("apply_2_1", self.s.impacted_actions)
        self.assertNotIn("commit_2", self.s.impacted_actions)
        self.assertNotIn("persist_2_1", self.s.impacted_actions)

    def test_impact_is_non_isolated(self):
        # apply_1_1 shares state with the other tx-1 actions -> indirect impact.
        self.assertFalse(self.s.is_isolated)
        self.assertIn("commit_1", self.s.impacted_actions)
        self.assertIn("persist_1_1", self.s.impacted_actions)

    def test_impacted_variables_are_tx1_only(self):
        for v in self.s.impacted_variables:
            self.assertTrue(v.startswith(("persisted_1_", "applied_1_")) or
                            v == "committed_1", v)
        self.assertIn("committed_1", self.s.impacted_variables)
        self.assertNotIn("committed_2", self.s.impacted_variables)


# ---------------------------------------------------------------------------
# 5. 2PC -- fully coupled (non-isolated)
# ---------------------------------------------------------------------------
class TwopcImpactTests(unittest.TestCase):

    def setUp(self):
        self.ir = twopc_build_ir(4)
        self.s = compute_impact(self.ir, ["vote_1_yes"], invariants=[])

    def test_not_isolated(self):
        self.assertFalse(self.s.is_isolated)
        self.assertTrue(self.s.indirect_actions)

    def test_reaches_decide_and_applies(self):
        self.assertIn("decide", self.s.impacted_actions)
        self.assertIn("apply_1", self.s.impacted_actions)
        # The change couples to the other voters' vote actions via `phase`.
        self.assertIn("vote_2_yes", self.s.impacted_actions)

    def test_phase_in_impact_scope(self):
        self.assertIn("phase", self.s.impacted_variables)
        self.assertIn("decision", self.s.impacted_variables)


# ---------------------------------------------------------------------------
# 6. Error handling
# ---------------------------------------------------------------------------
class ErrorTests(unittest.TestCase):

    def test_unknown_changed_action_raises(self):
        with self.assertRaises(ValueError) as ctx:
            compute_impact(_mini_ir(), ["does_not_exist"], invariants=[])
        self.assertIn("does_not_exist", str(ctx.exception))

    def test_empty_changed_actions(self):
        s = compute_impact(_mini_ir(), [], invariants=[])
        self.assertEqual(s.impacted_actions, [])
        self.assertEqual(s.changed_actions, [])
        self.assertEqual(s.affected_invariants, [])
        self.assertIn("empty", s.scope_reason.lower())


# ---------------------------------------------------------------------------
# 7. Invariant filtering
# ---------------------------------------------------------------------------
class InvariantFilteringTests(unittest.TestCase):

    def setUp(self):
        self.ir = zab_build_ir(3)
        self.inv_tx1 = Invariant(
            "tx1_prop", "d",
            If(eq(V("applied_1_1"), C("done")),
               eq(V("committed_1"), C("done")), C(True)),
            "safety")
        self.inv_tx2 = Invariant(
            "tx2_prop", "d",
            If(eq(V("applied_2_1"), C("done")),
               eq(V("committed_2"), C("done")), C(True)),
            "safety")

    def test_only_scoped_invariant_flagged(self):
        s = compute_impact(self.ir, ["apply_1_1"],
                           invariants=[self.inv_tx1, self.inv_tx2])
        self.assertEqual(s.affected_invariants, ["tx1_prop"])

    def test_unrelated_invariant_not_flagged(self):
        s = compute_impact(self.ir, ["apply_1_1"], invariants=[self.inv_tx2])
        self.assertEqual(s.affected_invariants, [])

    def test_none_expression_skipped(self):
        inv = Invariant("noexpr", "d", None, "safety")
        s = compute_impact(self.ir, ["apply_1_1"], invariants=[inv])
        self.assertEqual(s.affected_invariants, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)