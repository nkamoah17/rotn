# -*- coding: utf-8 -*-
"""Unit tests for rot.specdiff: semantic before/after ProtocolIR diffs.

Covers:
  * no-change diff is NONE / empty
  * added / removed action (STRUCTURAL)
  * modified guard / effect (SEMANTIC, with the changed part flagged)
  * action rename (COSMETIC, reported once -- not a remove + an add)
  * added / removed variable (STRUCTURAL)
  * variable rename (COSMETIC, references rewritten consistently)
  * changed domain definition (SEMANTIC, plus a domain element)
  * channel added / removed (STRUCTURAL)
  * init / pinned-property change (SEMANTIC)
  * assumption change (SEMANTIC) and assumption reorder (COSMETIC)
  * pure action / variable reordering (COSMETIC)
  * overall severity is the maximum across elements
  * to_dict() / render() output and error handling

Run: python tests/test_specdiff.py
"""

import os
import sys
import unittest
from copy import deepcopy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.ir import (ProtocolIR, StateVar, Action, Enum, Channel, Assignment,
                    V, C, eq)
from rot import specdiff
from rot.specdiff import (NONE, COSMETIC, STRUCTURAL, SEMANTIC,
                          compute_spec_diff)


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------
def _x(dom=None):
    return StateVar("x", dom if dom is not None else Enum(["a", "b"]))


def _act(name="act", var="x"):
    return Action(name, "global", guard=eq(V(var), C("a")),
                  effects=[Assignment(var, C("b"))])


def _base(dom=None):
    """One variable ``x`` (domain ``dom``) and one action over it."""
    return ProtocolIR("p", variables=[_x(dom)], actions=[_act()])


def _two_actions():
    return ProtocolIR(
        "p", variables=[_x()],
        actions=[Action("a1", "global", guard=eq(V("x"), C("a")),
                        effects=[Assignment("x", C("b"))]),
                 Action("a2", "global", guard=eq(V("x"), C("b")),
                        effects=[Assignment("x", C("a"))])])


def _with(ir, **kw):
    """A deep copy of ``ir`` with the named top-level fields replaced."""
    ir2 = deepcopy(ir)
    for k, v in kw.items():
        setattr(ir2, k, v)
    return ir2


def _actions(d):
    return [e.action for e in d.elements if e.kind == "action"]


def _vars(d):
    return [e.variable for e in d.elements if e.kind == "variable"]


def _channels(d):
    return [e.channel for e in d.elements if e.kind == "channel"]


# ---------------------------------------------------------------------------
# 1. basic severity / identity
# ---------------------------------------------------------------------------
class BasicSeverityTests(unittest.TestCase):
    def test_no_change_is_none(self):
        d = compute_spec_diff(_base(), _base())
        self.assertEqual(d.severity, NONE)
        self.assertTrue(d.is_empty)
        self.assertFalse(d.changed)
        self.assertEqual(d.elements, [])
        self.assertEqual(d.summary_counts()[NONE], 0)

    def test_overall_severity_is_max(self):
        # a cosmetic action rename *and* a semantic domain change -> SEMANTIC
        before = _base()
        after = _with(_base(dom=Enum(["a", "b", "c"])),
                      actions=[_act(name="act2")])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        counts = d.summary_counts()
        self.assertGreater(counts[COSMETIC], 0)
        self.assertGreater(counts[SEMANTIC], 0)

    def test_none_before_raises(self):
        self.assertRaises(ValueError, compute_spec_diff, None, _base())

    def test_none_after_raises(self):
        self.assertRaises(ValueError, compute_spec_diff, _base(), None)

    def test_diff_alias(self):
        self.assertEqual(specdiff.diff(_base(), _base()).severity, NONE)


# ---------------------------------------------------------------------------
# 2. actions
# ---------------------------------------------------------------------------
class ActionTests(unittest.TestCase):
    def test_added_action_is_structural(self):
        before = _base()
        after = _with(before, actions=[_act(), _act(name="act2", var="x")])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, STRUCTURAL)
        added = [a for a in _actions(d) if a.kind == "added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].name, "act2")

    def test_removed_action_is_structural(self):
        before = _with(_base(), actions=[_act(), _act(name="act2", var="x")])
        d = compute_spec_diff(before, _base())
        self.assertEqual(d.severity, STRUCTURAL)
        removed = [a for a in _actions(d) if a.kind == "removed"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0].name, "act2")

    def test_modified_guard_is_semantic(self):
        before = _base()
        after = _with(before, actions=[
            Action("act", "global", guard=eq(V("x"), C("c")),
                   effects=[Assignment("x", C("b"))])])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        mod = [a for a in _actions(d) if a.kind == "modified"]
        self.assertEqual(len(mod), 1)
        self.assertTrue(mod[0].guard_changed)
        self.assertFalse(mod[0].effect_changed)

    def test_modified_effect_is_semantic(self):
        before = _base()
        after = _with(before, actions=[
            Action("act", "global", guard=eq(V("x"), C("a")),
                   effects=[Assignment("x", C("c"))])])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        mod = [a for a in _actions(d) if a.kind == "modified"]
        self.assertEqual(len(mod), 1)
        self.assertFalse(mod[0].guard_changed)
        self.assertTrue(mod[0].effect_changed)

    def test_action_rename_is_cosmetic_and_single(self):
        before = _base()
        after = _with(before, actions=[_act(name="act2")])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, COSMETIC)
        # exactly one action element, a rename -- not a remove + an add
        self.assertEqual(len(_actions(d)), 1)
        renamed = _actions(d)[0]
        self.assertEqual(renamed.kind, "renamed")
        self.assertEqual(renamed.old_name, "act")
        self.assertEqual(renamed.name, "act2")


# ---------------------------------------------------------------------------
# 3. variables, domains, channels
# ---------------------------------------------------------------------------
class VariableTests(unittest.TestCase):
    def test_added_variable_is_structural(self):
        before = _base()
        after = _with(before, variables=[_x(), StateVar("y", Enum(["p", "q"]))])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, STRUCTURAL)
        added = [v for v in _vars(d) if v.kind == "added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].new_name, "y")

    def test_removed_variable_is_structural(self):
        before = _with(_base(), variables=[_x(), StateVar("y", Enum(["p", "q"]))])
        d = compute_spec_diff(before, _base())
        self.assertEqual(d.severity, STRUCTURAL)
        removed = [v for v in _vars(d) if v.kind == "removed"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0].old_name, "y")

    def test_variable_rename_is_cosmetic_and_single(self):
        before = _base()
        after = ProtocolIR("p", variables=[StateVar("y", Enum(["a", "b"]))],
                           actions=[Action("act", "global", guard=eq(V("y"), C("a")),
                                          effects=[Assignment("y", C("b"))])])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, COSMETIC)
        # one variable rename + no action change (reference rewritten)
        self.assertEqual(len(_vars(d)), 1)
        self.assertEqual(len(_actions(d)), 0)
        renamed = _vars(d)[0]
        self.assertEqual(renamed.kind, "renamed")
        self.assertEqual(renamed.old_name, "x")
        self.assertEqual(renamed.new_name, "y")

    def test_domain_change_is_semantic_with_domain_element(self):
        before = _base()
        after = _base(dom=Enum(["a", "b", "c"]))
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertTrue(any(v.domain_changed for v in _vars(d)))
        self.assertEqual(len(d.domain_changes()), 1)
        self.assertEqual(d.domain_changes()[0].variable, "x")

    def test_channel_added_is_structural(self):
        before = _base()
        after = _with(before, channels=[Channel("req", "a", "b")])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, STRUCTURAL)
        added = [c for c in _channels(d) if c.kind == "added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].name, "req")

    def test_channel_removed_is_structural(self):
        before = _with(_base(), channels=[Channel("req", "a", "b")])
        d = compute_spec_diff(before, _base())
        self.assertEqual(d.severity, STRUCTURAL)
        removed = [c for c in _channels(d) if c.kind == "removed"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0].name, "req")


# ---------------------------------------------------------------------------
# 4. init / property / assumptions
# ---------------------------------------------------------------------------
class PredicateAssumptionTests(unittest.TestCase):
    def test_init_change_is_semantic(self):
        before = _base()
        after = _with(before, init=eq(V("x"), C("a")))
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertTrue(any(e.kind == "init" for e in d.elements))

    def test_property_change_is_semantic(self):
        before = _base()
        after = _with(before, pinned_property=eq(V("x"), C("a")))
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertTrue(any(e.kind == "property" for e in d.elements))

    def test_assumption_added_is_semantic(self):
        before = _base()
        after = _with(before, assumptions=[eq(V("x"), C("a"))])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertTrue(any(e.kind == "assumption" for e in d.elements))

    def test_assumption_removed_is_semantic(self):
        before = _with(_base(), assumptions=[eq(V("x"), C("a"))])
        d = compute_spec_diff(before, _base())
        self.assertEqual(d.severity, SEMANTIC)
        self.assertTrue(any(e.kind == "assumption" for e in d.elements))

    def test_assumption_reordered_is_cosmetic(self):
        p = eq(V("x"), C("a"))
        q = eq(V("x"), C("b"))
        before = _with(_base(), assumptions=[p, q])
        after = _with(_base(), assumptions=[q, p])
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, COSMETIC)
        self.assertTrue(any(e.kind == "assumption" for e in d.elements))


# ---------------------------------------------------------------------------
# 5. pure reordering
# ---------------------------------------------------------------------------
class OrderingTests(unittest.TestCase):
    def test_action_reorder_is_cosmetic(self):
        ir = _two_actions()
        before = ir
        after = _with(ir, actions=list(reversed(ir.actions)))
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, COSMETIC)
        order = [e for e in d.elements if e.kind == "ordering"]
        self.assertEqual(len(order), 1)
        self.assertEqual(order[0].ordering_kind, "actions")

    def test_variable_reorder_is_cosmetic(self):
        base = _with(_base(), variables=[StateVar("x", Enum(["a", "b"])),
                                         StateVar("y", Enum(["p", "q"]))])
        before = base
        after = _with(base, variables=list(reversed(base.variables)))
        d = compute_spec_diff(before, after)
        self.assertEqual(d.severity, COSMETIC)
        order = [e for e in d.elements if e.kind == "ordering"]
        self.assertEqual(len(order), 1)
        self.assertEqual(order[0].ordering_kind, "variables")


# ---------------------------------------------------------------------------
# 6. serialisation
# ---------------------------------------------------------------------------
class SerializationTests(unittest.TestCase):
    def test_to_dict_empty(self):
        dd = compute_spec_diff(_base(), _base()).to_dict()
        self.assertEqual(dd["before"], "p")
        self.assertEqual(dd["after"], "p")
        self.assertEqual(dd["severity"], NONE)
        self.assertTrue(dd["is_empty"])
        self.assertEqual(dd["elements"], [])

    def test_to_dict_with_change(self):
        before = _base()
        after = _with(before, actions=[_act(), _act(name="act2", var="x")])
        dd = compute_spec_diff(before, after).to_dict()
        self.assertEqual(dd["severity"], STRUCTURAL)
        self.assertFalse(dd["is_empty"])
        self.assertEqual(len(dd["elements"]), 1)
        self.assertEqual(dd["elements"][0]["kind"], "action")
        self.assertEqual(dd["elements"][0]["severity"], STRUCTURAL)
        self.assertEqual(dd["elements"][0]["action"]["kind"], "added")

    def test_render_empty(self):
        text = compute_spec_diff(_base(), _base()).render()
        self.assertIn("no changes", text)
        self.assertIn(NONE.upper(), text)

    def test_render_nonempty(self):
        before = _base()
        after = _with(before, actions=[_act(), _act(name="act2", var="x")])
        text = compute_spec_diff(before, after).render()
        self.assertIn("STRUCTURAL", text)
        self.assertIn("act2", text)
        self.assertIn("added", text)

    def test_render_rename(self):
        before = _base()
        after = _with(before, actions=[_act(name="act2")])
        text = compute_spec_diff(before, after).render()
        self.assertIn("renamed", text)
        self.assertIn("COSMETIC", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
