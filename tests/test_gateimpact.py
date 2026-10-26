# -*- coding: utf-8 -*-
"""Tests for ``rot.gateimpact``.

``gateimpact`` is a read-only analysis layer that maps a
``rot.specdiff.SpecDiff`` onto the W3 replay gate (the ``(owner, action)``
Java gate points) and onto a witness path, so a reviewer can see at a glance
which changed actions are part of the gate contract and which steps of a
counterexample witness actually exercise a changed action.

These tests exercise the public API against:

* small, hand-built 2PC-shaped ``ProtocolIR``s (gate actions
  ``vote_*_yes`` / ``decide`` / ``apply_*``) so we can force a specific
  change (rename / guard / effect / add / remove) and assert on the result; and
* the built-in ``rot.targets`` 2PC pair (``correct`` vs ``buggy``), the
  canonical agreement-breaking change, for ``analyze_target_gate_impact``.

They do NOT run the pipeline / cegar / abstraction.
"""
from __future__ import print_function

import unittest
from copy import deepcopy

from rot.ir import (ProtocolIR, StateVar, Action, Enum, Assignment, V, C, eq)
from rot.specdiff import (NONE, COSMETIC, STRUCTURAL, SEMANTIC,
                          compute_spec_diff)
import rot.targets
from rot import gateimpact
from rot.gateimpact import (gate_action, witness_to_gate_steps,
                            changed_gate_actions, impacted_witness_steps,
                            analyze_gate_impact, analyze_target_gate_impact,
                            ActionImpact, WitnessStepImpact, GateImpact)


# ---------------------------------------------------------------------------
# Small 2PC-shaped ProtocolIR builders.
#
# Every action gets a *distinct* (guard, effect) pair by referencing a unique
# constant tag, so ``compute_spec_diff`` can tell the actions apart. A rename
# keeps the (guard, effect) tag and changes only the name -- exactly what the
# rename-aware diffing in ``specdiff`` keys off.
# ---------------------------------------------------------------------------
def _act(name, guard_tag, effect_tag, owner="global"):
    """An action whose guard/effect reference distinct constants."""
    return Action(name, owner,
                  guard=eq(V("flag"), C(guard_tag)),
                  effects=[Assignment("flag", C(effect_tag))])


def _specs(n=3):
    """(name, guard_tag, effect_tag, owner) for a small 2PC spec."""
    s = [("init", "i", "i", "coordinator"),
         ("vote_1_yes", "v1", "v1", "participant_1"),
         ("vote_2_yes", "v2", "v2", "participant_2"),
         ("decide", "d", "d", "coordinator")]
    for i in range(1, n + 1):
        s.append(("apply_%d" % i, "a%d" % i, "a%d" % i,
                  "participant_%d" % i))
    s.append(("done", "dn", "dn", "coordinator"))
    return s


# A domain large enough for every tag used by the base spec and the
# "modified" / "added" variants below (d2, e2, a4).
DOMAIN = ["i", "v1", "v2", "d", "dn", "a1", "a2", "a3", "a4", "d2", "e2"]


def _domain():
    return Enum(list(DOMAIN))


def _two_pc(n=3):
    specs = _specs(n)
    actions = [_act(nm, g, e, o) for (nm, g, e, o) in specs]
    return ProtocolIR("two_pc", variables=[StateVar("flag", _domain())],
                      actions=actions)


def _with(ir, **kw):
    ir2 = deepcopy(ir)
    for k, v in kw.items():
        setattr(ir2, k, v)
    return ir2


def _rebuild(base, replace=None, add=None, drop=None):
    """Copy ``base`` with its action list rebuilt by name."""
    replace = replace or {}
    drop = drop or set()
    out = []
    for a in base.actions:
        if a.name in drop:
            continue
        if a.name in replace:
            nm, g, e = replace[a.name]
            out.append(_act(nm, g, e))
        else:
            out.append(a)
    if add:
        out.extend(add)
    return _with(base, actions=out)


def _diff(base, after):
    return compute_spec_diff(base, after)


# Witness path exercising every participant's apply step.
# Index map: 0 init, 1 vote_1_yes, 2 decide, 3 apply_1, 4 apply_2,
#            5 apply_3, 6 done.
WPATH = ["init", "vote_1_yes", "decide", "apply_1", "apply_2", "apply_3",
         "done"]

# ---------------------------------------------------------------------------
# gate_action: the (owner, action) mapping for the W3 gate contract
# ---------------------------------------------------------------------------
class TestGateAction(unittest.TestCase):
    def test_vote_action_maps_to_participant(self):
        self.assertEqual(gate_action("vote_1_yes"),
                         ("participant_1", "vote_1_yes"))
        self.assertEqual(gate_action("vote_2_yes"),
                         ("participant_2", "vote_2_yes"))
        self.assertEqual(gate_action("vote_3_no"),
                         ("participant_3", "vote_3_no"))

    def test_decide_maps_to_coordinator(self):
        self.assertEqual(gate_action("decide"), ("coordinator", "decide"))

    def test_apply_action_maps_to_participant(self):
        self.assertEqual(gate_action("apply_1"), ("participant_1", "apply_1"))
        self.assertEqual(gate_action("apply_2"), ("participant_2", "apply_2"))

    def test_non_gate_actions_are_none(self):
        self.assertIsNone(gate_action("init"))
        self.assertIsNone(gate_action("done"))
        self.assertIsNone(gate_action("foo"))
        self.assertIsNone(gate_action(""))

    def test_malformed_vote_name_is_none(self):
        self.assertIsNone(gate_action("vote_"))
        self.assertIsNone(gate_action("vote_x"))

    def test_none_input_is_none(self):
        self.assertIsNone(gate_action(None))


# ---------------------------------------------------------------------------
# witness_to_gate_steps: project a witness path onto the gate schedule
# ---------------------------------------------------------------------------
class TestWitnessToGateSteps(unittest.TestCase):
    def test_full_path(self):
        self.assertEqual(
            witness_to_gate_steps(WPATH),
            [("participant_1", "vote_1_yes"),
             ("coordinator", "decide"),
             ("participant_1", "apply_1"),
             ("participant_2", "apply_2"),
             ("participant_3", "apply_3")])

    def test_empty_and_none(self):
        self.assertEqual(witness_to_gate_steps([]), [])
        self.assertEqual(witness_to_gate_steps(None), [])

    def test_skips_non_gate_actions(self):
        self.assertEqual(witness_to_gate_steps(["init", "decide", "done"]),
                         [("coordinator", "decide")])

# ---------------------------------------------------------------------------
# changed_gate_actions: per-action impact of a spec diff
# ---------------------------------------------------------------------------
class TestChangedGateActions(unittest.TestCase):
    def setUp(self):
        self.base = _two_pc()

    def test_no_change_is_empty(self):
        d = _diff(self.base, _two_pc())
        self.assertEqual(d.severity, NONE)
        self.assertEqual(changed_gate_actions(d), [])

    def test_rename_is_cosmetic_with_old_name_and_gate(self):
        after = _rebuild(self.base, replace={"apply_2": ("apply_2x", "a2", "a2")})
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(d.severity, COSMETIC)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "apply_2x")
        self.assertEqual(impact.old_name, "apply_2")
        self.assertEqual(impact.diff_kind, "renamed")
        self.assertEqual(impact.severity, COSMETIC)
        self.assertTrue(impact.is_gate)
        self.assertEqual(impact.gate, ("participant_2x", "apply_2x"))

    def test_guard_change_is_semantic(self):
        # guard tag d -> d2, effect tag unchanged (d)
        after = _rebuild(self.base, replace={"decide": ("decide", "d2", "d")})
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "decide")
        self.assertEqual(impact.diff_kind, "modified")
        self.assertEqual(impact.severity, SEMANTIC)
        self.assertTrue(impact.guard_changed)
        self.assertFalse(impact.effect_changed)
        self.assertEqual(impact.gate, ("coordinator", "decide"))

    def test_effect_change_is_semantic(self):
        # effect tag d -> e2, guard tag unchanged (d)
        after = _rebuild(self.base, replace={"decide": ("decide", "d", "e2")})
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(d.severity, SEMANTIC)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "decide")
        self.assertTrue(impact.effect_changed)
        self.assertFalse(impact.guard_changed)

    def test_add_is_structural_with_gate(self):
        add4 = [_act("apply_4", "a4", "a4", "participant_4")]
        after = _rebuild(self.base, add=add4)
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(d.severity, STRUCTURAL)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "apply_4")
        self.assertEqual(impact.diff_kind, "added")
        self.assertEqual(impact.severity, STRUCTURAL)
        self.assertTrue(impact.is_gate)
        self.assertEqual(impact.gate, ("participant_4", "apply_4"))

    def test_remove_is_structural(self):
        after = _rebuild(self.base, drop={"apply_3"})
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(d.severity, STRUCTURAL)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "apply_3")
        self.assertEqual(impact.diff_kind, "removed")
        self.assertEqual(impact.severity, STRUCTURAL)
        self.assertEqual(impact.gate, ("participant_3", "apply_3"))

    def test_non_gate_change_is_still_reported(self):
        # "done" is not a gate action, but a change to it is still reported.
        after = _rebuild(self.base, replace={"done": ("done_x", "dn", "dn")})
        d = _diff(self.base, after)
        impacts = changed_gate_actions(d)
        self.assertEqual(len(impacts), 1)
        impact = impacts[0]
        self.assertEqual(impact.action, "done_x")
        self.assertEqual(impact.old_name, "done")
        self.assertFalse(impact.is_gate)
        self.assertIsNone(impact.gate)

# ---------------------------------------------------------------------------
# impacted_witness_steps: which witness steps exercise a changed action
# ---------------------------------------------------------------------------
class TestImpactedWitnessSteps(unittest.TestCase):
    def setUp(self):
        self.base = _two_pc()

    def test_witness_hits_changed_action(self):
        # change apply_1's effect -> witness step at index 3 exercises it
        after = _rebuild(self.base,
                         replace={"apply_1": ("apply_1", "a1", "e2")})
        d = _diff(self.base, after)
        steps = impacted_witness_steps(d, WPATH)
        self.assertEqual(len(steps), 1)
        step = steps[0]
        self.assertEqual(step.step_index, 3)
        self.assertEqual(step.action, "apply_1")
        self.assertEqual(step.owner, "participant_1")
        self.assertEqual(step.severity, SEMANTIC)
        self.assertTrue(step.action_impact.effect_changed)

    def test_rename_matched_via_old_name(self):
        # witness still names the OLD action; the rename must be matched
        after = _rebuild(self.base, replace={"apply_2": ("apply_2x", "a2", "a2")})
        d = _diff(self.base, after)
        steps = impacted_witness_steps(d, WPATH)
        self.assertEqual(len(steps), 1)
        step = steps[0]
        self.assertEqual(step.step_index, 4)
        self.assertEqual(step.action, "apply_2")
        self.assertEqual(step.owner, "participant_2")
        self.assertEqual(step.action_impact.old_name, "apply_2")
        self.assertEqual(step.action_impact.severity, COSMETIC)

    def test_rename_matched_via_new_name(self):
        # witness already names the NEW action; the rename must be matched
        wpath = WPATH[:4] + ["apply_2x"] + WPATH[5:]
        after = _rebuild(self.base, replace={"apply_2": ("apply_2x", "a2", "a2")})
        d = _diff(self.base, after)
        steps = impacted_witness_steps(d, wpath)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].step_index, 4)
        self.assertEqual(steps[0].action, "apply_2x")

    def test_no_overlap_is_empty(self):
        # witness never names apply_2 (old) or apply_2x (new)
        wpath = ["init", "vote_1_yes", "decide", "apply_1", "done"]
        after = _rebuild(self.base, replace={"apply_2": ("apply_2x", "a2", "a2")})
        d = _diff(self.base, after)
        self.assertEqual(impacted_witness_steps(d, wpath), [])

    def test_multiple_changed_actions(self):
        # both apply_1 and apply_2 change; the witness exercises both
        after = _rebuild(self.base, replace={
            "apply_1": ("apply_1", "a1", "e2"),
            "apply_2": ("apply_2", "a2", "e2")})
        d = _diff(self.base, after)
        steps = impacted_witness_steps(d, WPATH)
        self.assertEqual([s.step_index for s in steps], [3, 4])

# ---------------------------------------------------------------------------
# analyze_gate_impact: the combined GateImpact object
# ---------------------------------------------------------------------------
class TestAnalyzeGateImpact(unittest.TestCase):
    def setUp(self):
        self.base = _two_pc()
        self.after = _rebuild(self.base,
                              replace={"apply_2": ("apply_2x", "a2", "a2")})
        self.diff = _diff(self.base, self.after)

    def test_returns_gate_impact(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        self.assertIsInstance(gi, GateImpact)
        self.assertIs(gi.spec_diff, self.diff)
        self.assertEqual(gi.witness_path, WPATH)
        self.assertEqual(len(gi.actions), 1)
        self.assertTrue(gi.impacts_witness)

    def test_names_and_severity(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        self.assertEqual(gi.before_name, "two_pc")
        self.assertEqual(gi.after_name, "two_pc")
        self.assertEqual(gi.overall_severity, COSMETIC)

    def test_changed_gate_actions_subset(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        gates = gi.changed_gate_actions
        self.assertEqual(len(gates), 1)
        self.assertEqual(gates[0].action, "apply_2x")
        self.assertTrue(all(a.is_gate for a in gates))

    def test_impacted_step_indices(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        self.assertEqual(gi.impacted_step_indices, [4])

    def test_action_witness_step_indices_filled(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        self.assertEqual(gi.actions[0].witness_step_indices, [4])
        self.assertTrue(gi.actions[0].impacts_witness)

    def test_to_dict(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        d = gi.to_dict()
        self.assertEqual(d["before"], "two_pc")
        self.assertEqual(d["after"], "two_pc")
        self.assertEqual(d["overall_severity"], COSMETIC)
        self.assertTrue(d["impacts_witness"])
        self.assertEqual(d["impacted_step_indices"], [4])
        self.assertEqual(len(d["changed_actions"]), 1)
        self.assertEqual(len(d["changed_gate_actions"]), 1)
        self.assertEqual(d["witness_path"], WPATH)
        self.assertIsInstance(d["witness_steps"], list)
        self.assertEqual(len(d["impacted_steps"]), 1)

    def test_render(self):
        gi = analyze_gate_impact(self.diff, WPATH)
        text = gi.render()
        self.assertIsInstance(text, str)
        self.assertIn("gate impact", text)
        self.assertIn("two_pc", text)
        self.assertIn("apply_2x", text)

    def test_requires_spec_diff(self):
        with self.assertRaises(ValueError):
            analyze_gate_impact(object(), WPATH)


# ---------------------------------------------------------------------------
# analyze_target_gate_impact: the canonical 2PC correct vs buggy pair
# ---------------------------------------------------------------------------
class TestAnalyzeTargetGateImpact(unittest.TestCase):
    def test_correct_vs_buggy(self):
        # the agreement-breaking change modifies the apply_* effects
        wpath = ["init", "vote_1_yes", "vote_2_yes", "decide",
                 "apply_1", "done"]
        gi = analyze_target_gate_impact("correct", "buggy", wpath, n=3)
        self.assertIsInstance(gi, GateImpact)
        self.assertEqual(gi.overall_severity, SEMANTIC)
        self.assertTrue(gi.impacts_witness)
        names = [a.action for a in gi.actions]
        self.assertIn("apply_1", names)
        # apply_1 is witness step index 4 in this path
        self.assertIn(4, gi.impacted_step_indices)

    def test_unknown_target_raises(self):
        with self.assertRaises(KeyError):
            analyze_target_gate_impact("correct", "no-such-target", [], n=3)


# ---------------------------------------------------------------------------
# ActionImpact / WitnessStepImpact serialization
# ---------------------------------------------------------------------------
class TestSerialization(unittest.TestCase):
    def test_action_impact_to_dict(self):
        a = ActionImpact("apply_1", "modified", SEMANTIC, reason="r",
                         guard_changed=False, effect_changed=True,
                         old_name=None,
                         gate_owner="participant_1", gate_action="apply_1")
        self.assertTrue(a.is_gate)
        self.assertEqual(a.gate, ("participant_1", "apply_1"))
        d = a.to_dict()
        self.assertEqual(d["action"], "apply_1")
        self.assertEqual(d["diff_kind"], "modified")
        self.assertEqual(d["severity"], SEMANTIC)
        self.assertTrue(d["effect_changed"])
        self.assertEqual(d["gate"], {"owner": "participant_1",
                                     "action": "apply_1"})
        self.assertEqual(d["witness_step_indices"], [])
        self.assertFalse(d["impacts_witness"])

    def test_witness_step_impact_to_dict(self):
        a = ActionImpact("apply_1", "modified", SEMANTIC,
                         gate_owner="participant_1", gate_action="apply_1")
        w = WitnessStepImpact(3, "participant_1", "apply_1", a)
        self.assertEqual(w.severity, SEMANTIC)
        d = w.to_dict()
        self.assertEqual(d["step_index"], 3)
        self.assertEqual(d["owner"], "participant_1")
        self.assertEqual(d["action"], "apply_1")
        self.assertEqual(d["severity"], SEMANTIC)
        self.assertEqual(d["diff_kind"], "modified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
