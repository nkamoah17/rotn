# -*- coding: utf-8 -*-
"""Enforcement tests for the liveness discharge (spec R2 / R3 / R4 + cross-engine).

These are the "teeth" of Phase 2: they drive the enforcement rules directly so
they cannot be silently bypassed.  Each test asserts a concrete, falsifiable
property:

* R2 (dual-soundness): a liveness PROVEN is sound only under bounded+concrete+
  complete, or fairness+label.  An unsound PROVEN is downgraded to UNKNOWN.
* R3 (no vacuity): a goal that already holds in init is rejected (vacuous); a
  goal reachable even on the buggy (livelock) harness is rejected (the checker
  must be able to fail -- the negative control).
* R4 (no spurious liveness): a tautological / trivially-true goal is rejected.
* Cross-engine agreement: symbolic + TLC agree on the bounded claim.
* Unbounded liveness: the fairness label is ALWAYS recorded (never silent) and
  the path fails closed to UNKNOWN (never an unsound PROVEN).

Pure stdlib, Python 3.6 compatible (no f-strings, no capture_output).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
import rot.liveness as L
from rot.approval import (livelock_build_ir,
                          task_ends_or_escalates_property as goal)
from rot.config import Config
from rot.invariants import Invariant
from rot.linearization import linearize
from rot.verdicts import Verdict

HORIZON = 8


def _model(buggy=False):
    return linearize(livelock_build_ir(buggy=buggy))


def _prop():
    g = goal()
    return Invariant(name="task_ends_or_escalates",
                     description="the task ends or escalates",
                     expression=g, kind="liveness")


def _cfg(**kw):
    base = dict(liveness_horizon=HORIZON, tlc_timeout=30)
    base.update(kw)
    return Config(**base)


# A tautological goal: holds in every state (including init) -- vacuous.
TAUT = ir.Or(ir.V("a_turn"), ir.Not(ir.V("a_turn")))


class R2SoundnessRuleTests(unittest.TestCase):
    """Spec R2: the dual-soundness rule, driven directly."""

    def test_bounded_concrete_complete_no_fairness_is_sound(self):
        self.assertTrue(L.r2_soundness_ok(L.DISCHARGE_BOUNDED, True, True, None))

    def test_bounded_incomplete_horizon_is_not_sound(self):
        self.assertFalse(L.r2_soundness_ok(L.DISCHARGE_BOUNDED, True, False,
                                           None))

    def test_bounded_non_concrete_engine_is_not_sound(self):
        self.assertFalse(L.r2_soundness_ok(L.DISCHARGE_BOUNDED, False, True,
                                           None))

    def test_fairness_with_label_is_sound(self):
        self.assertTrue(L.r2_soundness_ok(L.DISCHARGE_FAIRNESS, False, False,
                                         "WF(Decide)"))

    def test_fairness_without_label_is_not_sound(self):
        self.assertFalse(L.r2_soundness_ok(L.DISCHARGE_FAIRNESS, False, False,
                                           None))

    def test_unknown_discharge_path_is_not_sound(self):
        self.assertFalse(L.r2_soundness_ok("weird", True, True, None))

    def test_enforce_downgrades_unsound_proven_to_unknown(self):
        v = Verdict.proven("p", "symbolic", n_states=5,
                           property_kind="liveness", discharge="bounded")
        out = L._enforce_r2(v, L.DISCHARGE_BOUNDED, concrete=True,
                            horizon_complete=False, fairness_label=None)
        self.assertEqual(out.status, "unknown")
        self.assertIn("R2", out.note)

    def test_enforce_keeps_sound_bounded_proven(self):
        v = Verdict.proven("p", "symbolic", n_states=5,
                           property_kind="liveness", discharge="bounded")
        out = L._enforce_r2(v, L.DISCHARGE_BOUNDED, concrete=True,
                            horizon_complete=True, fairness_label=None)
        self.assertEqual(out.status, "proven")

    def test_enforce_downgrades_fairness_proven_without_label(self):
        v = Verdict.proven("p", "apalache", n_states=5,
                           property_kind="liveness", discharge="fairness")
        out = L._enforce_r2(v, L.DISCHARGE_FAIRNESS, concrete=False,
                            horizon_complete=False, fairness_label=None)
        self.assertEqual(out.status, "unknown")
        self.assertIn("R2", out.note)

    def test_enforce_keeps_fairness_proven_with_label(self):
        v = Verdict.proven("p", "apalache", n_states=5,
                           property_kind="liveness", discharge="fairness",
                           fairness_label="WF(Decide)")
        out = L._enforce_r2(v, L.DISCHARGE_FAIRNESS, concrete=False,
                            horizon_complete=False, fairness_label="WF(Decide)")
        self.assertEqual(out.status, "proven")
        self.assertEqual(out.fairness_label, "WF(Decide)")


class R3NoVacuityTests(unittest.TestCase):
    """Spec R3: the goal must not be vacuous, and the checker must be able to fail."""

    def test_goal_not_in_init_is_non_vacuous(self):
        ok, reason = L.r3_goal_not_vacuous(_model(False), goal())
        self.assertTrue(ok, reason)

    def test_goal_in_init_is_vacuous(self):
        ok, reason = L.r3_goal_not_vacuous(_model(False), TAUT)
        self.assertFalse(ok)
        self.assertIn("vacuous", reason.lower())

    def test_negative_control_passes_on_buggy_model(self):
        # The checker must be able to FAIL: the (valid) goal is NOT reachable on
        # the buggy (livelock) harness.
        ok, reason = L.r3_negative_control(_model(True), goal(), HORIZON, 200000)
        self.assertTrue(ok, reason)

    def test_negative_control_fails_when_goal_reachable_on_buggy(self):
        # A goal that IS reachable on the buggy harness is spurious liveness:
        # the checker is not discriminating.
        ok, reason = L.r3_negative_control(_model(True), TAUT, HORIZON, 200000)
        self.assertFalse(ok)
        self.assertIn("FAILED", reason)


class R4NoSpuriousLivenessTests(unittest.TestCase):
    """Spec R4: the goal must be a decided outcome, not a tautology."""

    def test_tautology_goal_rejected(self):
        ok, reason = L.r4_goal_is_decided_outcome(_model(False), TAUT)
        self.assertFalse(ok)

    def test_valid_goal_accepted(self):
        ok, reason = L.r4_goal_is_decided_outcome(_model(False), goal())
        self.assertTrue(ok, reason)


class CrossEngineAgreementTests(unittest.TestCase):
    """Spec: cross-engine agreement on the bounded liveness claim."""

    def test_correct_model_proven(self):
        v = L.discharge_liveness(_model(False), goal(), _prop(), _cfg(),
                                 target="livelock-correct")
        self.assertEqual(v.status, "proven")
        self.assertEqual(v.discharge, L.DISCHARGE_BOUNDED)
        self.assertTrue(v.evidence.get("agreement"))
        if v.evidence["crosscheck"]["status"] != "unknown":
            self.assertEqual(v.evidence["crosscheck"]["status"], "reached")

    def test_buggy_model_violated(self):
        v = L.discharge_liveness(_model(True), goal(), _prop(), _cfg(),
                                 target="livelock-buggy")
        self.assertEqual(v.status, "violated")
        self.assertEqual(v.discharge, L.DISCHARGE_BOUNDED)
        self.assertTrue(v.evidence.get("agreement"))
        if v.evidence["crosscheck"]["status"] != "unknown":
            self.assertEqual(v.evidence["crosscheck"]["status"], "not_reached")

    def test_vacuous_goal_rejected_end_to_end(self):
        prop = Invariant(name="vac", description="tautology", expression=TAUT,
                         kind="liveness")
        v = L.discharge_liveness(_model(False), TAUT, prop, _cfg(), target="vac")
        self.assertEqual(v.status, "unknown")
        self.assertNotEqual(v.status, "proven")


class UnboundedLivenessTests(unittest.TestCase):
    """Spec R2/D1/D2: unbounded liveness records the fairness label, fails closed."""

    def test_fairness_label_recorded_never_silent(self):
        v = L.discharge_liveness(_model(False), goal(), _prop(),
                                 _cfg(unbounded_liveness=True,
                                     fairness_action="Decide"),
                                 target="unbounded")
        self.assertEqual(v.fairness_label, "WF(Decide)")
        self.assertEqual(v.discharge, L.DISCHARGE_FAIRNESS)

    def test_fairness_label_custom_action(self):
        v = L.discharge_liveness(_model(False), goal(), _prop(),
                                 _cfg(unbounded_liveness=True,
                                     fairness_action="b_complete"),
                                 target="unbounded")
        self.assertEqual(v.fairness_label, "WF(b_complete)")

    def test_unbounded_fails_closed_not_unsound_proven(self):
        v = L.discharge_liveness(_model(False), goal(), _prop(),
                                 _cfg(unbounded_liveness=True), target="unbounded")
        self.assertEqual(v.status, "unknown")
        self.assertNotEqual(v.status, "proven")


class FairnessLabelHelperTests(unittest.TestCase):
    """The fairness label is always explicit (harness action, WF(action))."""

    def test_default_action(self):
        cfg = type("C", (), {"fairness_action": None})()
        self.assertEqual(L.fairness_label_for(cfg), "WF(Decide)")

    def test_explicit_action(self):
        cfg = type("C", (), {"fairness_action": "b_complete"})()
        self.assertEqual(L.fairness_label_for(cfg), "WF(b_complete)")


class EmitterFairnessAssumptionTests(unittest.TestCase):
    """Spec D2: the emitter emits a named WF(action) assumption -- never silently dropped."""

    def _emitter(self):
        from rot.emitter import Emitter

        class M(object):
            var_names = ["a_turn", "done"]
            actions = []
            variables = []

        return Emitter(M())

    def test_wf_assumption_emitted_when_supplied(self):
        e = self._emitter()
        cfg = e.cfg_spec(["TypeInv"], ["NoDeadlock"], assumptions=["Decide"])
        self.assertIn("ASSUME WF(Decide)", cfg)

    def test_no_assumption_when_not_supplied(self):
        e = self._emitter()
        cfg = e.cfg_spec(["TypeInv"], ["NoDeadlock"])
        self.assertNotIn("ASSUME", cfg)

    def test_multiple_assumptions(self):
        e = self._emitter()
        cfg = e.cfg_spec([], [], assumptions=["Decide", "b_complete"])
        self.assertIn("ASSUME WF(Decide)", cfg)
        self.assertIn("ASSUME WF(b_complete)", cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)