# -*- coding: utf-8 -*-
"""Phase 6 gate: close the TLA+ essentials (joern-primary-ab-plan §2.3).

The four essentials, in priority order, each turned from a silent gap into a
stated, sound, auditable discipline:

  1. **Stuttering assumption** (Phase 6.1) -- the IR carries an explicit
     "no stuttering / every step is an observable action" assumption.  It is
     *stated* on every liveness discharge (bounded and unbounded) and on the
     CEGAR verdict, and rendered in the report -- safety-safe (a stated
     assumption never changes a safety verdict), liveness-honest (a liveness
     claim is never read as holding without the assumption that closes the
     no-stutter gap).

  2. **State constraints (``assume``)** (Phase 6.2) -- first-class
     ``ASSUME`` clauses in the IR.  The concrete symbolic engine *prunes*
     states that do not definitely satisfy them (sound pruning: a promise
     about the environment / a modelling parameter).  An ``assume`` that
     excludes the init state yields an empty state space and a *visible*
     vacuous PROVEN (``n_states=0``), never a silent one.  A verdict decided
     under an assumption carries it as a NAMED assumption.

  3. **Strong / multi-action fairness** (Phase 6.3) -- beyond the pre-Phase-6
     single-action weak ``WF(a)``: strong fairness ``SF(a1)/SF(a2)/...`` and
     multi-action weak ``WF(a1)/WF(a2)/...``.  The formula is *always*
     recorded on the verdict (never silent), the named actions are validated
     against the model (a formula over a non-existent action fails closed),
     and the R2 dual-soundness rule still requires an explicit formula for a
     liveness PROVEN.

  4. **Symmetry sets** (Phase 6.4) -- the concrete symbolic engine quotients
     the state space by interchangeable variable sets (orbit canonical
     representative), exact for group-invariant properties.  The spend-cap
     ``k_sweep`` is the K-scale: it sweeps the in-flight bound and reports the
     K-masking boundary (``K=1`` masks the parallel-fire race; ``K>=2``
     exposes it) with a loud advisory, never silent.

Pure stdlib, offline, Python 3.6 compatible.

Run: python -m pytest tests/test_phase6_tla.py -v
"""

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import rot.ir as ir                                    # noqa: E402
import pipeline                                        # noqa: E402
import rot.spendcap as sc                              # noqa: E402
import rot.twopc as tw                                 # noqa: E402
from rot.config import Config                          # noqa: E402
from rot.invariants import Invariant                   # noqa: E402
from rot.linearization import linearize                # noqa: E402
from rot.liveness import (discharge_liveness,          # noqa: E402
                          fairness_formula_for)
from rot.symbolic import (SymbolicEngine,              # noqa: E402
                          _canonicalize, _validate_symmetry)
from rot.verdicts import (PROVEN, VIOLATED, UNKNOWN,   # noqa: E402
                          Verdict, k_masking_advisory)


# ============================================================================
# 1. Stuttering assumption (Phase 6.1)
# ============================================================================
class StutteringAssumptionTests(unittest.TestCase):
    def test_ir_default_stuttering_assumption(self):
        m = sc.build_ir(buggy=True, max_inflight=2)
        self.assertTrue(m.stuttering_assumption)
        self.assertEqual(m.stuttering_assumption, ir.STUTTERING_ASSUMPTION)

    def test_ir_custom_stuttering_roundtrip(self):
        custom = "every step is a labelled action; no stutter"
        m = sc.build_ir(buggy=True, max_inflight=2)
        m.stuttering_assumption = custom
        d = ir.ProtocolIR.from_dict(m.to_dict())
        self.assertEqual(d.stuttering_assumption, custom)

    def test_linear_model_carries_stuttering(self):
        m = sc.build_ir(buggy=True, max_inflight=2)
        lm = linearize(m)
        self.assertEqual(lm.stuttering_assumption,
                         ir.STUTTERING_ASSUMPTION)

    def test_liveness_bounded_verdict_carries_stuttering(self):
        goal = ir.BinOp("=", ir.V("completed"), ir.C(100))
        prop = Invariant(name="g", description="d", expression=goal,
                         kind="liveness")
        lm = linearize(sc.build_ir(buggy=False, max_inflight=4))
        cfg = Config(engine="symbolic", liveness_horizon=10)
        v = discharge_liveness(lm, goal, prop, cfg)
        self.assertEqual(v.status, PROVEN)
        self.assertTrue(v.stuttering_assumption)
        self.assertIn("stutter", v.stuttering_assumption.lower())

    def test_verdict_markdown_renders_stuttering(self):
        v = Verdict.proven("p", "symbolic",
                           stuttering_assumption=ir.STUTTERING_ASSUMPTION)
        md = v.to_markdown()
        self.assertIn("Stuttering assumption", md)
        self.assertIn("no stuttering", md.lower())

    def test_cegar_verdict_carries_stuttering(self):
        for _k, v in sc.k_sweep(buggy=True, k_values=(1, 2)):
            self.assertTrue(v.stuttering_assumption)


# ============================================================================
# 2. State constraints (assume) (Phase 6.2)
# ============================================================================
class AssumeNodeTests(unittest.TestCase):
    def test_assume_eval_true_and_undef_never_false(self):
        a = ir.Assume(ir.BinOp("<=", ir.V("inflight"), ir.C(1)))
        self.assertTrue(a.eval({"inflight": 1}))
        self.assertTrue(a.eval({"inflight": 0}))
        # A state where the var is absent -> UNDEF (never False).
        self.assertIs(a.eval({}), ir.Expr.UNDEF)

    def test_assume_serialization_roundtrip(self):
        a = ir.Assume(ir.BinOp("<=", ir.V("inflight"), ir.C(1)),
                      note="bound")
        d = a.to_dict()
        self.assertEqual(d["tag"], "assume")
        self.assertEqual(d["note"], "bound")
        back = ir.Expr.from_dict(d)
        self.assertIsInstance(back, ir.Assume)
        self.assertTrue(back.eval({"inflight": 1}))
        self.assertEqual(back.note, "bound")

    def test_build_ir_normalizes_raw_exprs_to_assume(self):
        raw = ir.BinOp("<=", ir.V("inflight"), ir.C(2))
        m = sc.build_ir(buggy=True, max_inflight=4, assumes=[raw])
        self.assertEqual(len(m.assumes), 1)
        self.assertIsInstance(m.assumes[0], ir.Assume)

    def test_build_ir_default_no_assumes(self):
        m = sc.build_ir(buggy=True, max_inflight=4)
        self.assertEqual(list(m.assumes or []), [])

    def test_linear_model_assumes_passthrough(self):
        m = sc.build_ir(buggy=True, max_inflight=4,
                        assumes=[sc.assume_inflight_at_most(1)])
        lm = linearize(m)
        self.assertEqual(len(lm.assumes), 1)


class AssumePruningTests(unittest.TestCase):
    def test_pruning_reduces_state_space(self):
        base = linearize(sc.build_ir(buggy=True, max_inflight=4))
        n_base = len(SymbolicEngine(base).reachable()[0])

        pruned = linearize(sc.build_ir(buggy=True, max_inflight=4,
                                       assumes=[
                                           sc.assume_inflight_at_most(1)]))
        eng = SymbolicEngine(pruned)
        states, complete = eng.reachable()
        self.assertTrue(complete)
        self.assertLess(len(states), n_base)
        self.assertGreater(eng.assume_pruned, 0)

    def test_pruned_count_is_loud(self):
        lm = linearize(sc.build_ir(buggy=True, max_inflight=4,
                                   assumes=[sc.assume_inflight_at_most(1)]))
        eng = SymbolicEngine(lm)
        eng.reachable()
        self.assertGreater(eng.assume_pruned, 0)

    def test_init_excluded_gives_visible_vacuous_proven(self):
        # assume(inflight < 0) excludes the init state -> empty state space.
        m = sc.build_ir(buggy=True, max_inflight=4,
                        assumes=[ir.BinOp("<", ir.V("inflight"), ir.C(0))])
        lm = linearize(m)
        eng = SymbolicEngine(lm)
        states, complete = eng.reachable()
        self.assertEqual(states, [])
        self.assertTrue(complete)
        res = eng.check(ir.T())
        self.assertEqual(res.status, PROVEN)
        self.assertEqual(res.n_states, 0)  # vacuity is visible, not silent

    def test_assume_inflight_at_most_eval(self):
        a = sc.assume_inflight_at_most(1)
        self.assertIsInstance(a, ir.Assume)
        self.assertTrue(a.expr.eval({"inflight": 1}))
        self.assertFalse(a.expr.eval({"inflight": 5}))

    def test_assume_inflight_at_most_rejects_low(self):
        with self.assertRaises(ValueError):
            sc.assume_inflight_at_most(0)

    def test_pipeline_records_named_assumption(self):
        v = Verdict.proven("p", "symbolic", n_states=3)
        ir_model = sc.build_ir(buggy=True, max_inflight=4,
                               assumes=[sc.assume_inflight_at_most(1)])
        pipeline._record_ir_assumptions(v, ir_model)
        self.assertEqual(len(v.assumptions), 1)
        self.assertIn("inflight <= 1", v.assumptions[0])
        self.assertIn("assume:", v.assumptions[0])

    def test_pipeline_no_assumes_is_noop(self):
        v = Verdict.proven("p", "symbolic", n_states=3)
        pipeline._record_ir_assumptions(v, sc.build_ir(buggy=True))
        self.assertEqual(list(v.assumptions or []), [])

    def test_verdict_markdown_records_assumption(self):
        v = Verdict.proven("p", "symbolic", assumptions=["assume: x <= 1"])
        self.assertIn("Recorded assumptions", v.to_markdown())
        self.assertIn("assume: x <= 1", v.to_markdown())


# ============================================================================
# 3. Strong / multi-action fairness (Phase 6.3)
# ============================================================================
class FairnessConfigTests(unittest.TestCase):
    def test_config_fields_roundtrip(self):
        cfg = Config(strong_fairness_actions=["Decide"],
                     weak_fairness_actions=["A", "B"])
        d = cfg.to_dict()
        self.assertEqual(d["strong_fairness_actions"], ["Decide"])
        self.assertEqual(d["weak_fairness_actions"], ["A", "B"])
        back = Config.from_dict(d)
        self.assertEqual(back.strong_fairness_actions, ["Decide"])
        self.assertEqual(back.weak_fairness_actions, ["A", "B"])

    def test_formula_strong(self):
        cfg = Config(strong_fairness_actions=["Decide", "Respond"])
        mode, actions, formula = fairness_formula_for(cfg)
        self.assertEqual(mode, "strong")
        self.assertEqual(actions, ["Decide", "Respond"])
        self.assertIn("SF(Decide)", formula)
        self.assertIn("SF(Respond)", formula)

    def test_formula_multi_weak(self):
        cfg = Config(weak_fairness_actions=["A", "B"])
        mode, actions, formula = fairness_formula_for(cfg)
        self.assertEqual(mode, "weak")
        self.assertEqual(actions, ["A", "B"])
        self.assertIn("WF(A)", formula)
        self.assertIn("WF(B)", formula)

    def test_formula_single_weak_default(self):
        cfg = Config()
        mode, actions, formula = fairness_formula_for(cfg)
        self.assertEqual(mode, "weak")
        self.assertEqual(len(actions), 1)
        self.assertTrue(formula.startswith("WF("))

    def test_formula_strong_wins_over_weak(self):
        cfg = Config(strong_fairness_actions=["S"],
                     weak_fairness_actions=["A", "B"])
        mode, _a, formula = fairness_formula_for(cfg)
        self.assertEqual(mode, "strong")
        self.assertIn("SF(S)", formula)


class FairnessDischargeTests(unittest.TestCase):
    def _model_prop(self):
        goal = ir.BinOp("=", ir.V("completed"), ir.C(100))
        prop = Invariant(name="g", description="d", expression=goal,
                         kind="liveness")
        lm = linearize(sc.build_ir(buggy=False, max_inflight=4))
        return lm, goal, prop

    def test_unbounded_records_formula_and_fails_closed(self):
        lm, goal, prop = self._model_prop()
        cfg = Config(engine="symbolic", unbounded_liveness=True,
                     strong_fairness_actions=["respond"])
        v = discharge_liveness(lm, goal, prop, cfg)
        # No concrete fairness-aware engine -> fail closed (not PROVEN).
        self.assertEqual(v.status, UNKNOWN)
        self.assertEqual(v.discharge, "fairness")
        self.assertIn("SF(respond)", v.fairness_label)

    def test_unbounded_nonexistent_action_fails_closed_named(self):
        lm, goal, prop = self._model_prop()
        cfg = Config(engine="symbolic", unbounded_liveness=True,
                     strong_fairness_actions=["ghost"])
        v = discharge_liveness(lm, goal, prop, cfg)
        self.assertEqual(v.status, UNKNOWN)
        self.assertIn("SF(ghost)", v.fairness_label)
        # The non-existent action is named, never silently recorded.
        self.assertIn("ghost", v.note)

    def test_unbounded_multi_weak_records_formula(self):
        lm, goal, prop = self._model_prop()
        cfg = Config(engine="symbolic", unbounded_liveness=True,
                     weak_fairness_actions=["spend_ok", "respond"])
        v = discharge_liveness(lm, goal, prop, cfg)
        self.assertEqual(v.status, UNKNOWN)
        self.assertIn("WF(spend_ok)", v.fairness_label)
        self.assertIn("WF(respond)", v.fairness_label)


# ============================================================================
# 4. Symmetry sets + K-scale (Phase 6.4)
# ============================================================================
class SymmetryCanonicalizeTests(unittest.TestCase):
    SETS = [("x1", "x2")]

    def test_same_orbit_same_rep(self):
        a = _canonicalize({"x1": 0, "x2": 1, "c": 5}, self.SETS)
        b = _canonicalize({"x1": 1, "x2": 0, "c": 5}, self.SETS)
        self.assertEqual(a, b)

    def test_distinct_orbits_differ(self):
        a = _canonicalize({"x1": 0, "x2": 1, "c": 5}, self.SETS)
        c = _canonicalize({"x1": 1, "x2": 1, "c": 5}, self.SETS)
        self.assertNotEqual(a, c)

    def test_non_symmetric_var_untouched(self):
        a = _canonicalize({"x1": 0, "x2": 1, "c": 5}, self.SETS)
        self.assertEqual(a["c"], 5)


class SymmetryValidationTests(unittest.TestCase):
    def _model(self):
        return linearize(sc.build_ir(buggy=False, max_inflight=3))

    def test_single_var_set_rejected(self):
        with self.assertRaises(ValueError):
            _validate_symmetry([["completed"]], self._model())

    def test_undeclared_var_rejected(self):
        with self.assertRaises(ValueError):
            _validate_symmetry([["completed", "inflight", "nope"]],
                               self._model())

    def test_valid_sets_accepted(self):
        # A set over two real vars is structurally valid; the soundness
        # preconditions (action closure + property invariance) are the
        # caller's responsibility, documented in _validate_symmetry.
        sets = _validate_symmetry([["completed", "inflight"]],
                                  self._model())
        self.assertEqual(len(sets), 1)


class SymmetryQuotientTests(unittest.TestCase):
    def test_twopc_state_reduction(self):
        m = linearize(tw.build_ir(n=3, buggy=False))
        full = SymbolicEngine(m).reachable()[0]
        sets = [["vote_1", "vote_2", "vote_3"],
                ["applied_1", "applied_2", "applied_3"]]
        eng = SymbolicEngine(m, symmetry=sets)
        quotient, complete = eng.reachable()
        self.assertTrue(complete)
        self.assertLess(len(quotient), len(full))

    def test_verdict_invariant_under_quotient(self):
        m = linearize(tw.build_ir(n=3, buggy=False))
        prop = Invariant(name="agreement", description="d",
                         expression=tw.agreement_property(3))
        full = SymbolicEngine(m).check(prop.expression)
        sets = [["vote_1", "vote_2", "vote_3"],
                ["applied_1", "applied_2", "applied_3"]]
        quot = SymbolicEngine(m, symmetry=sets).check(prop.expression)
        self.assertEqual(full.status, quot.status)
        self.assertEqual(full.status, PROVEN)


class KSweepTests(unittest.TestCase):
    def test_buggy_k1_proven_with_loud_masking(self):
        rows = dict(sc.k_sweep(buggy=True, k_values=(1,)))
        v = rows[1]
        self.assertEqual(v.status, PROVEN)
        km = v.evidence.get("k_masking")
        self.assertEqual(km["code"], "MASKED_AT_LOW_K")
        self.assertIn("K=1", km["message"])

    def test_buggy_k_ge_2_violated(self):
        for _k, v in sc.k_sweep(buggy=True, k_values=(2, 3)):
            self.assertEqual(v.status, VIOLATED)
            self.assertNotIn("k_masking", v.evidence)

    def test_correct_policy_proven_at_all_k(self):
        for _k, v in sc.k_sweep(buggy=False, k_values=(1, 2, 3)):
            self.assertEqual(v.status, PROVEN)
            self.assertNotIn("k_masking", v.evidence)

    def test_k_sweep_records_k_and_named_assumption(self):
        for k, v in sc.k_sweep(buggy=True, k_values=(1, 2)):
            self.assertEqual(v.evidence["k"], k)
            self.assertTrue(any("K=%d" % k in a for a in (v.assumptions or [])))

    def test_k_masking_advisory_direct(self):
        meta = {"amount": 100, "cap": 200, "max_inflight": 1, "buggy": True,
                "protocol": "SPENDCAP"}
        code, _msg = k_masking_advisory(meta, "proven")
        self.assertEqual(code, "MASKED_AT_LOW_K")
        # At/above the minimal overshoot count the advisory does not fire.
        meta2 = dict(meta, max_inflight=2)
        self.assertIsNone(k_masking_advisory(meta2, "proven")[0])
        # A non-proven verdict never fires the advisory.
        self.assertIsNone(k_masking_advisory(meta, "violated")[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)


