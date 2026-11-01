# -*- coding: utf-8 -*-
"""Phase 3: the robustness ladder (R0 -> R1 -> R2) -- acceptance tests.

Covers the five required cases (spec F1--F4 / T3):

  1. a *safety* claim that holds at every rung (a robust harness) -> [P, P, P];
  2. a *liveness* claim that holds under each rung's fairness
     (``task_ends_or_escalates``) -> [P, P, P];
  3. a layer regression is caught (``no_deadlock`` on the adversarial agent)
     -> [P, V, V], highest discharged rung = R0;
  4. stage-2 (R2) is a superset of stage-1 (R1): R2's actions and reachable
     states are a superset of R1's (the monotone environment, spec F1);
  5. the named non-claims include the compromised-*harness* non-claim (F3).

Plus the F1 monotone-safety law (the discharged rungs form a prefix) and the
F4 refinement chain / implication argument.

Run:  python tests/test_ladder.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
import rotn_research.ladder as ladder
import rotn_research.classify as classify
from rot.emitter import emit_refinement_chain


# A robust harness: the harness ALWAYS enforces the shared budget cap, so the
# no-runaway-budget safety claim holds at every rung (even under a compromised
# agent and benign harness faults). Injected via run_ladder(build_fn=...).
def robust_budget_build_ir(n=1, buggy=False, cap=100, amount=60):
    """A budget harness whose guard enforces the *shared* cap regardless of the
    agent's posture (the harness, not the agent, is the enforcer)."""
    variables = [
        ir.StateVar("spent_a", ir.IntRange(0, cap), ir.MODE_PRECISE, "agent_a",
                    "agent A's cumulative spend"),
        ir.StateVar("spent_b", ir.IntRange(0, cap), ir.MODE_PRECISE, "agent_b",
                    "agent B's cumulative spend"),
    ]
    shared_guard = ir.BinOp(
        "<=",
        ir.BinOp("+", ir.BinOp("+", ir.V("spent_a"), ir.V("spent_b")),
                 ir.C(amount)),
        ir.C(cap))
    actions = [
        ir.Action("init", "system", guard=ir.T(),
                  effects=[ir.Assignment("spent_a", ir.C(0)),
                           ir.Assignment("spent_b", ir.C(0))],
                  is_initial=True, source="test:robust_budget_init"),
        ir.Action("a_spend", "agent_a", guard=shared_guard,
                  effects=[ir.Assignment(
                      "spent_a", ir.BinOp("+", ir.V("spent_a"), ir.C(amount)))],
                  linearization="send(spend_a)",
                  source="test:robust_budget_a_spend"),
        ir.Action("b_spend", "agent_b", guard=shared_guard,
                  effects=[ir.Assignment(
                      "spent_b", ir.BinOp("+", ir.V("spent_b"), ir.C(amount)))],
                  linearization="send(spend_b)",
                  source="test:robust_budget_b_spend"),
    ]
    prop = ir.BinOp("<=", ir.BinOp("+", ir.V("spent_a"), ir.V("spent_b")),
                    ir.C(cap))
    return ir.ProtocolIR(
        name="budget-robust", variables=variables, channels=[], actions=actions,
        init=ir.T(), pinned_property=prop, source_path="",
        metadata={"protocol": "BUDGET", "buggy": bool(buggy), "n": int(n),
                  "cap": cap, "amount": amount,
                  "property_name": "no_runaway_budget",
                  "property_kind": "safety", "adversarial_agent": True},
    )


def _statuses(result):
    """The per-rung verdict statuses as a tuple (R0, R1, R2)."""
    return tuple(result["verdicts"][r]["status"] for r in ladder.rung_names())


class LadderStructureTests(unittest.TestCase):
    """The rung / target / non-claim structure (spec F3, F4)."""

    def test_three_rungs_monotone(self):
        self.assertEqual(ladder.rung_names(), ["R0", "R1", "R2"])
        self.assertEqual([r.level for r in ladder.RUNGS], [0, 1, 2])
        self.assertEqual(ladder.rung_by_name("R2").level, ladder.R2)
        self.assertEqual(ladder.rung_by_level(1).name, "R1")

    def test_six_ladder_targets(self):
        self.assertEqual(
            ladder.ladder_target_names(),
            ["approval", "delegation", "orchestration", "budget",
             "livelock", "deadlock"])

    def test_r2_adds_benign_faults(self):
        self.assertEqual(ladder.rung_by_name("R0").harness_faults, ())
        self.assertEqual(ladder.rung_by_name("R1").harness_faults, ())
        self.assertEqual(
            ladder.rung_by_name("R2").harness_faults,
            ("crash", "retry", "stutter"))
        self.assertEqual(ladder.rung_by_name("R2").buggy, True)
        self.assertEqual(ladder.rung_by_name("R0").buggy, False)

    def test_r2_fairness_covers_faults(self):
        """F2: R2's fairness covers the retry/stutter steps."""
        fair = ladder.rung_by_name("R2").fairness_actions
        self.assertIn("harness_retry", fair)
        self.assertIn("harness_stutter", fair)


class LadderSafetyTests(unittest.TestCase):
    """Cases 1 and 3: safety holds all rungs; a layer regression is caught."""

    def test_safety_holds_all_rungs(self):
        """Case 1: a robust harness -> no_runaway_budget is [P, P, P]."""
        result = ladder.run_ladder(
            target="budget", property_name="no_runaway_budget", n=1,
            max_states=200000, horizon=12, build_fn=robust_budget_build_ir)
        self.assertEqual(_statuses(result), ("proven", "proven", "proven"))
        self.assertEqual(result["highest_discharged_rung"], "R2")
        self.assertEqual(result["kind"], "safety")
        self.assertEqual(result["monotonicity_violations"], [])

    def test_layer_regression_caught(self):
        """Case 3: no_deadlock on the orchestration is [P, V, V] -> R0."""
        result = ladder.run_ladder(
            target="orchestration", property_name="no_deadlock", n=1,
            max_states=200000, horizon=12)
        self.assertEqual(_statuses(result), ("proven", "violated", "violated"))
        self.assertEqual(result["highest_discharged_rung"], "R0")
        self.assertEqual(result["kind"], "safety")
        self.assertEqual(result["monotonicity_violations"], [])
class LadderLivenessTests(unittest.TestCase):
    """Case 2: liveness holds under each rung's fairness."""

    def test_liveness_holds_under_each_rungs_fairness(self):
        """Case 2: task_ends_or_escalates is [P, P, P], each under its rung's
        fairness (F2)."""
        result = ladder.run_ladder(
            target="orchestration", property_name="task_ends_or_escalates",
            n=1, max_states=200000, horizon=12)
        self.assertEqual(_statuses(result), ("proven", "proven", "proven"))
        self.assertEqual(result["kind"], "liveness")
        self.assertEqual(result["highest_discharged_rung"], "R2")
        for rung in ladder.RUNGS:  # F2: each verdict carries its rung's fairness
            v = result["verdicts"][rung.name]
            self.assertIn("fairness", v["evidence"])
            self.assertEqual(v["evidence"]["rung"], rung.name)
            if rung.fairness_actions:
                self.assertTrue(v["fairness_label"])


class LadderSupersetTests(unittest.TestCase):
    """Case 4: stage-2 (R2) is a superset of stage-1 (R1)."""

    def test_stage2_superset_of_stage1_actions(self):
        """R2's actions are a superset of R1's (the fault self-loops added)."""
        build_fn = ladder.build_fn_for("orchestration")
        ir1 = ladder.build_ir_for_rung(build_fn, ladder.rung_by_name("R1"))
        ir2 = ladder.build_ir_for_rung(build_fn, ladder.rung_by_name("R2"))
        names1 = {a.name for a in ir1.actions}
        names2 = {a.name for a in ir2.actions}
        self.assertTrue(names1 <= names2)
        for fault in ladder.FAULT_NAMES:
            self.assertIn("harness_%s" % fault, names2)

    def test_stage2_superset_of_stage1_states(self):
        """R2's reachable states are a superset of R1's (monotone env, F1)."""
        from rot.linearization import linearize
        build_fn = ladder.build_fn_for("orchestration")
        m1 = linearize(ladder.build_ir_for_rung(
            build_fn, ladder.rung_by_name("R1")))
        m2 = linearize(ladder.build_ir_for_rung(
            build_fn, ladder.rung_by_name("R2")))
        r1 = {frozenset(s.items()) for s in m1.reachable()}
        r2 = {frozenset(s.items()) for s in m2.reachable()}
        self.assertTrue(r1 <= r2)


class LadderNonClaimTests(unittest.TestCase):
    """Case 5: the named non-claims include the compromised-harness non-claim."""

    def test_non_claims_include_compromised_harness(self):
        """F3: the compromised-*harness* rung is a named non-claim."""
        joined = " ".join(classify.non_claims()).lower()
        self.assertIn("harness", joined)
        self.assertIn("out of scope", joined)
        self.assertIn("liveness", joined)

    def test_ladder_result_carries_non_claims(self):
        result = ladder.run_ladder(
            target="orchestration", property_name="no_deadlock", n=1,
            max_states=200000, horizon=12)
        self.assertTrue(result["non_claims"])
        self.assertTrue(any("harness" in c.lower() for c in result["non_claims"]))
class LadderMonotonicityTests(unittest.TestCase):
    """F1: the discharged rungs form a prefix (the monotone-safety law)."""

    def test_discharged_set_is_a_prefix(self):
        # [P, P, P] -> prefix {R0, R1, R2}; [P, V, V] -> prefix {R0}.
        self.assertEqual(classify.verify_monotonicity({
            0: _verdict("proven"), 1: _verdict("proven"), 2: _verdict("proven"),
        }), [])
        self.assertEqual(classify.verify_monotonicity({
            0: _verdict("proven"), 1: _verdict("violated"),
            2: _verdict("violated"),
        }), [])
        # An illegal [V, P, P] (violated then discharged) is flagged (F1).
        self.assertTrue(classify.verify_monotonicity({
            0: _verdict("violated"), 1: _verdict("proven"),
            2: _verdict("proven"),
        }))

    def test_highest_discharged_rung(self):
        self.assertEqual(classify.highest_discharged_rung({
            0: _verdict("proven"), 1: _verdict("violated"),
            2: _verdict("violated")}), 0)
        self.assertEqual(classify.highest_discharged_rung({
            0: _verdict("proven"), 1: _verdict("proven"),
            2: _verdict("proven")}), 2)
        self.assertIsNone(classify.highest_discharged_rung({
            0: _verdict("violated"), 1: _verdict("violated"),
            2: _verdict("violated")}))


class LadderRefinementChainTests(unittest.TestCase):
    """F4: the refinement chain is auditable (named layers + implication)."""

    def test_refinement_chain_named_layers(self):
        chain = ladder.refinement_chain(
            ladder.build_fn_for("orchestration"), 1)
        self.assertEqual([c["rung"] for c in chain], ["R0", "R1", "R2"])
        for c in chain:
            self.assertIn("environment", c)
            self.assertIn("ir_name", c)

    def test_implication_argument(self):
        imp = ladder.implication_argument()
        for key in ("monotone_environment", "safety_F1", "liveness_F2",
                    "non_claim_F3"):
            self.assertIn(key, imp)

    def test_emit_refinement_chain(self):
        build_fn = ladder.build_fn_for("orchestration")
        chain = ladder.refinement_chain(build_fn, 1)
        text = emit_refinement_chain(
            chain, implication=ladder.implication_argument(),
            target="orchestration")
        self.assertIn("REFINEMENT CHAIN", text)
        self.assertIn("LAYER R0", text)
        self.assertIn("LAYER R1", text)
        self.assertIn("LAYER R2", text)
        self.assertIn("harness faults", text)
        self.assertIn("WF(harness_retry)", text)


def _verdict(status):
    """A minimal verdict stand-in with the fields classify.py reads."""
    class _V(object):
        def __init__(self, s):
            self.status = s
    return _V(status)


if __name__ == "__main__":
    unittest.main(verbosity=2)