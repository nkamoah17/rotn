# -*- coding: utf-8 -*-
"""End-to-end checks for the G4 approval / delegation / multi-agent model
(:mod:`rot.approval`): the four governance sub-models (approval, delegation,
orchestration, budget), each with a correct and a buggy variant that share
state and actions and differ only in a seeded governance decision.

Covers:

* the property expressions (``NoUnapprovedIrreversible``,
  ``NoPrivilegeEscalation``, ``NoDeadlock``, ``TaskEndsOrEscalates``,
  ``NoRunawayBudget``);
* correct/buggy hold/violate semantics via the model finder, including the
  concrete counterexample witnesses (the governance bypasses);
* the attack/deadlock path reconstruction (``path_to``);
* registry + MR-gate wiring (the buggy variant is BLOCK, the correct variant
  is PASS);
* the liveness rule ``TaskEndsOrEscalates`` through the pipeline's bounded
  reachability (``reach_within``) oracle.

Run:  python tests/test_approval.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.approval as approval
import rot.targets as targets
from rot.invariants import get as inv_get
from rot.modelfind import ModelFinder
from rot.mr_gate import PASS, BLOCK, evaluate_mr


def _holds_all_reachable(prop, model):
    mf = ModelFinder.from_ir(model)
    status, witness = mf.forall_reachable(lambda s: prop.eval(s))
    if status is True:
        return True, None
    if status is False:
        return False, witness
    raise AssertionError("model finder returned %r" % (status,))


def _violation(prop, model):
    mf = ModelFinder.from_ir(model)
    status, witness = mf.exists_reachable(lambda s: (not prop.eval(s)))
    if status == "SAT":
        return True, witness
    return False, None


# ---------------------------------------------------------------------------
# 1. Property expressions
# ---------------------------------------------------------------------------

class ApprovalPropertyTests(unittest.TestCase):
    def test_no_unapproved_irreversible(self):
        prop = approval.no_unapproved_irreversible_property()
        # executed without approval -> violation
        self.assertFalse(prop.eval({"phase": "executed", "approved_once": False}))
        # executed after approval -> holds
        self.assertTrue(prop.eval({"phase": "executed", "approved_once": True}))
        # not executed -> holds (vacuously)
        self.assertTrue(prop.eval({"phase": "pending", "approved_once": False}))

    def test_no_privilege_escalation(self):
        prop = approval.no_privilege_escalation_property()
        # delegatee executes a permission the delegator never held -> violation
        self.assertFalse(prop.eval({"delegator_perm": False,
                                    "token": True, "executed": True}))
        # delegatee executes a permission the delegator held -> holds
        self.assertTrue(prop.eval({"delegator_perm": True,
                                   "token": True, "executed": True}))
        # not executed -> holds
        self.assertTrue(prop.eval({"delegator_perm": False,
                                   "token": False, "executed": False}))

    def test_no_deadlock(self):
        prop = approval.no_deadlock_property()
        # circular wait (all agents blocked, task pending) -> violation
        self.assertFalse(prop.eval({
            "task_pending": True, "a_waiting": True, "b_waiting": True,
            "approver_waiting": True}))
        # one agent not blocked -> holds
        self.assertTrue(prop.eval({
            "task_pending": True, "a_waiting": True, "b_waiting": True,
            "approver_waiting": False}))

    def test_task_ends_or_escalates_goal(self):
        prop = approval.task_ends_or_escalates_property()
        # done -> goal met
        self.assertTrue(prop.eval({"done": True, "escalated": False}))
        # escalated -> goal met
        self.assertTrue(prop.eval({"done": False, "escalated": True}))
        # neither -> goal not met (yet)
        self.assertFalse(prop.eval({"done": False, "escalated": False}))

    def test_no_runaway_budget(self):
        prop = approval.no_runaway_budget_property(cap=100)
        # total within cap -> holds
        self.assertTrue(prop.eval({"spent_a": 40, "spent_b": 60}))
        # total past cap -> violation
        self.assertFalse(prop.eval({"spent_a": 60, "spent_b": 60}))


# ---------------------------------------------------------------------------
# 2. Well-formed IR
# ---------------------------------------------------------------------------

class ApprovalIrWellFormedTests(unittest.TestCase):
    def test_approval_ir(self):
        for buggy in (False, True):
            model = approval.approval_build_ir(buggy=buggy)
            self.assertEqual(len(model.variables), 2)
            # init + agent_request + approver_approve + approver_deny +
            # agent_execute = 5 actions.
            self.assertEqual(len(model.actions), 5)
            self.assertTrue(model.metadata["adversarial_agent"])
            self.assertEqual(model.metadata["protocol"], "APPROVAL")

    def test_delegation_ir(self):
        for buggy in (False, True):
            model = approval.delegation_build_ir(buggy=buggy)
            self.assertEqual(len(model.variables), 3)
            # init + grant_delegator_perm + delegator_delegate +
            # delegatee_execute = 4 actions.
            self.assertEqual(len(model.actions), 4)
            self.assertTrue(model.metadata["adversarial_agent"])
            self.assertEqual(model.metadata["protocol"], "DELEGATION")

    def test_orchestration_ir(self):
        for buggy in (False, True):
            model = approval.orchestration_build_ir(buggy=buggy)
            self.assertEqual(len(model.variables), 8)
            # init + a_request_b + b_request_approver + approver_decide +
            # b_complete + a_complete + escalate + approver_request_a = 8.
            self.assertEqual(len(model.actions), 8)
            self.assertTrue(model.metadata["adversarial_agent"])
            self.assertEqual(model.metadata["protocol"], "ORCHESTRATION")

    def test_budget_ir(self):
        for buggy in (False, True):
            model = approval.budget_build_ir(buggy=buggy)
            self.assertEqual(len(model.variables), 2)
            # init + a_spend + b_spend = 3 actions.
            self.assertEqual(len(model.actions), 3)
            self.assertTrue(model.metadata["adversarial_agent"])
            self.assertEqual(model.metadata["protocol"], "BUDGET")


# ---------------------------------------------------------------------------
# 3. Correct holds / buggy violates (the thesis discriminators)
# ---------------------------------------------------------------------------

class ApprovalSemanticsTests(unittest.TestCase):
    def test_approval_correct_holds(self):
        prop = approval.no_unapproved_irreversible_property()
        ok, w = _holds_all_reachable(prop, approval.approval_build_ir(buggy=False))
        self.assertTrue(ok, "correct harness should hold, got %r" % (w,))

    def test_approval_buggy_violates(self):
        prop = approval.no_unapproved_irreversible_property()
        has, w = _violation(prop, approval.approval_build_ir(buggy=True))
        self.assertTrue(has, "buggy harness should violate")
        self.assertEqual(w["phase"], "executed")
        self.assertFalse(w["approved_once"])

    def test_delegation_correct_holds(self):
        prop = approval.no_privilege_escalation_property()
        ok, w = _holds_all_reachable(prop, approval.delegation_build_ir(buggy=False))
        self.assertTrue(ok, "correct harness should hold, got %r" % (w,))

    def test_delegation_buggy_violates(self):
        prop = approval.no_privilege_escalation_property()
        has, w = _violation(prop, approval.delegation_build_ir(buggy=True))
        self.assertTrue(has, "buggy harness should violate")
        self.assertFalse(w["delegator_perm"])
        self.assertTrue(w["executed"])

    def test_orchestration_correct_holds_no_deadlock(self):
        prop = approval.no_deadlock_property()
        ok, w = _holds_all_reachable(
            prop, approval.orchestration_build_ir(buggy=False))
        self.assertTrue(ok, "correct should be deadlock-free, got %r" % (w,))

    def test_orchestration_buggy_deadlock(self):
        prop = approval.no_deadlock_property()
        has, w = _violation(prop, approval.orchestration_build_ir(buggy=True))
        self.assertTrue(has, "buggy orchestration should deadlock")
        # the circular-wait state: every agent blocked on another, task pending.
        self.assertTrue(w["task_pending"])
        self.assertTrue(w["a_waiting"])
        self.assertTrue(w["b_waiting"])
        self.assertTrue(w["approver_waiting"])

    def test_budget_correct_holds(self):
        prop = approval.no_runaway_budget_property()
        ok, w = _holds_all_reachable(prop, approval.budget_build_ir(buggy=False))
        self.assertTrue(ok, "correct harness should hold the cap, got %r" % (w,))

    def test_budget_buggy_violates(self):
        prop = approval.no_runaway_budget_property()
        has, w = _violation(prop, approval.budget_build_ir(buggy=True))
        self.assertTrue(has, "buggy harness should run past the cap")
        self.assertGreater(w["spent_a"] + w["spent_b"], approval.CAP)
# ---------------------------------------------------------------------------
# 4. Attack / deadlock path reconstruction
# ---------------------------------------------------------------------------

class ApprovalPathTests(unittest.TestCase):
    def test_approval_bypass_path(self):
        model = approval.approval_build_ir(buggy=True)
        mf = ModelFinder.from_ir(model)
        witness = {"phase": "executed", "approved_once": False}
        # the witness is exactly the unapproved-execution state (broken rule).
        self.assertFalse(
            approval.no_unapproved_irreversible_property().eval(witness))
        path = mf.path_to(witness)
        self.assertTrue(path)
        # the bypass: the irreversible action executes with no approval in the
        # path (the buggy harness enables execute from any non-executed phase,
        # so it can even skip the request).  The invariant is broken exactly
        # because execute is present while approve is absent.
        names = [step[1].name for step in path]
        self.assertIn("agent_execute", names)
        self.assertNotIn("approver_approve", names)

    def test_deadlock_path(self):
        model = approval.orchestration_build_ir(buggy=True)
        mf = ModelFinder.from_ir(model)
        witness = {"task_pending": True, "a_waiting": True, "b_waiting": True,
                   "approver_waiting": True, "b_approved": False, "b_done": False,
                   "done": False, "escalated": False}
        path = mf.path_to(witness)
        self.assertTrue(path)
        # the cycle closes: A waits on B, B waits on the approver, the
        # approver waits on A.
        names = [step[1].name for step in path]
        self.assertIn("a_request_b", names)
        self.assertIn("b_request_approver", names)
        self.assertIn("approver_request_a", names)

    def test_runaway_budget_path(self):
        model = approval.budget_build_ir(buggy=True)
        mf = ModelFinder.from_ir(model)
        # both agents spend (60 + 60 = 120 > 100 cap).
        witness = {"spent_a": approval.AMOUNT, "spent_b": approval.AMOUNT}
        path = mf.path_to(witness)
        self.assertTrue(path)
        names = [step[1].name for step in path]
        self.assertIn("a_spend", names)
        self.assertIn("b_spend", names)


# ---------------------------------------------------------------------------
# 5. Registry wiring
# ---------------------------------------------------------------------------

class ApprovalRegistryTests(unittest.TestCase):
    def _check_target(self, name, protocol, properties, default_property):
        self.assertIn(name, targets.names())
        spec = targets.get(name)
        self.assertEqual(spec.protocol, protocol)
        self.assertEqual(spec.properties, properties)
        self.assertEqual(spec.default_property, default_property)
        self.assertEqual(targets.default_property(name), default_property)

    def test_targets_registered(self):
        self._check_target("approval-correct", "APPROVAL",
                           ["no_unapproved_irreversible"],
                           "no_unapproved_irreversible")
        self._check_target("approval-buggy", "APPROVAL",
                           ["no_unapproved_irreversible"],
                           "no_unapproved_irreversible")
        self._check_target("delegation-correct", "DELEGATION",
                           ["no_privilege_escalation"],
                           "no_privilege_escalation")
        self._check_target("delegation-buggy", "DELEGATION",
                           ["no_privilege_escalation"],
                           "no_privilege_escalation")
        self._check_target("orchestration-correct", "ORCHESTRATION",
                           ["no_deadlock", "task_ends_or_escalates"],
                           "no_deadlock")
        self._check_target("orchestration-buggy", "ORCHESTRATION",
                           ["no_deadlock", "task_ends_or_escalates"],
                           "no_deadlock")
        self._check_target("budget-correct", "BUDGET",
                           ["no_runaway_budget"], "no_runaway_budget")
        self._check_target("budget-buggy", "BUDGET",
                           ["no_runaway_budget"], "no_runaway_budget")

    def test_invariants_registered(self):
        for name, kind in [
            ("no_unapproved_irreversible", "safety"),
            ("no_privilege_escalation", "safety"),
            ("no_deadlock", "safety"),
            ("task_ends_or_escalates", "liveness"),
            ("no_runaway_budget", "safety"),
        ]:
            inv = inv_get(name, 1)
            self.assertEqual(inv.name, name)
            self.assertEqual(inv.kind, kind)
            self.assertTrue(inv.pinned)
            self.assertTrue(inv.blocking_permission())
            self.assertIsNotNone(inv.expression)

    def test_get_property_resolves(self):
        prop = targets.get_property("approval-correct",
                                   "no_unapproved_irreversible", 1)
        self.assertFalse(prop.expression.eval(
            {"phase": "executed", "approved_once": False}))
        self.assertTrue(prop.expression.eval(
            {"phase": "executed", "approved_once": True}))


# ---------------------------------------------------------------------------
# 6. MR-gate wiring (the safety invariants; the liveness rule is tested via
#    the pipeline's reach_within oracle in the next class).
# ---------------------------------------------------------------------------

class ApprovalMrGateTests(unittest.TestCase):
    def test_approval_blocks_buggy(self):
        v = evaluate_mr("approval-correct", "approval-buggy",
                        properties=["no_unapproved_irreversible"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        rec = [r for r in v.invariants if r.name == "no_unapproved_irreversible"]
        self.assertTrue(rec)
        self.assertTrue(rec[0].violated_after)
        self.assertTrue(rec[0].blocking)

    def test_approval_passes_correct(self):
        v = evaluate_mr("approval-correct", "approval-correct",
                        properties=["no_unapproved_irreversible"], n=1)
        self.assertEqual(v.verdict, PASS)
        rec = [r for r in v.invariants if r.name == "no_unapproved_irreversible"]
        self.assertFalse(rec[0].violated_after)

    def test_delegation_blocks_buggy(self):
        v = evaluate_mr("delegation-correct", "delegation-buggy",
                        properties=["no_privilege_escalation"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        rec = [r for r in v.invariants if r.name == "no_privilege_escalation"]
        self.assertTrue(rec[0].violated_after)
        self.assertTrue(rec[0].blocking)

    def test_delegation_passes_correct(self):
        v = evaluate_mr("delegation-correct", "delegation-correct",
                        properties=["no_privilege_escalation"], n=1)
        self.assertEqual(v.verdict, PASS)

    def test_orchestration_blocks_buggy(self):
        v = evaluate_mr("orchestration-correct", "orchestration-buggy",
                        properties=["no_deadlock"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        rec = [r for r in v.invariants if r.name == "no_deadlock"]
        self.assertTrue(rec[0].violated_after)
        self.assertTrue(rec[0].blocking)

    def test_orchestration_passes_correct(self):
        v = evaluate_mr("orchestration-correct", "orchestration-correct",
                        properties=["no_deadlock"], n=1)
        self.assertEqual(v.verdict, PASS)

    def test_budget_blocks_buggy(self):
        v = evaluate_mr("budget-correct", "budget-buggy",
                        properties=["no_runaway_budget"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        rec = [r for r in v.invariants if r.name == "no_runaway_budget"]
        self.assertTrue(rec[0].violated_after)
        self.assertTrue(rec[0].blocking)

    def test_budget_passes_correct(self):
        v = evaluate_mr("budget-correct", "budget-correct",
                        properties=["no_runaway_budget"], n=1)
        self.assertEqual(v.verdict, PASS)


# ---------------------------------------------------------------------------
# 7. Liveness rule (TaskEndsOrEscalates) via the pipeline's reach_within oracle
# ---------------------------------------------------------------------------

class OrchestrationLivenessTests(unittest.TestCase):
    def test_task_ends_or_escalates_reachable_correct(self):
        import pipeline
        v = pipeline.run(target_name="orchestration-correct",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.property_kind, "liveness")
        self.assertEqual(v.status, "proven")

    def test_task_ends_or_escalates_reachable_buggy(self):
        # Even in the deadlock-prone orchestration the escape hatch makes the
        # goal reachable: the task can still be escalated.
        import pipeline
        v = pipeline.run(target_name="orchestration-buggy",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.status, "proven")


if __name__ == "__main__":
    unittest.main(verbosity=2)