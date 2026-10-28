# -*- coding: utf-8 -*-
"""End-to-end checks for the G5 (liveness) + G6 (binds) work.

This is the liveness core (G5) and the "binds" that were previously missing
(G6): a real ``TaskEndsOrEscalates`` liveness rule, a *livelock* (progress
without completion), a *deadlock* (stuck, no progress), and an *over-
privileged tool* (a model-checked over-grant).

Run:  python tests/test_liveness_binds.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.agent_harness as agent_harness
import rot.approval as approval
import rot.compliance as compliance
import rot.ir as ir
import rot.mcp_adapter as mcp
import rot.modelfind as modelfind
import rot.targets as targets
from rot.invariants import get as inv_get
from rot.modelfind import ModelFinder
from rot.mr_gate import PASS, BLOCK, evaluate_mr


def _terminal():
    """The legitimate terminal predicate (task done or escalated)."""
    return ir.Or(ir.V("done"), ir.V("escalated"))


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
# 1. Livelock (G5 liveness core): progress without completion
# ---------------------------------------------------------------------------

class LivelockModelTests(unittest.TestCase):
    def test_correct_ends_or_escalates(self):
        import pipeline
        v = pipeline.run(target_name="livelock-correct",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.property_kind, "liveness")
        self.assertEqual(v.status, "proven")

    def test_buggy_never_ends(self):
        import pipeline
        v = pipeline.run(target_name="livelock-buggy",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.property_kind, "liveness")
        self.assertEqual(v.status, "violated")

    def test_buggy_is_not_stuck(self):
        # The defining feature of a *livelock* (vs a deadlock): the system
        # keeps making progress, so there is NO stuck state.
        model = approval.livelock_build_ir(1, buggy=True)
        stuck, witness, _ = modelfind.find_deadlock_state(model,
                                                          terminal=_terminal())
        self.assertFalse(stuck,
                         "livelock-buggy must not be stuck (that would make "
                         "it a deadlock)")


# ---------------------------------------------------------------------------
# 2. Deadlock (G6 deadlock bind): stuck, no progress
# ---------------------------------------------------------------------------

class DeadlockModelTests(unittest.TestCase):
    def test_correct_ends_or_escalates(self):
        import pipeline
        v = pipeline.run(target_name="deadlock-correct",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.status, "proven")

    def test_buggy_never_ends(self):
        import pipeline
        v = pipeline.run(target_name="deadlock-buggy",
                         property_name="task_ends_or_escalates",
                         engine="symbolic", n=1, max_states=100000,
                         out_dir="out", quiet=True)
        self.assertEqual(v.status, "violated")
    def test_buggy_is_stuck(self):
        model = approval.deadlock_build_ir(1, buggy=True)
        stuck, witness, _ = modelfind.find_deadlock_state(model,
                                                          terminal=_terminal())
        self.assertTrue(stuck, "deadlock-buggy must be stuck")
        self.assertTrue(witness["task_pending"])
        self.assertTrue(witness["a_waiting"])
        self.assertTrue(witness["b_waiting"])
        self.assertFalse(witness["done"])
        self.assertFalse(witness["escalated"])

    def test_deadlock_vs_livelock_discrimination(self):
        # Both violate TaskEndsOrEscalates; they differ by the stuck-state
        # check: deadlock is stuck, livelock is not.
        dl_stuck, _, _ = modelfind.find_deadlock_state(
            approval.deadlock_build_ir(1, buggy=True), terminal=_terminal())
        ll_stuck, _, _ = modelfind.find_deadlock_state(
            approval.livelock_build_ir(1, buggy=True), terminal=_terminal())
        self.assertTrue(dl_stuck)
        self.assertFalse(ll_stuck)


# ---------------------------------------------------------------------------
# 3. find_deadlock_state helper
# ---------------------------------------------------------------------------

class FindDeadlockStateTests(unittest.TestCase):
    def test_correct_model_has_no_deadlock(self):
        for build in (lambda: approval.livelock_build_ir(1, buggy=False),
                      lambda: approval.deadlock_build_ir(1, buggy=False)):
            stuck, _, _ = modelfind.find_deadlock_state(build(),
                                                        terminal=_terminal())
            self.assertFalse(stuck)

    def test_empty_model(self):
        model = ir.ProtocolIR(name="empty", variables=[], actions=[],
                              init=ir.T(), pinned_property=ir.T())
        stuck, witness, reachable = modelfind.find_deadlock_state(model)
        self.assertFalse(stuck)
        self.assertIsNone(witness)
        self.assertEqual(reachable, [])


# ---------------------------------------------------------------------------
# 4. Over-privileged tool (G6 over-privileged bind, model-checked over-grant)
# ---------------------------------------------------------------------------

class OverPrivilegedToolTests(unittest.TestCase):
    def test_property_expression(self):
        prop = agent_harness.no_over_privileged_tool_property()
        self.assertTrue(prop.eval({"took_unneeded": False}))
        self.assertFalse(prop.eval({"took_unneeded": True}))

    def test_correct_holds(self):
        model = agent_harness.overpriv_build_ir(1, buggy=False)
        prop = agent_harness.no_over_privileged_tool_property()
        holds, _ = _holds_all_reachable(prop, model)
        self.assertTrue(holds)

    def test_buggy_violates_with_witness(self):
        model = agent_harness.overpriv_build_ir(1, buggy=True)
        prop = agent_harness.no_over_privileged_tool_property()
        violated, witness = _violation(prop, model)
        self.assertTrue(violated)
        self.assertTrue(witness["took_unneeded"])

    def test_required_tools_metadata(self):
        model = agent_harness.overpriv_build_ir(1, buggy=True)
        self.assertEqual(model.metadata.get("required_tools"), ["read_data"])
        self.assertEqual(model.metadata.get("unneeded_tools"), ["send_email"])

    def test_blocks_buggy(self):
        v = evaluate_mr("overpriv-correct", "overpriv-buggy",
                        properties=["no_over_privileged_tool"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        rec = [r for r in v.invariants if r.name == "no_over_privileged_tool"]
        self.assertTrue(rec)
        self.assertTrue(rec[0].violated_after)
        self.assertTrue(rec[0].blocking)

    def test_passes_correct(self):
        v = evaluate_mr("overpriv-correct", "overpriv-correct",
                        properties=["no_over_privileged_tool"], n=1)
        self.assertEqual(v.verdict, PASS)
        rec = [r for r in v.invariants if r.name == "no_over_privileged_tool"]
        self.assertFalse(rec[0].violated_after)


# ---------------------------------------------------------------------------
# 5. Invariant + target registration
# ---------------------------------------------------------------------------

class RegistrationTests(unittest.TestCase):
    def test_no_over_privileged_tool_registered(self):
        inv = inv_get("no_over_privileged_tool", 1)
        self.assertEqual(inv.name, "no_over_privileged_tool")
        self.assertEqual(inv.kind, "safety")
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())

    def test_targets_registered(self):
        for name in ("livelock-correct", "livelock-buggy",
                     "deadlock-correct", "deadlock-buggy",
                     "overpriv-correct", "overpriv-buggy"):
            self.assertIn(name, targets.names())
            spec = targets.get(name)
            self.assertIn(spec.default_property, spec.properties)


# ---------------------------------------------------------------------------
# 6. The "binds" vocabulary + SOC 2 / AIUC control mapping
# ---------------------------------------------------------------------------

class BindsVocabularyTests(unittest.TestCase):
    def test_all_findings_include_binds(self):
        for finding in (mcp.FINDING_DEADLOCK, mcp.FINDING_LIVELOCK,
                        mcp.FINDING_OVER_PRIVILEGED):
            self.assertIn(finding, mcp.ALL_FINDINGS)

    def test_bind_finding_for(self):
        self.assertEqual(mcp.bind_finding_for("no_deadlock"),
                         mcp.FINDING_DEADLOCK)
        self.assertEqual(mcp.bind_finding_for("task_ends_or_escalates"),
                         mcp.FINDING_LIVELOCK)
        self.assertEqual(mcp.bind_finding_for("no_over_privileged_tool"),
                         mcp.FINDING_OVER_PRIVILEGED)
        self.assertIsNone(mcp.bind_finding_for("not-a-property"))

    def test_binds_table_targets(self):
        for bind in mcp.BINDS.values():
            if bind["target"] is not None:
                self.assertIn(bind["target"], targets.names())

    def test_controls_for_new_findings(self):
        self.assertEqual(compliance.controls_for(mcp.FINDING_DEADLOCK),
                         [compliance.SOC2_CC66, compliance.AIUC_1])
        self.assertEqual(compliance.controls_for(mcp.FINDING_LIVELOCK),
                         [compliance.SOC2_CC66, compliance.AIUC_1])
        self.assertEqual(compliance.controls_for(mcp.FINDING_OVER_PRIVILEGED),
                         [compliance.SOC2_CC61, compliance.AIUC_1])

    def test_finding_accepts_new_names(self):
        for finding in (mcp.FINDING_DEADLOCK, mcp.FINDING_LIVELOCK,
                        mcp.FINDING_OVER_PRIVILEGED):
            f = mcp.Finding(finding, "policy", mcp.SEVERITY_ERROR,
                            "prop", "message")
            self.assertEqual(f.to_dict()["finding"], finding)
            self.assertIn(compliance.AIUC_1, f.to_dict()["controls"])

    def test_unknown_finding_rejected(self):
        with self.assertRaises(ValueError):
            mcp.Finding("not-a-finding", "policy", mcp.SEVERITY_ERROR,
                        "p", "m")


if __name__ == "__main__":
    unittest.main(verbosity=2)
