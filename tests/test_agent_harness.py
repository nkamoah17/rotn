# -*- coding: utf-8 -*-
"""End-to-end checks for the general adversarial-agent + policy-harness model
(G1): the :class:`Tool` / :class:`HarnessPolicy` primitives, the
``NoExfiltration`` property, correct/buggy hold/violate semantics via the
model finder, registry + MR-gate wiring, and the spendcap instance that shows
the "strong core" is a special case of the general builder.

Run:  python tests/test_agent_harness.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
import rot.agent_harness as agent_harness
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


class HarnessPolicyTests(unittest.TestCase):
    def test_guard_defaults_to_allow(self):
        p = agent_harness.HarnessPolicy({})
        g = p.guard("anything")
        self.assertIsInstance(g, ir.Const)
        self.assertIs(g.value, True)

    def test_policy_eval_allow(self):
        p = agent_harness.HarnessPolicy({"send": ir.Not(ir.V("holding"))})
        self.assertEqual(p.policy_eval("send", {"holding": False}), "allow")

    def test_policy_eval_deny(self):
        p = agent_harness.HarnessPolicy({"send": ir.Not(ir.V("holding"))})
        self.assertEqual(p.policy_eval("send", {"holding": True}), "deny")

    def test_policy_eval_unknown(self):
        # A guard that is UNDEF in the state reports "unknown".
        p = agent_harness.HarnessPolicy({"send": ir.V("maybe")})
        self.assertEqual(p.policy_eval("send", {}), "unknown")

    def test_round_trip_via_dict(self):
        p = agent_harness.HarnessPolicy({"send": ir.Not(ir.V("holding"))},
                                       name="exfil")
        rt = agent_harness.HarnessPolicy.from_dict(p.to_dict())
        self.assertEqual(rt.to_dict(), p.to_dict())

    def test_tools_sorted(self):
        p = agent_harness.HarnessPolicy({"b": ir.T(), "a": ir.T(), "c": ir.T()})
        self.assertEqual(p.tools(), ["a", "b", "c"])


class ExfiltrationPropertyTests(unittest.TestCase):
    def test_property_is_not_exfiltrated(self):
        prop = agent_harness.no_exfiltration_property()
        self.assertTrue(prop.eval({"exfiltrated": False}))
        self.assertFalse(prop.eval({"exfiltrated": True}))


class ExfiltrationSemanticsTests(unittest.TestCase):
    def test_ir_well_formed(self):
        for buggy in (False, True):
            model = agent_harness.exfiltrate_build_ir(buggy=buggy)
            self.assertEqual(len(model.variables), 2)
            # init + 4 tools (read_private, send_unapproved, send_approved,
            # redact) = 5 actions.
            self.assertEqual(len(model.actions), 5)
            self.assertTrue(model.metadata["adversarial_agent"])

    def test_correct_holds_no_exfiltration(self):
        prop = agent_harness.no_exfiltration_property()
        ok, w = _holds_all_reachable(prop,
                                     agent_harness.exfiltrate_build_ir(buggy=False))
        self.assertTrue(ok,
                        "correct policy should hold no_exfiltration, got %r" % (w,))

    def test_buggy_violates_no_exfiltration(self):
        prop = agent_harness.no_exfiltration_property()
        has, w = _violation(prop,
                            agent_harness.exfiltrate_build_ir(buggy=True))
        self.assertTrue(has, "buggy policy should violate no_exfiltration")
        self.assertTrue(w["exfiltrated"])

    def test_buggy_attack_path(self):
        model = agent_harness.exfiltrate_build_ir(buggy=True)
        mf = ModelFinder.from_ir(model)
        witness = {"holding_private": True, "exfiltrated": True}
        path = mf.path_to(witness)
        self.assertTrue(path)
        # the attack path is: read_private (taints) then send_unapproved
        # (exfiltrates) -- exactly the NoExfiltration bypass.
        names = [step[1].name for step in path]
        self.assertEqual(names,
                         ["agent_take_read_private", "agent_take_send_unapproved"])

    def test_send_approved_is_effect_free(self):
        # the approved (safe) channel has no state effect -> it can never cause
        # an exfiltration; only the unapproved send while holding private data
        # can.  (This is what "expose only the safe channel" means structurally.)
        tools = {t.name: t for t in agent_harness.exfiltrate_tools()}
        self.assertEqual(tools["send_approved"].effect, [])


class ExfiltrationRegistryTests(unittest.TestCase):
    def test_both_targets_registered(self):
        for name in ("exfil-correct", "exfil-buggy"):
            self.assertIn(name, targets.names())
            spec = targets.get(name)
            self.assertEqual(spec.protocol, "EXFILTRATION")
            self.assertEqual(spec.properties, ["no_exfiltration"])
            self.assertEqual(spec.default_property, "no_exfiltration")
            self.assertEqual(targets.default_property(name), "no_exfiltration")
        self.assertEqual(targets.get("exfil-correct").properties,
                         targets.get("exfil-buggy").properties)

    def test_invariant_registered(self):
        inv = inv_get("no_exfiltration", 1)
        self.assertEqual(inv.name, "no_exfiltration")
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())
        self.assertIsNotNone(inv.expression)

    def test_get_property_resolves(self):
        prop = targets.get_property("exfil-correct", "no_exfiltration", 1)
        self.assertTrue(prop.expression.eval({"exfiltrated": False}))
        self.assertFalse(prop.expression.eval({"exfiltrated": True}))

    def test_mr_gate_blocks_buggy_variant(self):
        v = evaluate_mr("exfil-correct", "exfil-buggy",
                        properties=["no_exfiltration"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        ne = [r for r in v.invariants if r.name == "no_exfiltration"]
        self.assertTrue(ne)
        self.assertTrue(ne[0].violated_after)
        self.assertTrue(ne[0].blocking)

    def test_mr_gate_passes_correct_variant(self):
        v = evaluate_mr("exfil-correct", "exfil-correct",
                        properties=["no_exfiltration"], n=1)
        self.assertEqual(v.verdict, PASS)
        ne = [r for r in v.invariants if r.name == "no_exfiltration"]
        self.assertTrue(ne)
        self.assertFalse(ne[0].violated_after)


class SpendcapInstanceTests(unittest.TestCase):
    """The general builder must reproduce the strong-core spendcap verdicts.

    This is the "shows it generalizes" proof: :mod:`rot.spendcap` (the strong
    core) is an instance of the adversarial-agent + policy-harness builder, and
    the verdicts match.
    """

    def test_spendcap_instance_correct_proves(self):
        prop = agent_harness.spendcap.within_cap_property()
        ok, _ = _holds_all_reachable(prop,
                                     agent_harness.spendcap_build_ir(buggy=False))
        self.assertTrue(ok, "spendcap instance (correct) should prove the cap")

    def test_spendcap_instance_buggy_violates(self):
        prop = agent_harness.spendcap.within_cap_property()
        has, w = _violation(prop,
                            agent_harness.spendcap_build_ir(buggy=True))
        self.assertTrue(has, "spendcap instance (buggy) should violate the cap")
        self.assertGreaterEqual(w["inflight"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
