# -*- coding: utf-8 -*-
"""End-to-end checks for the AgentStep adversarial-agent vertical slice:
the AdversarialPolicy primitive, the policy_conformance property, bounded
hold/violate semantics via the model finder, and registry + MR-gate wiring.

Run:  python tests/test_agent_step.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
import rot.agent_step as agent_step
import rot.targets as targets
from rot.invariants import policy_conformance, get as inv_get
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


class AdversarialPolicyTests(unittest.TestCase):
    def test_default_allows_denies(self):
        p = agent_step.DEFAULT_POLICY
        self.assertTrue(p.allows("read_log"))
        self.assertTrue(p.allows("update_balance"))
        self.assertTrue(p.denies("exfiltrate_secret"))
        self.assertFalse(p.allows("exfiltrate_secret"))
        self.assertFalse(p.denies("read_log"))

    def test_actions_is_sorted_union(self):
        self.assertEqual(agent_step.DEFAULT_POLICY.actions(),
                         ["exfiltrate_secret", "read_log", "update_balance"])

    def test_denied_defaults_to_empty(self):
        p = ir.AdversarialPolicy(allowed=["a", "b"])
        self.assertEqual(p.denied, frozenset())
        self.assertTrue(p.allows("a"))

    def test_overlap_rejected(self):
        with self.assertRaises(ValueError):
            ir.AdversarialPolicy(allowed=["a"], denied=["a"])

    def test_round_trip_via_dict(self):
        p = agent_step.DEFAULT_POLICY
        rt = ir.AdversarialPolicy.from_dict(p.to_dict())
        self.assertEqual(rt.allowed, p.allowed)
        self.assertEqual(rt.denied, p.denied)
        self.assertEqual(rt.to_dict(), p.to_dict())

    def test_empty_policy(self):
        p = ir.AdversarialPolicy(allowed=[], denied=[])
        self.assertEqual(p.actions(), [])
        self.assertEqual(p.to_dict(), {"allowed": [], "denied": []})


class PropertyTests(unittest.TestCase):
    def test_default_property_mentions_decision(self):
        d = str(agent_step.policy_conformance_property().to_dict())
        self.assertIn("decision", d)

    def test_empty_denied_is_trivially_true(self):
        p = ir.AdversarialPolicy(allowed=["a"])
        self.assertTrue(agent_step.policy_conformance_property(p).eval({}))

    def test_multiple_denied_all_excluded(self):
        p = ir.AdversarialPolicy(allowed=["a"], denied=["x", "y"])
        prop = agent_step.policy_conformance_property(p)
        self.assertFalse(prop.eval({"decision": "x"}))
        self.assertFalse(prop.eval({"decision": "y"}))
        self.assertTrue(prop.eval({"decision": "a"}))
        self.assertTrue(prop.eval({"decision": "z"}))


class AgentStepSemanticsTests(unittest.TestCase):
    def test_ir_well_formed(self):
        for buggy in (False, True):
            m = agent_step.build_ir(n=1, buggy=buggy)
            self.assertFalse(m.validate(), msg=str(m.validate()))
            self.assertTrue(any(a.is_initial for a in m.actions))
            self.assertTrue(any(v.mode == ir.MODE_EXISTENTIAL for v in m.variables))

    def test_correct_model_satisfies_policy_conformance(self):
        ok, w = _holds_all_reachable(agent_step.policy_conformance_property(),
                                     agent_step.build_ir(n=1, buggy=False))
        self.assertTrue(ok, "correct AgentStep should conform, witness=%s" % (w,))

    def test_buggy_model_violates_policy_conformance(self):
        has, w = _violation(agent_step.policy_conformance_property(),
                            agent_step.build_ir(n=1, buggy=True))
        self.assertTrue(has, "buggy AgentStep should violate policy_conformance")
        self.assertEqual(w["decision"], "exfiltrate_secret")

    def test_correct_denied_action_unreachable(self):
        mf = ModelFinder.from_ir(agent_step.build_ir(n=1, buggy=False))
        status, _ = mf.exists_reachable(lambda s: s.get("decision") == "exfiltrate_secret")
        self.assertEqual(status, "UNSAT")

    def test_allowed_action_reachable_in_both_variants(self):
        for buggy in (False, True):
            mf = ModelFinder.from_ir(agent_step.build_ir(n=1, buggy=buggy))
            status, _ = mf.exists_reachable(lambda s: s.get("decision") == "read_log")
            self.assertEqual(status, "SAT")

    def test_custom_policy(self):
        p = ir.AdversarialPolicy(allowed=["safe"], denied=["drop", "steal"])
        has, w = _violation(agent_step.policy_conformance_property(p),
                            agent_step.build_ir(policy=p, buggy=True))
        self.assertTrue(has)
        self.assertIn(w["decision"], ["drop", "steal"])
        ok, _ = _holds_all_reachable(agent_step.policy_conformance_property(p),
                                     agent_step.build_ir(policy=p, buggy=False))
        self.assertTrue(ok)


class InvariantRegistryTests(unittest.TestCase):
    def test_registered_and_lookup(self):
        inv = inv_get("policy_conformance", 1)
        self.assertEqual(inv.name, "policy_conformance")
        self.assertEqual(inv.label, "bounded_depth")
        self.assertTrue(inv.pinned)
        self.assertTrue(inv.blocking_permission())
        self.assertIsNotNone(inv.expression)


class AgentStepRegistryTests(unittest.TestCase):
    def test_both_targets_registered(self):
        for name in ("agent-step", "agent-step-buggy"):
            self.assertIn(name, targets.names())
            spec = targets.get(name)
            self.assertEqual(spec.protocol, "AGENT_STEP")
            self.assertEqual(spec.properties, ["policy_conformance", "bounded_eventually"])
            self.assertEqual(spec.default_property, "policy_conformance")
            self.assertEqual(targets.default_property(name), "policy_conformance")
        # The two targets share the same property set; they differ only in the
        # seeded decision rule (conforming vs adversarial), which the semantics
        # tests above already discriminate.
        self.assertEqual(targets.get("agent-step").properties,
                         targets.get("agent-step-buggy").properties)

    def test_get_property_resolves(self):
        prop = targets.get_property("agent-step", "policy_conformance", 1)
        self.assertTrue(prop.expression.eval({"decision": "read_log"}))
        self.assertFalse(prop.expression.eval({"decision": "exfiltrate_secret"}))

    def test_mr_gate_blocks_buggy_variant(self):
        v = evaluate_mr("agent-step", "agent-step-buggy",
                        properties=["policy_conformance"], n=1)
        self.assertEqual(v.verdict, BLOCK)
        pc = [r for r in v.invariants if r.name == "policy_conformance"]
        self.assertTrue(pc)
        self.assertTrue(pc[0].violated_after)
        self.assertTrue(pc[0].blocking)

    def test_mr_gate_passes_correct_variant(self):
        v = evaluate_mr("agent-step", "agent-step",
                        properties=["policy_conformance"], n=1)
        self.assertEqual(v.verdict, PASS)
        pc = [r for r in v.invariants if r.name == "policy_conformance"]
        self.assertTrue(pc)
        self.assertFalse(pc[0].violated_after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
