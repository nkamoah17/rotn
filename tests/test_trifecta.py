# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.trifecta` (the three-facet policy audit).

Covers:
  * a *conforming* agent (``buggy=False``) yields all three facets proven;
  * an *adversarial* agent (``buggy=True``) yields a definite safety
    violation with a witness;
  * a *stuck* agent (no allowed action) yields definite liveness +
    conformance violations;
  * determinism (same policy -> same verdicts and policy hash);
  * policy-hash stability (a valid SHA-256);
  * policy validation (allowed/denied overlap raises ``ValueError``);
  * the result/facet structure (status, property, witness, evidence, n_states).

Run: python tests/test_trifecta.py
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir  # noqa: E402  (imported after the path fix)
from rot.trifecta import (  # noqa: E402
    audit,
    policy_hash,
    TrifectaResult,
    FacetVerdict,
    PROVEN,
    VIOLATED,
)

# A policy where the agent may act (>= 1 allowed action).
_GOOD_POLICY = ir.AdversarialPolicy(
    allowed=["read_log", "update_balance"],
    denied=["exfiltrate_secret"],
)

# A policy with no allowed action (the agent is stuck).
_STUCK_POLICY = ir.AdversarialPolicy(
    allowed=[],
    denied=["do"],
)


class TrifectaAuditTests(unittest.TestCase):
    def test_conforming_agent_all_proven(self):
        res = audit(_GOOD_POLICY, buggy=False, horizon=12, max_states=200000)
        self.assertIsInstance(res, TrifectaResult)
        self.assertEqual(res.safety.status, PROVEN)
        self.assertEqual(res.liveness.status, PROVEN)
        self.assertEqual(res.conformance.status, PROVEN)
        self.assertTrue(res.all_proven())
        self.assertFalse(res.any_violated())

    def test_adversarial_agent_safety_violated(self):
        # The adversarial agent takes a denied action, so the policy
        # conformance invariant is violated in a reachable state.
        res = audit(_GOOD_POLICY, buggy=True, horizon=12, max_states=200000)
        self.assertEqual(res.safety.status, VIOLATED)
        self.assertTrue(res.any_violated())
        self.assertFalse(res.all_proven())
        # A definite violation carries a witness.
        self.assertIsNotNone(res.safety.witness)

    def test_stuck_agent_liveness_and_conformance_violated(self):
        # No allowed action -> the agent can never commit (liveness) and no
        # reachable state has an allowed action taken (conformance).
        res = audit(_STUCK_POLICY, buggy=False, horizon=12, max_states=200000)
        self.assertEqual(res.liveness.status, VIOLATED)
        self.assertEqual(res.conformance.status, VIOLATED)
        self.assertTrue(res.any_violated())
        self.assertFalse(res.all_proven())

    def test_determinism_same_policy_same_verdicts(self):
        r1 = audit(_GOOD_POLICY, buggy=False, horizon=12, max_states=200000)
        r2 = audit(_GOOD_POLICY, buggy=False, horizon=12, max_states=200000)
        self.assertEqual(r1.safety.status, r2.safety.status)
        self.assertEqual(r1.liveness.status, r2.liveness.status)
        self.assertEqual(r1.conformance.status, r2.conformance.status)
        self.assertEqual(r1.policy_hash, r2.policy_hash)
        self.assertEqual(r1.n_states, r2.n_states)

    def test_policy_hash_is_stable_sha256(self):
        h1 = policy_hash(_GOOD_POLICY)
        h2 = policy_hash(_GOOD_POLICY)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 hex digest length
        self.assertEqual(int(h1, 16) >= 0, True)  # valid hex
        # A different policy yields a different hash.
        other = ir.AdversarialPolicy(allowed=["a"], denied=["b"])
        self.assertNotEqual(policy_hash(_GOOD_POLICY), policy_hash(other))

    def test_overlap_raises_value_error(self):
        # The overlap is rejected at policy construction (AdversarialPolicy
        # validates allowed/denied are disjoint), so the audit never sees it.
        self.assertRaises(
            ValueError, ir.AdversarialPolicy, ["a", "b"], ["b", "c"])

    def test_facet_structure(self):
        res = audit(_GOOD_POLICY, buggy=False, horizon=12, max_states=200000)
        for facet in (res.safety, res.liveness, res.conformance):
            self.assertIsInstance(facet, FacetVerdict)
            self.assertIn(facet.facet, ("safety", "liveness", "conformance"))
            self.assertIn(facet.status, (PROVEN, VIOLATED, "unknown"))
            self.assertIsInstance(facet.property_name, str)
            self.assertIsInstance(facet.evidence, dict)
            self.assertIsInstance(facet.n_states, int)
            self.assertIsInstance(facet.to_dict(), dict)

    def test_result_json_serialisable(self):
        res = audit(_GOOD_POLICY, buggy=False, horizon=12, max_states=200000)
        d = res.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("safety", d)
        self.assertIn("liveness", d)
        self.assertIn("conformance", d)
        self.assertIn("policy_hash", d)
        self.assertIn("n_states", d)
        # Must be JSON-serialisable (witnesses are plain state dicts).
        import json
        json.dumps(d)


if __name__ == "__main__":
    unittest.main(verbosity=2)