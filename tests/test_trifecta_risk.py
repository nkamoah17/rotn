# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.trifecta_risk` (the D6 "Lethal Trifecta" flag).

This is the design-time *capability* flag, distinct from :mod:`rot.trifecta`
(the three-facet *audit*).  It inspects a policy's action set
(``allowed ∪ denied``) for the three lethal facets -- private-data-access,
untrusted-content-intake, egress -- and fires only when all three are present.

Covers:
  * the **spend-cap policy** -> ``detected``, with the **egress** facet
    witnessed specifically by ``exfiltrate_secret``;
  * a **benign policy** (missing facets) -> ``clear``;
  * the AgentStep ``DEFAULT_POLICY`` (names ``exfiltrate_secret`` but no
    untrusted-content-intake action) -> ``clear``;
  * the exact emitted strings (``TRIFECTA: detected (facets: ...)`` /
    ``TRIFECTA: clear``);
  * :func:`classify_action` per-action facet attribution;
  * determinism, sorted witnesses, and JSON serialisability.

Run: python tests/test_trifecta_risk.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir  # noqa: E402  (imported after the path fix)
from rot import agent_step  # noqa: E402
from rot.trifecta_risk import (  # noqa: E402
    FACETS,
    TrifectaRisk,
    classify_action,
    detect,
)

DETECTED_MSG = ("TRIFECTA: detected (facets: private-data-access, "
                "untrusted-content-intake, egress)")
CLEAR_MSG = "TRIFECTA: clear"

# A spend-cap-style agent policy whose action set spans all three lethal
# facets: it reads a private ledger, ingests an external quote, and (in the
# denied set) names the egress capability ``exfiltrate_secret``.
_SPENDCAP_POLICY = ir.AdversarialPolicy(
    allowed=["read_private_ledger", "fetch_external_quote", "update_balance"],
    denied=["exfiltrate_secret"],
)

# A benign policy: it touches private data but has NO untrusted-content-intake
# and NO egress capability, so the lethal combination is absent.
_BENIGN_POLICY = ir.AdversarialPolicy(
    allowed=["read_log", "update_balance"],
    denied=[],
)


class TrifectaRiskDetectionTests(unittest.TestCase):
    def test_spendcap_policy_detected_on_egress_via_exfiltrate_secret(self):
        # The core D6 requirement: the spend-cap policy is flagged, and the
        # egress facet is witnessed specifically by ``exfiltrate_secret``.
        res = detect(_SPENDCAP_POLICY)
        self.assertIsInstance(res, TrifectaRisk)
        self.assertTrue(res.detected)
        self.assertEqual(res.message, DETECTED_MSG)
        self.assertEqual(res.missing, ())
        # All three facets present, in canonical order.
        self.assertEqual(res.present, FACETS)
        # The egress facet is witnessed by exactly ``exfiltrate_secret``.
        self.assertIn("egress", res.facets)
        self.assertEqual(res.facets["egress"], ["exfiltrate_secret"])
        self.assertTrue(res.present_facet("egress"))

    def test_spendcap_policy_all_three_facets_witnessed(self):
        res = detect(_SPENDCAP_POLICY)
        for facet in FACETS:
            self.assertIn(facet, res.facets)
            self.assertTrue(res.facets[facet])
            # Witnesses are a subset of the policy's action set, sorted.
            self.assertEqual(res.facets[facet], sorted(res.facets[facet]))
            for action in res.facets[facet]:
                self.assertIn(action, _SPENDCAP_POLICY.actions())

    def test_benign_policy_clear(self):
        res = detect(_BENIGN_POLICY)
        self.assertFalse(res.detected)
        self.assertEqual(res.message, CLEAR_MSG)
        # private-data-access is present; the other two facets are missing.
        self.assertEqual(res.present, ("private-data-access",))
        self.assertEqual(res.missing,
                         ("untrusted-content-intake", "egress"))
        self.assertFalse(res.present_facet("egress"))
        self.assertFalse(res.present_facet("untrusted-content-intake"))

    def test_agent_step_default_policy_clear(self):
        # The AgentStep DEFAULT_POLICY names ``exfiltrate_secret`` (egress +
        # private-data) but has NO untrusted-content-intake action, so the
        # lethal combination is NOT complete -> clear.
        res = detect(agent_step.DEFAULT_POLICY)
        self.assertFalse(res.detected)
        self.assertEqual(res.message, CLEAR_MSG)
        self.assertIn("egress", res.facets)
        self.assertIn("untrusted-content-intake", res.missing)


class TrifectaRiskMessageTests(unittest.TestCase):
    def test_detected_message_exact(self):
        self.assertEqual(detect(_SPENDCAP_POLICY).message, DETECTED_MSG)

    def test_clear_message_exact(self):
        self.assertEqual(detect(_BENIGN_POLICY).message, CLEAR_MSG)

    def test_message_is_one_of_the_two_canonical_forms(self):
        for policy in (_SPENDCAP_POLICY, _BENIGN_POLICY,
                       agent_step.DEFAULT_POLICY):
            self.assertIn(detect(policy).message, (DETECTED_MSG, CLEAR_MSG))


class ClassifyActionTests(unittest.TestCase):
    def test_exfiltrate_secret_is_egress_and_private(self):
        self.assertEqual(
            classify_action("exfiltrate_secret"),
            ("private-data-access", "egress"))

    def test_single_facet_actions(self):
        self.assertEqual(
            classify_action("read_private_ledger"), ("private-data-access",))
        self.assertEqual(
            classify_action("fetch_external_quote"),
            ("untrusted-content-intake",))

    def test_neutral_action_indicates_nothing(self):
        self.assertEqual(classify_action("do_nothing"), ())

    def test_case_insensitive(self):
        self.assertEqual(classify_action("Exfiltrate_Secret"),
                         classify_action("exfiltrate_secret"))

    def test_result_in_canonical_order(self):
        hits = classify_action("exfiltrate_secret")
        idx = [FACETS.index(f) for f in hits]
        self.assertEqual(idx, sorted(idx))


class TrifectaRiskStructureTests(unittest.TestCase):
    def test_determinism_same_policy_same_result(self):
        r1 = detect(_SPENDCAP_POLICY)
        r2 = detect(_SPENDCAP_POLICY)
        self.assertEqual(r1.detected, r2.detected)
        self.assertEqual(r1.message, r2.message)
        self.assertEqual(r1.facets, r2.facets)
        self.assertEqual(r1.present, r2.present)
        self.assertEqual(r1.missing, r2.missing)
        self.assertEqual(r1.to_json(), r2.to_json())

    def test_actions_are_full_set_sorted(self):
        res = detect(_SPENDCAP_POLICY)
        self.assertEqual(res.actions, tuple(_SPENDCAP_POLICY.actions()))
        self.assertEqual(res.actions, tuple(sorted(res.actions)))

    def test_to_dict_shape(self):
        d = detect(_SPENDCAP_POLICY).to_dict()
        self.assertIsInstance(d, dict)
        for key in ("detected", "facets", "present", "missing", "actions",
                    "n_actions", "message"):
            self.assertIn(key, d)
        self.assertTrue(d["detected"])
        self.assertEqual(d["n_actions"], len(_SPENDCAP_POLICY.actions()))

    def test_json_serialisable_and_deterministic(self):
        r = detect(_SPENDCAP_POLICY)
        self.assertEqual(r.to_json(), r.to_json())
        d = json.loads(r.to_json())  # must not raise
        self.assertEqual(d["message"], DETECTED_MSG)
        self.assertEqual(d["detected"], True)

    def test_empty_policy_is_clear(self):
        res = detect(ir.AdversarialPolicy(allowed=[], denied=[]))
        self.assertFalse(res.detected)
        self.assertEqual(res.message, CLEAR_MSG)
        self.assertEqual(res.present, ())
        self.assertEqual(res.missing, FACETS)

    def test_detect_rejects_none(self):
        self.assertRaises(TypeError, detect, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)