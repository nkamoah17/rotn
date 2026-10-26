# -*- coding: utf-8 -*-
"""Tests for :mod:`rot.manifest` (deterministic verification reports).

Covers:
  * determinism -- the same ``(policy, environment)`` produces byte-identical
    manifests (and hence the same ``manifest_id``) across re-runs;
  * ``manifest_id`` is a valid SHA-256 and is self-consistent (``verify``);
  * integrity -- :func:`verify_manifest` recomputes the body hash and detects
    tampering;
  * reproducibility -- :func:`verify` with an ``expected_id`` matches;
  * the schema fields (schema, policy, environment, verdicts, witness,
    overall, manifest_id);
  * the overall-result folding (proven / violated);
  * the manifest's policy hash matches :func:`rot.trifecta.policy_hash`;
  * key-order independence (different construction order -> same id).

Run: python tests/test_manifest.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir  # noqa: E402  (imported after the path fix)
from rot import manifest  # noqa: E402
from rot.trifecta import policy_hash  # noqa: E402

# A policy where the agent may act (conforming -> all proven).
_GOOD_POLICY = ir.AdversarialPolicy(
    allowed=["read_log", "update_balance"],
    denied=["exfiltrate_secret"],
)

# An adversarial policy (buggy=True -> safety violated).
_ADV_POLICY = ir.AdversarialPolicy(
    allowed=["read_log"],
    denied=["exfiltrate_secret"],
)


class ManifestDeterminismTests(unittest.TestCase):
    def test_deterministic_byte_identical(self):
        m1 = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                     max_states=200000)
        m2 = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                     max_states=200000)
        self.assertEqual(m1.manifest_id, m2.manifest_id)
        self.assertEqual(m1.to_json(), m2.to_json())
        self.assertEqual(m1.to_json(indent=2), m2.to_json(indent=2))

    def test_manifest_id_is_valid_sha256(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        self.assertEqual(len(m.manifest_id), 64)
        self.assertEqual(int(m.manifest_id, 16) >= 0, True)  # valid hex

    def test_key_order_independence(self):
        # Reconstructing the same manifest body in a different key order must
        # yield the same id (the canonical serializer sorts keys).
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        d = m.to_dict()
        # Rebuild with a shuffled key order.
        shuffled = dict(reversed(list(d.items())))
        self.assertEqual(manifest.verify_manifest(shuffled)[0], True)
        self.assertEqual(shuffled["manifest_id"], m.manifest_id)


class ManifestIntegrityTests(unittest.TestCase):
    def test_verify_passes(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        self.assertTrue(m.verify())

    def test_verify_manifest_integrity(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        ok, cid, note = manifest.verify_manifest(m.to_dict())
        self.assertTrue(ok, note)
        self.assertEqual(cid, m.manifest_id)

    def test_verify_manifest_tamper_detection(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        tampered = m.to_dict()
        # Change the overall result to a *different* value (the conforming
        # agent is "proven", so flip it to "violated") to tamper the body.
        tampered["overall"] = {"all_proven": False, "any_violated": True,
                               "result": "violated"}
        ok, _cid, note = manifest.verify_manifest(tampered)
        self.assertFalse(ok)
        self.assertIn("does not match", note)

    def test_verify_reproducibility_with_expected_id(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        ok, mm, note = manifest.verify(_GOOD_POLICY, buggy=False, horizon=12,
                                       max_states=200000,
                                       expected_id=m.manifest_id)
        self.assertTrue(ok, note)
        self.assertEqual(mm.manifest_id, m.manifest_id)

    def test_verify_expected_id_mismatch(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        ok, _mm, note = manifest.verify(_GOOD_POLICY, buggy=False, horizon=12,
                                        max_states=200000,
                                        expected_id="0" * 64)
        self.assertFalse(ok)
        self.assertIn("does not match", note)


class ManifestSchemaTests(unittest.TestCase):
    def test_schema_fields_present(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        d = m.to_dict()
        for key in ("schema", "policy", "environment", "verdicts", "witness",
                    "overall", "manifest_id"):
            self.assertIn(key, d)
        self.assertEqual(d["schema"], manifest.SCHEMA)
        self.assertIn("safety", d["verdicts"])
        self.assertIn("liveness", d["verdicts"])
        self.assertIn("conformance", d["verdicts"])

    def test_policy_hash_matches_trifecta(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        self.assertEqual(m.policy["hash"], policy_hash(_GOOD_POLICY))
        self.assertEqual(sorted(m.policy["allowed"]),
                         sorted(_GOOD_POLICY.allowed))
        self.assertEqual(sorted(m.policy["denied"]),
                         sorted(_GOOD_POLICY.denied))

    def test_environment_fields(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        env = m.environment
        self.assertEqual(env["family"], "AGENT_STEP")
        self.assertFalse(env["buggy"])
        self.assertEqual(env["horizon"], 12)
        self.assertEqual(env["max_states"], 200000)
        self.assertIsInstance(env["n_states"], int)


class ManifestOverallTests(unittest.TestCase):
    def test_overall_proven_for_conforming(self):
        m = manifest.build_manifest(_GOOD_POLICY, buggy=False, horizon=12,
                                    max_states=200000)
        self.assertEqual(m.overall["result"], "proven")
        self.assertTrue(m.overall["all_proven"])
        self.assertFalse(m.overall["any_violated"])

    def test_overall_violated_for_adversarial(self):
        m = manifest.build_manifest(_ADV_POLICY, buggy=True, horizon=12,
                                    max_states=200000)
        self.assertEqual(m.overall["result"], "violated")
        self.assertTrue(m.overall["any_violated"])
        self.assertFalse(m.overall["all_proven"])
        # The primary witness is the safety counterexample.
        self.assertIsNotNone(m.witness)


if __name__ == "__main__":
    unittest.main(verbosity=2)