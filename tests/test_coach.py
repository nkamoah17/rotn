# -*- coding: utf-8 -*-
"""Tests for the CoachingArtifact (rot.coach) -- the third leg of the triad.

Covers the acceptance bar for the "coach agents back in bounds" gap:

  * the 5-step loop record is present (detect / explain / correct / recheck /
    close) and the re-check is PROVEN for the corrected policy;
  * the artifact is **deterministic** (the same input always yields the same
    hash) and **hashable** (the top-level hash is the SHA-256 of the canonical
    body);
  * the rationale is derived from the witness (plain-English, deterministic);
  * the corrected policy is the ``request``-sum variant (in-flight charged);
  * the **fail-closed** path: a corrected policy that does *not* re-prove
    yields status ``open`` (never "coached");
  * the K-sweep: the coaching is a pure function of the model knobs.

Run: python tests/test_coach.py
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.coach import (  # noqa: E402
    SCHEMA, CLOSED, OPEN, CoachingArtifact, coach, coach_hash, canonical_json)
from rot.dw import parse_file  # noqa: E402

#: The canonical buggy spend-cap .dw fixture (the ``response``-sum variant).
_POLICY_BUGGY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "aws_dogwood", "spendcap", "policies", "spendcap-buggy.dw")


def _buggy_policy():
    return parse_file(_POLICY_BUGGY)


class CoachingArtifactShapeTests(unittest.TestCase):
    """The 5-step loop record is present and well-formed."""

    def test_artifact_is_a_coaching_artifact(self):
        a = coach(_buggy_policy(), max_inflight=3)
        self.assertIsInstance(a, CoachingArtifact)
        self.assertEqual(a.body["schema"], SCHEMA)

    def test_five_step_record_is_present(self):
        a = coach(_buggy_policy(), max_inflight=3)
        for step in ("detect", "explain", "correct", "recheck", "close"):
            self.assertIn(step, a.body, "missing step %r" % step)

    def test_detect_is_violated_with_witness(self):
        a = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a.body["detect"]["status"], "violated")
        self.assertEqual(a.body["detect"]["witness"],
                         {"completed": 0, "inflight": 3})

    def test_recheck_is_proven(self):
        a = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a.body["recheck"]["status"], "proven")

    def test_closed_when_recheck_proven(self):
        a = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a.status(), CLOSED)

    def test_corrected_policy_is_request_sum(self):
        a = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a.body["correct"]["event_kind"], "request")
        self.assertEqual(a.body["policy"]["event_kind"], "response")
        self.assertIn("request", a.body["correct"]["delta"])

    def test_corrected_guard_charges_inflight(self):
        a = coach(_buggy_policy(), max_inflight=3)
        guard = a.body["correct"]["guard"]
        self.assertIn("inflight", guard)
        self.assertIn("completed", guard)
        # The buggy guard does NOT charge in-flight.
        self.assertNotIn("inflight *", a.body["correct"]["buggy_guard"])


class RationaleTests(unittest.TestCase):
    """The rationale is derived from the witness (plain-English, deterministic)."""

    def test_rationale_mentions_the_witness(self):
        a = coach(_buggy_policy(), max_inflight=3)
        rationale = a.body["explain"]["rationale"]
        self.assertIn("in-flight", rationale)
        self.assertIn("completed=0", rationale)
        self.assertIn("cap", rationale)

    def test_rationale_is_deterministic(self):
        a1 = coach(_buggy_policy(), max_inflight=3)
        a2 = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a1.body["explain"], a2.body["explain"])

    def test_exposure_is_computed_from_witness(self):
        a = coach(_buggy_policy(), max_inflight=3)
        # completed=0, inflight=3, amount=100 -> exposure = 300.
        self.assertEqual(a.body["explain"]["exposure"], 300)
        self.assertEqual(a.body["explain"]["cap"], 200)


class DeterminismTests(unittest.TestCase):
    """The artifact is a pure function of its input (deterministic + hashable)."""

    def test_hash_is_stable_across_runs(self):
        a1 = coach(_buggy_policy(), max_inflight=3)
        a2 = coach(_buggy_policy(), max_inflight=3)
        self.assertEqual(a1.hash, a2.hash)

    def test_hash_is_sha256_of_canonical_body(self):
        a = coach(_buggy_policy(), max_inflight=3)
        expected = hashlib.sha256(
            canonical_json(a.body).encode("utf-8")).hexdigest()
        self.assertEqual(a.hash, expected)
        # And it matches the module's own hash function.
        self.assertEqual(a.hash, coach_hash(a.body))

    def test_to_dict_carries_the_hash(self):
        a = coach(_buggy_policy(), max_inflight=3)
        d = a.to_dict()
        self.assertEqual(d["hash"], a.hash)
        self.assertEqual(d["status"], a.status())

    def test_to_json_is_valid_json(self):
        a = coach(_buggy_policy(), max_inflight=3)
        parsed = json.loads(a.to_json())
        self.assertEqual(parsed["hash"], a.hash)
        self.assertEqual(parsed["status"], a.status())

    def test_hash_changes_when_input_changes(self):
        a_k2 = coach(_buggy_policy(), max_inflight=2)
        a_k3 = coach(_buggy_policy(), max_inflight=3)
        self.assertNotEqual(a_k2.hash, a_k3.hash)


class FailClosedTests(unittest.TestCase):
    """A corrected policy that does not re-prove yields status ``open``."""

    def test_open_when_correction_does_not_reprove(self):
        # Passing the buggy policy as the "correction" means the re-check is
        # the buggy (response-sum) policy, which is VIOLATED -> not proven.
        p = _buggy_policy()
        a = coach(p, max_inflight=3, corrected=p)
        self.assertEqual(a.status(), OPEN)
        self.assertEqual(a.body["recheck"]["status"], "violated")
        self.assertIn("NOT discharged", a.body["close"]["discharge"])

    def test_open_is_never_coached(self):
        p = _buggy_policy()
        a = coach(p, max_inflight=3, corrected=p)
        self.assertNotEqual(a.status(), CLOSED)
        self.assertEqual(a.body["close"]["status"], OPEN)


class KsweepTests(unittest.TestCase):
    """The coaching is a pure function of the model knobs (the K-sweep)."""

    def test_k1_masks_the_race(self):
        # At K=1 the buggy policy is PROVEN (the race is unexpressible), so
        # the coaching's detect step is not violated -- but the loop still
        # runs and is deterministic.
        a = coach(_buggy_policy(), max_inflight=1)
        self.assertEqual(a.body["detect"]["status"], "proven")

    def test_k_ge_2_admits_the_violation(self):
        for k in (2, 3, 4):
            a = coach(_buggy_policy(), max_inflight=k)
            self.assertEqual(a.body["detect"]["status"], "violated",
                             "K=%d" % k)
            self.assertEqual(a.body["recheck"]["status"], "proven",
                             "K=%d" % k)
            self.assertEqual(a.status(), CLOSED, "K=%d" % k)


if __name__ == "__main__":
    unittest.main(verbosity=2)