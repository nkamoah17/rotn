# -*- coding: utf-8 -*-
"""A1 -- the loud K-masking advisory.

A settled-only (``response``-triggered) spend-cap policy checked at a
concurrency pool bound ``K`` below the *minimal overshoot count* returns
``PROVEN`` because the parallel-fire race is not expressible in the state
space -- a **silent false-negative** (the K=1 trap: the buggy guard is never
exercised).  A1 makes that bound *loud* without changing the verdict or the
exit code: a ``MASKED_AT_LOW_K`` advisory is emitted in the manifest and as a
human warning.

Covered here:
  * ``minimal_overshoot_count`` -- the pure arithmetic (K=1 trap: the fewest
    in-flight requests that can push a settled-only decision past the cap);
  * ``k_masking_advisory`` -- fires exactly on a settled-only cap/budget policy
    that is PROVEN at a K below the minimal overshoot, and nowhere else;
  * ``Verdict`` / ``Manifest`` -- carry the advisory (schema + integrity);
  * the CLI end-to-end -- ``rot check --max-inflight 1`` on the buggy policy
    is PROVEN *with* the advisory; ``--max-inflight 2`` is VIOLATED (no
    advisory); the correct policy is PROVEN with *no* advisory at any K.

Run: python tests/test_kmasking.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.verdicts as verdicts  # noqa: E402
from rot.verdicts import (  # noqa: E402
    MASKED_AT_LOW_K,
    minimal_overshoot_count,
    k_masking_advisory,
    Verdict,
)

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_POLICY_BUGGY = os.path.join(_REPO, "tests", "fixtures", "aws_dogwood",
                             "spendcap", "policies", "spendcap-buggy.dw")
_POLICY_CORRECT = os.path.join(_REPO, "tests", "fixtures", "aws_dogwood",
                               "spendcap", "policies", "spendcap-correct.dw")


def _md(buggy=True, k=1, amount=100, cap=200, family="SPENDCAP"):
    """Build an IR-metadata dict shaped like the spend-cap front-end emits."""
    return {
        "family": family,
        "protocol": "SPENDCAP",
        "property_name": "spendcap_within_cap",
        "property_kind": "safety",
        "buggy": buggy,
        "amount": amount,
        "cap": cap,
        "max_inflight": k,
    }


class MinimalOvershootTests(unittest.TestCase):
    def test_canonical_spendcap(self):
        # amount=100, cap=200: two in-flight requests (200) coexisting with
        # the 100 a settled-only rule would still admit exceed the cap.
        self.assertEqual(minimal_overshoot_count(100, 200), 2)

    def test_larger_cap(self):
        # cap=1000, amount=100: settled-only admits up to 900 settled; one
        # more in-flight (100) still fits, two (200) push past -> need 2.
        self.assertEqual(minimal_overshoot_count(100, 1000), 2)

    def test_unit_amount(self):
        # amount=1, cap=5: the settled-only guard admits up to completed=4;
        # one in-flight request (5) still fits, two (6) push past -> need 2.
        # The K=1 trap is universal for any cap > amount: K must be >= 2.
        self.assertEqual(minimal_overshoot_count(1, 5), 2)

    def test_cap_equal_amount(self):
        # amount=100, cap=100: guard admits only completed=0; two in-flight
        # (200) exceed the cap -> need 2.
        self.assertEqual(minimal_overshoot_count(100, 100), 2)

    def test_cap_below_amount(self):
        # amount=100, cap=50: a single in-flight request (100) already
        # exceeds the cap, so even K=1 can express a violation -> need 1.
        self.assertEqual(minimal_overshoot_count(100, 50), 1)

    def test_degenerate_amount(self):
        # A non-positive amount cannot overshoot; the bound is vacuous.
        self.assertEqual(minimal_overshoot_count(0, 100), 1)
        self.assertEqual(minimal_overshoot_count(-5, 100), 1)


class AdvisoryDecisionTests(unittest.TestCase):
    def test_fires_on_buggy_proven_below_bound(self):
        code, msg = k_masking_advisory(_md(buggy=True, k=1), "proven")
        self.assertEqual(code, MASKED_AT_LOW_K)
        self.assertIn("K=1", msg)
        self.assertIn("K>=2", msg)

    def test_does_not_fire_at_or_above_bound(self):
        self.assertEqual(k_masking_advisory(_md(buggy=True, k=2), "proven"),
                         (None, None))
        self.assertEqual(k_masking_advisory(_md(buggy=True, k=4), "proven"),
                         (None, None))

    def test_does_not_fire_for_correct_policy(self):
        # A correct (in-flight-charging) policy is safe at every K, so there
        # is nothing to mask -- even at K=1.
        self.assertEqual(k_masking_advisory(_md(buggy=False, k=1), "proven"),
                         (None, None))

    def test_does_not_fire_on_violated(self):
        # A VIOLATED verdict already rules the policy out; no masking warning.
        self.assertEqual(k_masking_advisory(_md(buggy=True, k=1), "violated"),
                         (None, None))
        self.assertEqual(k_masking_advisory(_md(buggy=True, k=1), "unknown"),
                         (None, None))

    def test_does_not_fire_for_non_cap_budget(self):
        # A liveness / non-cap property is not subject to the K bound.
        md = _md(buggy=True, k=1)
        md.update({"family": "LIVENESS", "protocol": "LIVENESS",
                   "property_name": "eventually_reach",
                   "property_kind": "liveness"})
        self.assertEqual(k_masking_advisory(md, "proven"), (None, None))

    def test_missing_fields_are_safe(self):
        # No amount/cap/K recorded -> cannot compute the bound -> no advisory.
        self.assertEqual(k_masking_advisory({}, "proven"), (None, None))
        self.assertEqual(k_masking_advisory(None, "proven"), (None, None))


class VerdictAdvisoryTests(unittest.TestCase):
    def test_carries_and_serializes_advisory(self):
        v = Verdict(verdicts.PROVEN, "spendcap_within_cap", "symbolic",
                    advisories=[MASKED_AT_LOW_K])
        self.assertEqual(v.advisories, [MASKED_AT_LOW_K])
        self.assertEqual(v.to_dict()["advisories"], [MASKED_AT_LOW_K])
        # Round-trips through JSON (the manifest/trace artifact path).
        self.assertEqual(json.loads(v.to_json())["advisories"],
                         [MASKED_AT_LOW_K])

    def test_default_is_empty(self):
        v = Verdict(verdicts.PROVEN, "p", "symbolic")
        self.assertEqual(v.advisories, [])
        self.assertEqual(v.to_dict()["advisories"], [])

    def test_bad_advisory_code_rejected(self):
        with self.assertRaises(ValueError):
            Verdict(verdicts.PROVEN, "p", "symbolic",
                    advisories=["NOT_A_REAL_ADVISORY"])

    def test_markdown_renders_advisory(self):
        v = Verdict(verdicts.PROVEN, "p", "symbolic",
                    advisories=[MASKED_AT_LOW_K])
        md = v.to_markdown()
        self.assertIn("Advisories", md)
        self.assertIn(MASKED_AT_LOW_K, md)


class ManifestAdvisoryTests(unittest.TestCase):
    def _manifest(self, advisories=None):
        from rot.manifest import Manifest
        return Manifest(
            {"hash": "x", "allowed": [], "denied": []},
            {"family": "SPENDCAP", "buggy": True, "horizon": 12,
             "max_states": 1, "n_states": 1},
            {"safety": {"status": "proven"}},
            None,
            {"all_proven": True, "any_violated": False, "result": "proven"},
            advisories=advisories)

    def test_manifest_carries_advisory(self):
        m = self._manifest(advisories=[MASKED_AT_LOW_K])
        self.assertEqual(m.advisories, [MASKED_AT_LOW_K])
        self.assertEqual(m.to_dict()["advisories"], [MASKED_AT_LOW_K])
        # The advisory is part of the hashable body -> integrity check holds.
        self.assertTrue(m.verify())

    def test_advisory_changes_manifest_id(self):
        # The bound is recorded, not silently dropped: a different advisory
        # list yields a different manifest_id.
        m = self._manifest(advisories=[MASKED_AT_LOW_K])
        m2 = self._manifest()
        self.assertNotEqual(m.manifest_id, m2.manifest_id)


def _run_check(policy, max_inflight):
    """Run ``rot check`` and return ``(exit_code, report_dict_or_None, out)``."""
    out_dir = tempfile.mkdtemp(prefix="rotn_kmask_")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "rot", "check",
             "--policy", policy,
             "--max-inflight", str(max_inflight),
             "--out", out_dir],
            cwd=_REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = proc.stdout.decode("utf-8", "replace")
        report = None
        rp = os.path.join(out_dir, "report.json")
        if os.path.isfile(rp):
            with open(rp, "r") as fh:
                report = json.load(fh)
        return proc.returncode, report, out
    finally:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)


class CliAdvisoryTests(unittest.TestCase):
    def test_buggy_k1_proven_with_advisory(self):
        code, report, out = _run_check(_POLICY_BUGGY, 1)
        self.assertEqual(code, 0, out)  # PROVEN (within the K=1 bound)
        self.assertIsNotNone(report)
        self.assertEqual(report["verdict"], "proven")
        self.assertEqual(report["advisory"], MASKED_AT_LOW_K)
        self.assertIn("re-check at K>=2", report["advisory_message"])
        # The human warning is loud, not silent.
        self.assertIn("MASKED_AT_LOW_K", out)

    def test_buggy_k2_violated_no_advisory(self):
        code, report, out = _run_check(_POLICY_BUGGY, 2)
        self.assertEqual(code, 1, out)  # VIOLATED: the race is expressible
        self.assertEqual(report["verdict"], "violated")
        self.assertNotIn("advisory", report)
        self.assertNotIn("MASKED_AT_LOW_K", out)

    def test_correct_k1_proven_no_advisory(self):
        code, report, out = _run_check(_POLICY_CORRECT, 1)
        self.assertEqual(code, 0, out)  # PROVEN: genuinely safe at every K
        self.assertEqual(report["verdict"], "proven")
        self.assertNotIn("advisory", report)
        self.assertNotIn("MASKED_AT_LOW_K", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)