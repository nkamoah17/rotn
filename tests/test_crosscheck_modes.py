# Copyright (c) KAMANU. All rights reserved.
"""Phase 2 -- item 4: the PROVEN authority + the engine label.

The plan: "PROVEN requires smtz3=PROVEN AND tlc=PROVEN (the two independent
model checkers); policy_direct stays the offline fallback when TLC is absent;
every verdict report labels which engine(s) minted it.  Keep the existing
'all-three-agree' path as the strict mode."

These tests pin both modes (``strict`` and ``primary``) and the engine label
(``minted_by``), using *stubbed* engine seams so they run without Z3 or a TLC
jar:

  * ``strict``   -- PROVEN/VIOLATED require ALL THREE engines to agree
                    (the pre-existing path; the default, unchanged).
  * ``primary``  -- PROVEN/VIOLATED require the two independent model
                    checkers (smtz3 AND tlc).  When TLC is absent,
                    policy_direct is the offline fallback (smtz3 AND
                    policy_direct).

  * ``minted_by`` -- every PROVEN/VIOLATED names the engine(s) that minted
                    it (``[]`` when the join is UNKNOWN).

Run: python tests/test_crosscheck_modes.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot.crosscheck import (CrossChecker, MODE_PRIMARY, MODE_STRICT,
                            join_mode, minted_by)
from rot.invariants import spendcap_within_cap
from rot.symbolic import EngineResult
from rot.verdicts import Verdict

PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"


def _stub(smt_status, tlc_status, pd_status, mode):
    """A ``CrossChecker`` with all three engine seams stubbed to fixed
    statuses, so ``check()`` exercises only the join + label logic."""
    prop = spendcap_within_cap()
    checker = CrossChecker(None, None, prop, None, mode=mode)
    checker._smt_verdict = lambda: Verdict(
        status=smt_status, property_name=prop.name, engine="smtz3")
    checker._tlc_result = lambda: EngineResult(status=tlc_status, note="t")
    checker._policy_direct_verdict = lambda: EngineResult(
        status=pd_status, note="p")
    return checker


class JoinModePureFunctionTests(unittest.TestCase):
    """``join_mode``: the strict vs. primary join, as a pure function."""

    def test_strict_requires_all_three(self):
        self.assertEqual(
            join_mode(PROVEN, PROVEN, PROVEN, MODE_STRICT), PROVEN)
        # One engine absent -> no verdict (stricter than primary).
        self.assertEqual(
            join_mode(PROVEN, PROVEN, UNKNOWN, MODE_STRICT), UNKNOWN)

    def test_primary_two_mc_when_tlc_present(self):
        # TLC present: the two independent model checkers decide; policy
        # direct is informational.
        self.assertEqual(
            join_mode(PROVEN, PROVEN, UNKNOWN, MODE_PRIMARY), PROVEN)
        self.assertEqual(
            join_mode(VIOLATED, VIOLATED, UNKNOWN, MODE_PRIMARY), VIOLATED)

    def test_primary_falls_back_to_policy_direct_when_tlc_absent(self):
        # TLC absent (UNKNOWN): policy_direct is the offline fallback.
        self.assertEqual(
            join_mode(PROVEN, UNKNOWN, PROVEN, MODE_PRIMARY), PROVEN)
        self.assertEqual(
            join_mode(VIOLATED, UNKNOWN, VIOLATED, MODE_PRIMARY), VIOLATED)

    def test_primary_no_engine_to_pair_is_unknown(self):
        # Both TLC and policy_direct absent -> nothing to pair with SMT.
        self.assertEqual(
            join_mode(PROVEN, UNKNOWN, UNKNOWN, MODE_PRIMARY), UNKNOWN)

    def test_primary_disagreement_is_unknown(self):
        self.assertEqual(
            join_mode(PROVEN, VIOLATED, PROVEN, MODE_PRIMARY), UNKNOWN)

    def test_primary_is_stricter_or_equal_to_strict(self):
        # Where strict mints a verdict, primary must mint the same one
        # (all-three-agree implies two-mc-agree).
        for s in (PROVEN, VIOLATED, UNKNOWN):
            for t in (PROVEN, VIOLATED, UNKNOWN):
                for p in (PROVEN, VIOLATED, UNKNOWN):
                    st = join_mode(s, t, p, MODE_STRICT)
                    pr = join_mode(s, t, p, MODE_PRIMARY)
                    if st in (PROVEN, VIOLATED):
                        self.assertEqual(st, pr,
                                         "strict verdict %s must survive "
                                         "primary for (%s,%s,%s)"
                                         % (st, s, t, p))

    def test_unknown_mode_raises(self):
        self.assertRaises(ValueError,
                          join_mode, PROVEN, PROVEN, PROVEN, "bogus")


class MintedByLabelTests(unittest.TestCase):
    """``minted_by``: the engine label on a minted verdict."""

    def test_strict_labels_all_three(self):
        self.assertEqual(
            minted_by(PROVEN, PROVEN, PROVEN, PROVEN, MODE_STRICT),
            ["smtz3", "tlc", "policy_direct"])

    def test_primary_labels_two_mc_when_tlc_present(self):
        self.assertEqual(
            minted_by(PROVEN, PROVEN, UNKNOWN, PROVEN, MODE_PRIMARY),
            ["smtz3", "tlc"])

    def test_primary_labels_fallback_when_tlc_absent(self):
        self.assertEqual(
            minted_by(PROVEN, UNKNOWN, PROVEN, PROVEN, MODE_PRIMARY),
            ["smtz3", "policy_direct"])

class CheckModeIntegrationTests(unittest.TestCase):
    """``CrossChecker.check()`` honors the mode and carries the label."""

    def test_strict_check_labels_all_three(self):
        checker = _stub(PROVEN, PROVEN, PROVEN, MODE_STRICT)
        verdict = checker.check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(
            verdict.evidence["crosscheck"]["minted_by"],
            ["smtz3", "tlc", "policy_direct"])
        self.assertEqual(verdict.evidence["crosscheck"]["mode"], MODE_STRICT)
        self.assertIn("smtz3 + tlc + policy_direct", verdict.note)

    def test_primary_check_labels_two_mc(self):
        checker = _stub(PROVEN, PROVEN, UNKNOWN, MODE_PRIMARY)
        verdict = checker.check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(
            verdict.evidence["crosscheck"]["minted_by"],
            ["smtz3", "tlc"])
        self.assertIn("smtz3 + tlc", verdict.note)

    def test_primary_check_falls_back_to_policy_direct(self):
        checker = _stub(PROVEN, UNKNOWN, PROVEN, MODE_PRIMARY)
        verdict = checker.check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(
            verdict.evidence["crosscheck"]["minted_by"],
            ["smtz3", "policy_direct"])
        self.assertIn("smtz3 + policy_direct", verdict.note)

    def test_strict_vs_primary_differ_when_pd_absent(self):
        """The mode matters: with policy_direct absent, strict declines to
        mint while primary (two MCs) still proves -- and the labels differ."""
        strict = _stub(PROVEN, PROVEN, UNKNOWN, MODE_STRICT).check()
        primary = _stub(PROVEN, PROVEN, UNKNOWN, MODE_PRIMARY).check()
        self.assertEqual(strict.status, UNKNOWN)
        self.assertEqual(primary.status, PROVEN)
        self.assertEqual(strict.evidence["crosscheck"]["minted_by"], [])
        self.assertEqual(primary.evidence["crosscheck"]["minted_by"],
                         ["smtz3", "tlc"])


if __name__ == "__main__":
    unittest.main()

