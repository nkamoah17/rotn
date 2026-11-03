# -*- coding: utf-8 -*-
"""APW-1 -- Settled-sum cap bypass (the canonical spend-cap shape).

The policy admits a spend when the *settled* total within the window is under
the cap.  The one-word bug is the aggregate's event kind:

  * **buggy**   -- sums the *responses* (settled charges) only, so a burst of
    parallel fires (``spend_ok`` back-to-back, before any ``respond`` settles)
    grows the in-flight amount past the cap.  VIOLATED.
  * **correct** -- sums the *requests* (in-flight + settled), so the in-flight
    term is charged against the cap.  PROVEN.

Deliverables this file verifies (Phase 1 gate):
  * the hand-written oracle (``rot.spendcap.build_ir``) decides VIOLATED for
    the buggy variant with the named witness, PROVEN for the correct variant;
  * the ``.dw`` fixture lowers to exactly that oracle (``oracle-match``);
  * the catalog samples exist and parse to the same IR.

Run: python tests/test_apw1.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.spendcap as spendcap  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven,  # noqa: E402
                        assert_oracle_match, fixture)

APW = "APW-1"
BUGGY_WITNESS = {"completed": 0, "inflight": 3}
BUGGY_FIXTURE = fixture("spendcap-buggy.dw")
CORRECT_FIXTURE = fixture("spendcap-correct.dw")
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw1-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw1-correct.dw")


class APW1OracleTests(unittest.TestCase):
    """The APW-1 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            spendcap.build_ir(buggy=True), BUGGY_WITNESS, APW)
        # The witness is the 3-parallel-fire state: nothing settled yet, three
        # in flight (0 + 3 * 100 = 300 > the 200 cap).
        self.assertEqual(res.witness["completed"], 0)
        self.assertEqual(res.witness["inflight"], 3)

    def test_correct_oracle_is_proven(self):
        res = assert_correct_proven(spendcap.build_ir(buggy=False), APW)
        self.assertIsNone(res.witness)

    def test_the_only_difference_is_the_inflight_term(self):
        """buggy/correct share state + pinned property; only ``spend_ok``
        differs (the in-flight term)."""
        buggy = spendcap.build_ir(buggy=True)
        correct = spendcap.build_ir(buggy=False)
        self.assertEqual(buggy.pinned_property.to_dict(),
                         correct.pinned_property.to_dict())
        self.assertNotEqual(
            self._spend_ok_guard(buggy).to_dict(),
            self._spend_ok_guard(correct).to_dict())

    @staticmethod
    def _spend_ok_guard(ir):
        for a in ir.actions:
            if a.name == "spend_ok":
                return a.guard
        raise AssertionError("no spend_ok action in %s" % ir.name)


class APW1OracleMatchTests(unittest.TestCase):
    """The ``.dw`` fixture lowers to the hand-written oracle."""

    def test_buggy_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            BUGGY_FIXTURE, spendcap.build_ir(buggy=True), APW)

    def test_correct_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            CORRECT_FIXTURE, spendcap.build_ir(buggy=False), APW)

    def test_fixture_buggy_flag_is_threaded(self):
        from rot.dw import parse_file
        self.assertTrue(parse_file(BUGGY_FIXTURE).is_buggy)
        self.assertFalse(parse_file(CORRECT_FIXTURE).is_buggy)


class APW1SampleTests(unittest.TestCase):
    """The catalog samples exist, parse, and match the oracle."""

    def test_samples_exist(self):
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            self.assertTrue(os.path.exists(p), "missing sample: %s" % p)

    def test_samples_lower_to_the_oracle(self):
        from rot.dw import parse_file
        assert_oracle_match(
            SAMPLE_BUGGY, spendcap.build_ir(buggy=True), APW)
        assert_oracle_match(
            SAMPLE_CORRECT, spendcap.build_ir(buggy=False), APW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
