# -*- coding: utf-8 -*-
"""APW-4 -- Distinct-count race (a cap on *distinct* recipients/values).

The policy caps the number of *distinct* recipients an agent may message
within a window (anti-fan-out / anti-spam).  The bug is which event feeds the
counter:

  * **buggy**   -- counts only *settled* (responded) events, so a burst of
    in-flight sends to many distinct recipients is admitted before any settle.
    VIOLATED.
  * **correct** -- counts *all* (request + response) events, so the in-flight
    distinct recipients are charged against the cap.  PROVEN.

The named witness: the distinct set has grown past the cap while the counted
(settled) set is still zero -- the in-flight burst that a settled-only monitor
misses.

Run: python tests/test_apw4.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven,  # noqa: E402
                        assert_oracle_match, fixture)

APW = "APW-4"
BUGGY_WITNESS = {"distinct": 4, "counted": 0}
BUGGY_FIXTURE = fixture("distinct-count-buggy.dw")
CORRECT_FIXTURE = fixture("distinct-count-correct.dw")
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw4-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw4-correct.dw")


class APW4OracleTests(unittest.TestCase):
    """The APW-4 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            shapes.build_distinct_count_ir(buggy=True), BUGGY_WITNESS, APW)
        # Distinct set past the cap, settled count still zero (the burst).
        self.assertGreater(res.witness["distinct"],
                           res.witness["counted"])

    def test_correct_oracle_is_proven(self):
        assert_correct_proven(
            shapes.build_distinct_count_ir(buggy=False), APW)


class APW4OracleMatchTests(unittest.TestCase):
    """The ``.dw`` fixture lowers to the hand-written oracle."""

    def test_buggy_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            BUGGY_FIXTURE, shapes.build_distinct_count_ir(buggy=True), APW)

    def test_correct_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            CORRECT_FIXTURE, shapes.build_distinct_count_ir(buggy=False),
            APW)


class APW4SampleTests(unittest.TestCase):
    """The catalog samples exist, parse, and match the oracle."""

    def test_samples_exist(self):
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            self.assertTrue(os.path.exists(p), "missing sample: %s" % p)

    def test_samples_lower_to_the_oracle(self):
        assert_oracle_match(
            SAMPLE_BUGGY, shapes.build_distinct_count_ir(buggy=True), APW)
        assert_oracle_match(
            SAMPLE_CORRECT, shapes.build_distinct_count_ir(buggy=False), APW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
