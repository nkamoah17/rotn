# -*- coding: utf-8 -*-
"""APW-3 -- Taint race ("no egress after a confidential read").

The agent touches confidential data (the taint), then sends data to an
outsider (the egress).  The rule is *data-dependent + temporal*: the egress is
forbidden while the taint is held.  The one-word bug is the event *kind* of the
taint trigger:

  * **buggy**   -- the taint is set by the read's *response*; the egress is
    admitted unguarded, so private data can reach an unapproved channel while
    it is still held.  VIOLATED.
  * **correct** -- the taint is set by the read's *request*, so the egress is
    admitted only when the agent is NOT holding private data.  PROVEN.

The named witness is the parallel read/send interleaving: the agent holds
private data and the egress has fired (``exfiltrated``).

Run: python tests/test_apw3.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven,  # noqa: E402
                        assert_oracle_match, fixture)

APW = "APW-3"
BUGGY_WITNESS = {"holding_private": True, "exfiltrated": True}
BUGGY_FIXTURE = fixture("taint-egress-buggy.dw")
CORRECT_FIXTURE = fixture("taint-egress-correct.dw")
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw3-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw3-correct.dw")


class APW3OracleTests(unittest.TestCase):
    """The APW-3 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            shapes.build_taint_egress_ir(buggy=True), BUGGY_WITNESS, APW)
        # The read/send interleaving: private data held AND exfiltrated.
        self.assertEqual(res.witness["holding_private"], True)
        self.assertEqual(res.witness["exfiltrated"], True)

    def test_correct_oracle_is_proven(self):
        assert_correct_proven(
            shapes.build_taint_egress_ir(buggy=False), APW)

    def test_pinned_property_is_no_exfiltration(self):
        for buggy in (False, True):
            ir = shapes.build_taint_egress_ir(buggy=buggy)
            # The pinned property is NOT exfiltrated (NoExfiltration).
            self.assertIn("exfiltrated", _dumps(ir.pinned_property))


def _dumps(e):
    return str(e.to_dict())


class APW3OracleMatchTests(unittest.TestCase):
    """The ``.dw`` fixture lowers to the hand-written oracle."""

    def test_buggy_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            BUGGY_FIXTURE, shapes.build_taint_egress_ir(buggy=True), APW)

    def test_correct_fixture_lowers_to_oracle(self):
        assert_oracle_match(
            CORRECT_FIXTURE, shapes.build_taint_egress_ir(buggy=False), APW)


class APW3SampleTests(unittest.TestCase):
    """The catalog samples exist, parse, and match the oracle."""

    def test_samples_exist(self):
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            self.assertTrue(os.path.exists(p), "missing sample: %s" % p)

    def test_samples_lower_to_the_oracle(self):
        assert_oracle_match(
            SAMPLE_BUGGY, shapes.build_taint_egress_ir(buggy=True), APW)
        assert_oracle_match(
            SAMPLE_CORRECT, shapes.build_taint_egress_ir(buggy=False), APW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
