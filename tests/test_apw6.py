# -*- coding: utf-8 -*-
"""APW-6 -- Window-boundary burst (absolute "daily" windows).

The policy says "at most K events per window" (e.g. per day).  The bug is that
the counter *hard-resets* at the window boundary (an absolute window), so an
attacker does K events just before the boundary and K more just after it -- a
2x burst.  The correct (sliding-window) form does not hard-reset, so the total
across windows stays bounded.

  * **buggy**   -- the counter resets to zero at the boundary; ``cap`` events
    before + ``cap`` after = a 2x burst past the cap.  VIOLATED.
  * **correct** -- no hard reset (sliding window); the total admitted is
    bounded by the cap.  PROVEN.

The named witness: the current-window counter (``count``) is low (1) while the
total admitted (``total``) is past the cap (4) -- the burst across the reset.

This is a *forward-looking* shape: the Dogwood roadmap lists absolute-time
windows, but they are not in the language yet.  The oracle is hand-written in
``rot.shapes`` and the catalog sample illustrates the intent.

Run: python tests/test_apw6.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven)  # noqa: E402

APW = "APW-6"
BUGGY_WITNESS = {"count": 1, "total": 4}
CAP = 3
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw6-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw6-correct.dw")


def _action_names(ir):
    return set(a.name for a in ir.actions)


class APW6OracleTests(unittest.TestCase):
    """The APW-6 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            shapes.build_window_boundary_ir(buggy=True, cap=CAP),
            BUGGY_WITNESS, APW)
        # The burst: current-window count is low, total is past the cap.
        self.assertGreater(res.witness["total"], CAP)
        self.assertLess(res.witness["count"], res.witness["total"])

    def test_correct_oracle_is_proven(self):
        assert_correct_proven(
            shapes.build_window_boundary_ir(buggy=False, cap=CAP), APW)

    def test_buggy_has_a_boundary_reset(self):
        """The absolute-window bug: the buggy variant has a ``reset_boundary``
        action that zeroes the counter at the window edge."""
        self.assertIn("reset_boundary",
                      _action_names(shapes.build_window_boundary_ir(
                          buggy=True, cap=CAP)))

    def test_correct_has_no_boundary_reset(self):
        """The correct (sliding-window) variant has no ``reset_boundary``
        action, so the total stays bounded by the cap."""
        self.assertNotIn("reset_boundary",
                         _action_names(shapes.build_window_boundary_ir(
                             buggy=False, cap=CAP)))


class APW6SampleTests(unittest.TestCase):
    """The catalog samples exist and parse (forward-looking shape)."""

    def test_samples_exist(self):
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            self.assertTrue(os.path.exists(p), "missing sample: %s" % p)

    def test_samples_parse(self):
        from rot.dw import parse_file
        for p in (SAMPLE_BUGGY, SAMPLE_CORRECT):
            policy = parse_file(p)
            self.assertIsNotNone(policy, "sample did not parse: %s" % p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
