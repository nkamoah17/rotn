# -*- coding: utf-8 -*-
"""APW-5 -- Session splitting (a cap scoped to a policy session).

The policy says "at most K events per session".  The bug is that the counter
the guard reads is *scoped* to the session and is reset on every event, so the
guard is always satisfied and N sessions each admit K events -- the total is
N x the per-session cap.  The Classmethod tutorial itself notes temporal
limits are *per-session*; this shape makes that explicit.

  * **buggy**   -- the guard's counter is reset after every event (it only ever
    sees the most recent one), so the session's true count runs past the cap.
    VIOLATED.
  * **correct** -- the counter tracks the session's event count (lock-step), so
    the session's count is bounded by the cap.  PROVEN.

The named witness: the session's true count (``session_count``) is past the cap
while the guard's counter (``scope_count``) still reads 1 -- the scope bug.

This is a *forward-looking* shape: the oracle is hand-written in ``rot.shapes``
and the catalog sample illustrates the intent; it does not yet lower from a
``.dw`` file (there is no ``scoped_cap`` detector).

Run: python tests/test_apw5.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.shapes as shapes  # noqa: E402
from apw_common import (assert_buggy_violated, assert_correct_proven)  # noqa: E402

APW = "APW-5"
BUGGY_WITNESS = {"session_count": 4, "scope_count": 1}
CAP = 3
SAMPLE_BUGGY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw5-buggy.dw")
SAMPLE_CORRECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "samples", "apw5-correct.dw")


def _do_event(ir):
    for a in ir.actions:
        if a.name == "do_event":
            return a
    raise AssertionError("no do_event action in %s" % ir.name)


def _scope_assignment(ir):
    for e in _do_event(ir).effects:
        if e.var == "scope_count":
            return e
    raise AssertionError("no scope_count assignment in %s" % ir.name)


class APW5OracleTests(unittest.TestCase):
    """The APW-5 oracle decides VIOLATED (buggy) / PROVEN (correct)."""

    def test_buggy_oracle_is_violated_with_named_witness(self):
        res = assert_buggy_violated(
            shapes.build_scoped_cap_ir(buggy=True, cap=CAP), BUGGY_WITNESS, APW)
        # The session's true count is past the cap; the guard's counter reads 1.
        self.assertGreater(res.witness["session_count"], CAP)
        self.assertEqual(res.witness["scope_count"], 1)

    def test_correct_oracle_is_proven(self):
        assert_correct_proven(
            shapes.build_scoped_cap_ir(buggy=False, cap=CAP), APW)

    def test_buggy_resets_the_guard_counter(self):
        """The scope bug: the buggy variant resets ``scope_count`` to a constant
        (1) on every event, so the guard ``scope_count < cap`` is always true."""
        e = _scope_assignment(shapes.build_scoped_cap_ir(buggy=True, cap=CAP))
        self.assertEqual(e.expr.to_dict(), {"tag": "const", "value": 1})

    def test_correct_tracks_the_guard_counter(self):
        """The correct variant increments ``scope_count`` (lock-step), so the
        guard eventually denies."""
        e = _scope_assignment(shapes.build_scoped_cap_ir(buggy=False, cap=CAP))
        self.assertEqual(e.expr.to_dict().get("op"), "+")


class APW5SampleTests(unittest.TestCase):
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
