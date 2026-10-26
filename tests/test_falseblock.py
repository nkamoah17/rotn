# -*- coding: utf-8 -*-
"""Tests for rot.falseblock (Step 3.6: false-block measurement).

Runs under ``python -m unittest tests.test_falseblock`` from the ROTN
directory (Python 3.6), using the same import bootstrap as
tests/test_specdiff.py.

The corpus passed to :func:`rot.falseblock.measure_false_blocks` is an
iterable of ``(before, after)`` pairs; each side is a registered target name
(or a ``rot.ir.ProtocolIR``).  Each entry is treated as a diff that *should*
be accepted, so a BLOCK verdict on it counts as a false block.  The report
exposes ``blocked`` / ``passed`` / ``warned`` counts, ``false_block_rate``
(``blocked / total``), and a recommendation when the rate exceeds the
threshold.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

# --- import bootstrap (mirror tests/test_specdiff.py) ------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from rot.falseblock import (
    FalseBlockReport,
    measure_false_blocks,
)
from rot.mr_gate import BLOCK


def safe_corpus():
    """A small corpus of *safe* diffs (their AFTER state keeps the pinned
    blocking invariants) -> the gate PASSES each one.

    Note: ``("buggy", "buggy")`` is NOT safe -- the buggy spec already
    violates the pinned ``agreement`` invariant, so even a no-change diff
    from it is blocked.  A genuinely safe diff lands on a ``correct`` AFTER.
    """
    return [
        ("correct", "correct"),  # no change
        ("buggy", "correct"),    # fix: restore the correct spec
    ]


class TestFalseBlock(unittest.TestCase):

    def test_safe_corpus_zero_rate(self):
        report = measure_false_blocks(safe_corpus(), n=2, threshold=0.1)
        self.assertEqual(report.corpus_size, 2)
        self.assertEqual(report.blocked, 0)
        self.assertEqual(report.passed, 2)
        self.assertEqual(report.warned, 0)
        self.assertEqual(report.false_block_rate, 0.0)
        self.assertFalse(report.exceeded)

    def test_including_blocked_diff_raises_rate(self):
        corpus = [
            ("correct", "correct"),
            ("correct", "buggy"),  # breaks the pinned blocking invariant
        ]
        report = measure_false_blocks(corpus, n=2, threshold=0.5)
        self.assertEqual(report.corpus_size, 2)
        self.assertEqual(report.blocked, 1)
        self.assertEqual(report.passed, 1)
        self.assertAlmostEqual(report.false_block_rate, 0.5)
        # 0.5 is not strictly greater than 0.5 -> within threshold.
        self.assertFalse(report.exceeded)

    def test_rate_exceeds_threshold_recommends_restriction(self):
        corpus = [
            ("correct", "correct"),
            ("correct", "buggy"),  # blocked
        ]
        report = measure_false_blocks(corpus, n=2, threshold=0.3)
        self.assertAlmostEqual(report.false_block_rate, 0.5)
        self.assertTrue(report.exceeded)
        self.assertIn("restrict", report.recommendation)

    def test_below_threshold_acceptable(self):
        report = FalseBlockReport(
            corpus_size=10, blocked=0, passed=10, warned=0,
            false_block_rate=0.0, threshold=0.1, exceeded=False,
            recommendation="false_block_rate 0.000 is within threshold 0.100: "
            "the gate's pinned-property set is acceptable", outcomes=[],
        )
        self.assertFalse(report.exceeded)
        self.assertIn("within threshold", report.recommendation)

    def test_outcome_records(self):
        report = measure_false_blocks([("correct", "buggy")], n=2)
        self.assertEqual(report.blocked, 1)
        o = report.outcomes[0]
        self.assertEqual(o.before, "correct")
        self.assertEqual(o.after, "buggy")
        self.assertEqual(o.verdict, BLOCK)
        self.assertTrue(o.blocked)
        self.assertIn("agreement", o.blocked_invariants)

    def test_json_roundtrip(self):
        report = measure_false_blocks(safe_corpus(), n=2)
        tmp = tempfile.mkdtemp(prefix="rot_fb_")
        try:
            path = report.write(tmp)
            self.assertTrue(os.path.exists(path))
            with open(path, "r") as f:
                data = json.load(f)
            self.assertEqual(data["corpus_size"], 2)
            self.assertEqual(data["false_block_rate"], 0.0)
            self.assertEqual(len(data["outcomes"]), 2)
            self.assertIn("verdict", data["outcomes"][0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()