# -*- coding: utf-8 -*-
"""Tests for rot.zk_bugs (Step 3.7: ZooKeeper/ZAB bug-replay evaluation).

Runs under ``python -m unittest tests.test_zk_bug_replay`` from the ROTN
directory (Python 3.6), using the same import bootstrap as
tests/test_falseblock.py.

The corpus (``rot.zk_bugs.commit_corpus``) is a small, *honest* set of
ZooKeeper/ZAB commits -- each expressed as a before/after ``ProtocolIR`` diff
(exactly what a merge request looks like to the gate) -- replayed through the
Phase 3 MR gate (``rot.mr_gate.evaluate_mr``) with the ZAB invariant set.

These tests lock in:

  * the corpus composition (3 bug-introducing + 3 safe),
  * that EVERY commit's actual verdict matches its documented expectation
    (the corpus is self-consistent: what we claim is what the gate does),
  * the per-commit classification (TP / FN / TN),
  * the aggregate Step 3.7 metrics (false-block rate 0.0, precision 1.0,
    recall 2/3), and
  * the JSON report round-trip.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

# --- import bootstrap (mirror tests/test_falseblock.py) ---------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from rot.mr_gate import PASS, BLOCK  # noqa: E402
from rot.zk_bugs import (  # noqa: E402
    commit_corpus,
    replay_corpus,
    TP, FN, TN,
)

N = 2  # small enough to prove every invariant over ALL reachable states


# -- cached report (replaying is the expensive part; reuse across tests) -----
_REPORT = None


def _report():
    global _REPORT
    if _REPORT is None:
        _REPORT = replay_corpus(n=N)
    return _REPORT


def _outcome(report, commit_id):
    for o in report.outcomes:
        if o.commit.commit_id == commit_id:
            return o
    raise AssertionError("no outcome for %s" % commit_id)


class TestZkCorpus(unittest.TestCase):
    """Corpus composition and self-consistency."""

    def test_corpus_composition(self):
        corpus = commit_corpus(n=N)
        self.assertEqual(len(corpus), 6)
        self.assertEqual(sum(1 for c in corpus if c.is_bug), 3)
        self.assertEqual(sum(1 for c in corpus if not c.is_bug), 3)

    def test_corpus_ids_unique(self):
        ids = [c.commit_id for c in commit_corpus(n=N)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_verdict_matches_expectation(self):
        """The corpus must be honest: actual gate verdict == documented intent."""
        report = _report()
        self.assertEqual(len(report.outcomes), 6)
        for o in report.outcomes:
            self.assertEqual(
                o.verdict, o.commit.expected_verdict,
                "commit %s expected %s but the gate returned %s (%s)"
                % (o.commit.commit_id, o.commit.expected_verdict,
                   o.verdict, o.justification))


class TestZkClassifications(unittest.TestCase):
    """Per-commit TP / FN / TN classification."""

    def test_premature_apply_bugs_are_true_positives(self):
        report = _report()
        for cid in ("ZK-001", "ZK-002"):
            o = _outcome(report, cid)
            self.assertEqual(o.verdict, BLOCK, cid)
            self.assertEqual(o.classification, TP, cid)
            self.assertIn("zab_no_premature_apply", o.blocking_violated)
            self.assertTrue(o.has_deterministic_test,
                            "%s should emit a deterministic witness" % cid)
    def test_quorum_bug_is_honest_false_negative(self):
        """ZK-003 breaks real durability but is outside the two-invariant set."""
        report = _report()
        o = _outcome(report, "ZK-003")
        self.assertEqual(o.verdict, PASS)
        self.assertEqual(o.classification, FN)
        self.assertEqual(o.blocking_violated, [])

    def test_safe_changes_are_true_negatives(self):
        report = _report()
        for cid in ("ZK-S1", "ZK-S2", "ZK-S3"):
            o = _outcome(report, cid)
            self.assertEqual(o.verdict, PASS, cid)
            self.assertEqual(o.classification, TN, cid)


class TestZkMetrics(unittest.TestCase):
    """Aggregate Step 3.7 headline metrics."""

    def test_counts(self):
        report = _report()
        self.assertEqual(report.total, 6)
        self.assertEqual(report.bugs, 3)
        self.assertEqual(report.safe, 3)
        self.assertEqual(report.true_positives, 2)
        self.assertEqual(report.detected_not_blocked, 0)
        self.assertEqual(report.false_negatives, 1)
        self.assertEqual(report.false_positives, 0)
        self.assertEqual(report.false_warnings, 0)
        self.assertEqual(report.true_negatives, 3)

    def test_ratios(self):
        report = _report()
        self.assertEqual(report.false_block_rate, 0.0)   # no safe commit blocked
        self.assertAlmostEqual(report.blocking_precision, 1.0)   # all blocks are TPs
        self.assertAlmostEqual(report.blocking_recall, 2.0 / 3.0)
        self.assertAlmostEqual(report.detection_recall, 2.0 / 3.0)
        self.assertEqual(report.bugs_detected, 2)


class TestZkReport(unittest.TestCase):
    """JSON report round-trip."""

    def test_json_roundtrip(self):
        report = _report()
        tmp = tempfile.mkdtemp(prefix="rot_zk_")
        try:
            path = report.write(tmp)
            self.assertTrue(os.path.exists(path))
            with open(path, "r") as f:
                data = json.load(f)
            self.assertEqual(data["total_commits"], 6)
            self.assertEqual(data["bug_commits"], 3)
            self.assertEqual(data["safe_commits"], 3)
            self.assertEqual(data["true_positives_blocked"], 2)
            self.assertEqual(data["false_negatives_missed"], 1)
            self.assertEqual(data["false_positives_blocked"], 0)
            self.assertEqual(data["false_block_rate"], 0.0)
            self.assertEqual(len(data["outcomes"]), 6)
            self.assertIn("verdict", data["outcomes"][0])
            self.assertIn("classification", data["outcomes"][0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()