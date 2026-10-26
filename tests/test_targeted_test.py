# -*- coding: utf-8 -*-
"""tests/test_targeted_test.py -- tests for rot/targeted_test.py (Step 3.5).

Verifies that a ``SpecDiff``/``GateImpact`` pair (the Step 3 output) is turned
into a targeted suite of W3 replay schedules with:

  * correct expected verdicts (a pure-Python replay oracle that discriminates
    baseline compliance from candidate violation),
  * emitted JSONL + manifest that match the W3/W4 pipeline contract, and
  * schedules that map back to the impacted actions / witness steps.

Run:
    python -m unittest tests.test_targeted_test -v
"""
import io
import json
import os
import shutil
import tempfile
import unittest

import rot.targets as targets
import rot.witness as witness
from rot.ir import ProtocolIR
from rot.targeted_test import (
    VERDICT_COMPLIANCE,
    VERDICT_VIOLATION,
    analyze_targeted,
    replay_schedule,
    write_suite,
)

# A unanimous 2PC run (n=2): everyone votes yes, coordinator commits, both apply.
# This is a valid control path that must stay compliant on baseline and candidate.
_CONTROL_2PC = ["vote_1_yes", "vote_2_yes", "decide", "apply_1", "apply_2"]


class ReplayOracleTest(unittest.TestCase):
    """replay_schedule must compute the right verdict per target + path."""

    def setUp(self):
        self.n = 2
        self.correct = targets.build("correct", self.n)
        self.buggy = targets.build("buggy", self.n)
        self.prop = targets.get_property(
            "buggy", targets.default_property("buggy"), n=self.n).expression
        wres = witness.find_witness("buggy", "agreement", n=self.n)
        self.witness_path = wres["path"]
        self.assertTrue(self.witness_path, "expected a witness for buggy/2pc")

    def test_witness_violates_on_candidate(self):
        self.assertEqual(
            replay_schedule(self.buggy, self.prop, self.witness_path)["verdict"],
            VERDICT_VIOLATION)

    def test_witness_complies_on_baseline(self):
        self.assertEqual(
            replay_schedule(self.correct, self.prop, self.witness_path)["verdict"],
            VERDICT_COMPLIANCE)

    def test_control_complies_on_both(self):
        self.assertEqual(
            replay_schedule(self.correct, self.prop, _CONTROL_2PC)["verdict"],
            VERDICT_COMPLIANCE)
        self.assertEqual(
            replay_schedule(self.buggy, self.prop, _CONTROL_2PC)["verdict"],
            VERDICT_COMPLIANCE)

    def test_replay_reports_full_result(self):
        r = replay_schedule(self.buggy, self.prop, self.witness_path)
        for key in ("verdict", "state", "applied", "skipped", "property_value"):
            self.assertIn(key, r)
        self.assertIsInstance(r["applied"], list)
        self.assertIsInstance(r["skipped"], list)
        self.assertIsInstance(r["state"], dict)


class GenerateSuiteTest(unittest.TestCase):
    """analyze_targeted must yield a discriminating suite of schedules."""

    def setUp(self):
        self.before, self.after, self.sd, self.gi, self.schedules = \
            analyze_targeted("correct", "buggy", n=2)

    def test_returns_protocolirs(self):
        self.assertIsInstance(self.before, ProtocolIR)
        self.assertIsInstance(self.after, ProtocolIR)

    def test_suite_has_witness_and_control(self):
        cases = [s.case for s in self.schedules]
        self.assertIn("witness", cases)
        self.assertIn("control", cases)

    def test_witness_detects_regression(self):
        w = [s for s in self.schedules if s.case == "witness"][0]
        self.assertEqual(w.before_verdict, VERDICT_COMPLIANCE)
        self.assertEqual(w.after_verdict, VERDICT_VIOLATION)
        self.assertTrue(w.detects_regression)
        # the buggy 2PC change touches both apply actions
        self.assertIn("apply_1", w.changed_actions)
        self.assertIn("apply_2", w.changed_actions)
        self.assertTrue(w.impacted_step_indices)

    def test_control_stays_compliant(self):
        c = [s for s in self.schedules if s.case == "control"][0]
        self.assertEqual(c.before_verdict, VERDICT_COMPLIANCE)
        self.assertEqual(c.after_verdict, VERDICT_COMPLIANCE)
        self.assertFalse(c.detects_regression)

    def test_schedules_are_unique(self):
        ids = [s.schedule_id for s in self.schedules]
        self.assertEqual(len(ids), len(set(ids)))


class WriteSuiteTest(unittest.TestCase):
    """write_suite must emit W3/W4-compatible files + a manifest."""

    def setUp(self):
        self.before, self.after, self.sd, self.gi, self.schedules = \
            analyze_targeted("correct", "buggy", n=2)
        self.n = 2
        self.tmp = tempfile.mkdtemp(prefix="rotn_tt_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_emits_files_and_manifest(self):
        write_suite(self.schedules, self.tmp, "correct", "buggy", "agreement",
                    self._prop(), self.n)

        with io.open(os.path.join(self.tmp, "manifest.json"),
                     encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["suite"], "rotn-targeted-test")
        self.assertEqual(manifest["n_schedules"], len(self.schedules))
        self.assertEqual(manifest["before"], "correct")
        self.assertEqual(manifest["after"], "buggy")
        self.assertEqual(len(manifest["schedules"]), len(self.schedules))

        for s in self.schedules:
            fp = os.path.join(self.tmp, s.schedule_id + ".jsonl")
            self.assertTrue(os.path.exists(fp), "missing %s" % fp)
            expected_lines = 1 + len(witness.witness_to_schedule(s.path))
            self.assertEqual(self._n_lines(fp), expected_lines)

    def test_schedule_file_contract(self):
        write_suite(self.schedules, self.tmp, "correct", "buggy", "agreement",
                    self._prop(), self.n)
        with io.open(os.path.join(self.tmp, "witness.jsonl"),
                     encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        header = json.loads(lines[0])
        self.assertEqual(header["_meta"], "rotn-schedule")
        self.assertEqual(header["target"], "buggy")
        self.assertEqual(header["property"], "agreement")
        self.assertEqual(header["n_steps"], len(lines) - 1)
        wpath = [s.path for s in self.schedules if s.case == "witness"][0]
        self.assertEqual(header["witness_path"], wpath)
        for i, ln in enumerate(lines[1:]):
            obj = json.loads(ln)
            self.assertIn("owner", obj)
            self.assertIn("action", obj)
            self.assertEqual(obj["step"], i)

    # -- helpers -----------------------------------------------------------
    def _prop(self):
        return targets.get_property(
            "buggy", targets.default_property("buggy"), n=self.n).expression

    @staticmethod
    def _n_lines(path):
        with io.open(path, encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())


if __name__ == "__main__":
    unittest.main()