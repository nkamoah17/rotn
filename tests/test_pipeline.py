# -*- coding: utf-8 -*-
"""End-to-end pipeline tests (symbolic engine) for the 2PC vertical slice.

These run the REAL pipeline (build IR -> property-directed abstraction ->
linearize -> symbolic engine -> CEGAR -> Verdict -> report) and assert:
  * ``correct`` + agreement  -> proven  (exit 0)
  * ``buggy``   + agreement  -> violated (exit 1) with a genuine witness
  * the auditable report (JSON + Markdown) is written and parseable
  * the CLI ``--list`` path and exit-code mapping work

The symbolic engine is used here so the tests are deterministic and do not
depend on Java/TLC being installed. Pure stdlib, Python 3.6 compatible.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pipeline  # noqa: E402
import rot.invariants as invariants  # noqa: E402


class PipelineTests(unittest.TestCase):
    def _run(self, target, prop, engine="symbolic"):
        tmp = tempfile.mkdtemp(prefix="rotn_test_")
        verdict = pipeline.run(
            target_name=target, property_name=prop, engine=engine,
            out_dir=tmp, quiet=True, max_states=200000)
        return verdict, tmp

    def _report(self, tmp, target, prop):
        jpath = os.path.join(tmp, "%s_%s.json" % (target, prop))
        mpath = os.path.join(tmp, "%s_%s.md" % (target, prop))
        self.assertTrue(os.path.isfile(jpath), "missing %s" % jpath)
        self.assertTrue(os.path.isfile(mpath), "missing %s" % mpath)
        with open(jpath, "r") as f:
            data = json.load(f)
        with open(mpath, "r") as f:
            md = f.read()
        return jpath, data, md

    def test_correct_agreement_proven(self):
        verdict, tmp = self._run("correct", "agreement")
        self.assertEqual(verdict.status, "proven")
        self.assertTrue(verdict.is_proven())
        _, data, md = self._report(tmp, "correct", "agreement")
        self.assertEqual(data["target"], "correct")
        self.assertEqual(data["property_name"], "agreement")
        self.assertEqual(data["verdict"]["status"], "proven")
        # The abstraction manifest is part of the auditable report.
        self.assertIn("abstraction", data)
        self.assertIn("Keep", md)

    def test_buggy_agreement_violated_with_witness(self):
        verdict, tmp = self._run("buggy", "agreement")
        self.assertEqual(verdict.status, "violated")
        self.assertTrue(verdict.is_violated())
        # A concrete, non-empty witness is produced.
        self.assertIsInstance(verdict.counterexample, dict)
        self.assertTrue(verdict.counterexample)
        # And the witness genuinely refutes agreement (not a spurious state).
        prop = invariants.get("agreement", 3)
        self.assertEqual(prop.expression.eval(verdict.counterexample), False)
        _, data, md = self._report(tmp, "buggy", "agreement")
        self.assertEqual(data["verdict"]["status"], "violated")
        self.assertIn("Counterexample", md)

    def test_correct_vs_buggy_discriminate(self):
        """The two targets must give different verdicts on agreement."""
        correct, _ = self._run("correct", "agreement")
        buggy, _ = self._run("buggy", "agreement")
        self.assertEqual(correct.status, "proven")
        self.assertEqual(buggy.status, "violated")

    def test_validity_property_runs(self):
        """A second pinned invariant still runs end-to-end (symbolic)."""
        verdict, tmp = self._run("correct", "validity")
        self.assertIn(verdict.status, ("proven", "violated", "unknown"))
        _, data, _ = self._report(tmp, "correct", "validity")
        self.assertEqual(data["property_name"], "validity")


class PipelineCliTests(unittest.TestCase):
    def test_exit_code_correct_is_zero(self):
        tmp = tempfile.mkdtemp(prefix="rotn_cli_")
        rc = pipeline.main(["correct", "--property", "agreement",
                            "--engine", "symbolic", "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)

    def test_exit_code_buggy_is_one(self):
        tmp = tempfile.mkdtemp(prefix="rotn_cli_")
        rc = pipeline.main(["buggy", "--property", "agreement",
                            "--engine", "symbolic", "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_VIOLATED)

    def test_list_targets(self):
        rc = pipeline.main(["--list"])
        self.assertEqual(rc, pipeline.EXIT_PROVEN)

    def test_unknown_target_is_error(self):
        rc = pipeline.main(["does_not_exist", "--engine", "symbolic"])
        self.assertEqual(rc, pipeline.EXIT_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)