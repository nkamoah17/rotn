# -*- coding: utf-8 -*-
"""Phase 3 -- reference-interpreter oracle (``rot replay --oracle dogwood``).

Verifies the "Dogwood admits it, ROTN catches it" side-by-side:

  * the pure helpers (decision parsing, summarising, the gate predicate, and
    the three gate-class fixtures) are correct -- these run with no toolchain;
  * the end-to-end gate (``run_gate``) replays the APW-1/2/4 buggy+correct
    policies + witness traces against the locally-built ``dogwood`` reference
    interpreter and asserts the gate (ROTN=VIOLATED and the buggy policy
    admits the violation on the same trace).  Skipped when the ``dogwood``
    binary is absent, matching the codebase's engine-degradation convention.

Run: python tests/test_reference_replay.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.oracle as oracle  # noqa: E402


class OracleHelperTests(unittest.TestCase):
    """Pure helpers -- no toolchain required."""

    def test_parse_decisions_extracts_seq_timepoint_decision(self):
        raw = ("@0 (time point 0): ALLOW  [rules: 0]\n"
               "@2 (time point 1): DENY\n"
               "some other line\n"
               "@4 (time point 2): DENY")
        got = oracle.parse_decisions(raw)
        self.assertEqual(
            got,
            [{"seq": 0, "timepoint": 0, "decision": "ALLOW"},
             {"seq": 2, "timepoint": 1, "decision": "DENY"},
             {"seq": 4, "timepoint": 2, "decision": "DENY"}])

    def test_parse_decisions_ignores_noise(self):
        self.assertEqual(oracle.parse_decisions("no decisions here"), [])
        self.assertEqual(oracle.parse_decisions(""), [])

    def test_summarize_counts_admitted_and_denied(self):
        d = [{"decision": "ALLOW"}, {"decision": "DENY"},
             {"decision": "DENY"}]
        s = oracle.summarize(d)
        self.assertEqual(s["n_decisions"], 3)
        self.assertEqual(s["n_admitted"], 1)
        self.assertEqual(s["n_denied"], 2)
        self.assertTrue(s["admitted_any"])
        self.assertTrue(s["denied_any"])

    def test_side_by_side_gate_requires_both_legs(self):
        admits = {"ok": True, "error": None, "decisions": [
            {"seq": 0, "timepoint": 0, "decision": "ALLOW"}],
            "raw": "", "exit": 0}
        denies = {"ok": True, "error": None, "decisions": [
            {"seq": 0, "timepoint": 0, "decision": "DENY"}],
            "raw": "", "exit": 0}
        ok = oracle.side_by_side("violated", {"inflight": 3}, "p", admits)
        self.assertTrue(ok["gate"]["agreement"])
        no = oracle.side_by_side("violated", {"inflight": 3}, "p", denies)
        self.assertFalse(no["gate"]["agreement"])
        no2 = oracle.side_by_side("proven", None, "p", admits)
        self.assertFalse(no2["gate"]["agreement"])
        self.assertTrue(no2["gate"]["reference_admitted"])
        self.assertFalse(no2["gate"]["rot_violated"])

    def test_gate_classes_are_three_and_point_at_existing_files(self):
        classes = oracle.gate_classes()
        self.assertEqual([c["apw"] for c in classes],
                         ["APW-1", "APW-2", "APW-4"])
        for c in classes:
            for key in ("buggy", "correct", "trace", "schema"):
                self.assertTrue(
                    os.path.isfile(c[key]),
                    "missing %s for %s: %s" % (key, c["apw"], c[key]))

    def test_gate_fixtures_lower_to_their_apw_class(self):
        """The gate proves what it claims: each gate class's buggy fixture
        must lower to *that* APW class's protocol.

        Regression: the APW-2 row pointed at ``apw2-permit-buggy.dw`` (the
        Classmethod ``formerly within <approval-event>`` gating shape) while
        the dispatcher classified that shape as taint-egress (APW-3) -- the
        gate "passed" APW-2 by proving the *wrong* bug class.  This test
        pins the fixture-to-class mapping the gate relies on.
        """
        from rot.dw import parse_file
        expected = {
            "APW-1": "SPENDCAP",
            "APW-2": "APPROVAL_REPLAY",
            "APW-4": "DISTINCT_COUNT",
        }
        for c in oracle.gate_classes():
            ir = parse_file(c["buggy"]).to_ir()
            self.assertEqual(
                ir.metadata.get("protocol"), expected[c["apw"]],
                "%s gate fixture %s lowers to the wrong class (protocol=%r)"
                % (c["apw"], os.path.basename(c["buggy"]),
                   ir.metadata.get("protocol")))
            self.assertEqual(ir.metadata.get("buggy"), True,
                             "%s gate fixture must be the buggy variant"
                             % c["apw"])



@unittest.skipIf(oracle.find_dogwood() is None,
                 "dogwood reference binary not present (Phase-0 build absent)")
class ReferenceReplayGateTests(unittest.TestCase):
    """End-to-end: replay the gate classes against the reference interpreter."""

    @classmethod
    def setUpClass(cls):
        cls.binary = oracle.find_dogwood()
        cls.reports = oracle.run_gate(cls.binary)
        cls.by_apw = {r["apw"]: r for r in cls.reports}

    def test_gate_classes_present(self):
        self.assertEqual(set(self.by_apw), {"APW-1", "APW-2", "APW-4"})

    def test_each_class_rotn_is_violated(self):
        for apw in ("APW-1", "APW-2", "APW-4"):
            r = self.by_apw[apw]
            self.assertEqual(
                r["rot"]["verdict"], "violated",
                "%s ROTN verdict: %s" % (apw, r["rot"]))

    def test_each_buggy_policy_admits_in_the_reference(self):
        for apw in ("APW-1", "APW-2", "APW-4"):
            r = self.by_apw[apw]
            self.assertTrue(
                r["dogwood_reference_buggy"]["admitted_any"],
                "%s buggy policy did not admit in the reference: %s"
                % (apw, r["dogwood_reference_buggy"]))

    def test_gate_agrees(self):
        self.assertTrue(
            oracle.gate_passed(self.reports),
            "gate failed: %s" % [(r["apw"], r["gate"]) for r in self.reports])

    def test_apw1_correct_policy_denies_in_the_reference(self):
        """The corrected APW-1 (request-sum) enforces the cap in the
        reference: the 4th request is denied."""
        ref = self.by_apw["APW-1"]["dogwood_reference_correct"]
        self.assertTrue(ref["denied_any"])
        self.assertIn(3, ref["denied_timepoints"])

    def test_apw2_correct_policy_consumes_the_approval(self):
        """The corrected APW-2 admits exactly one order then denies the
        replayed ones (approval consumed)."""
        ref = self.by_apw["APW-2"]["dogwood_reference_correct"]
        self.assertEqual(ref["n_admitted"], 1)
        self.assertEqual(ref["n_denied"], 3)

    def test_apw4_buggy_admits_all_recipients(self):
        """The buggy APW-4 (settled-only counter) admits the whole
        cross-recipient in-flight burst in the reference."""
        ref = self.by_apw["APW-4"]["dogwood_reference_buggy"]
        self.assertEqual(ref["n_admitted"], 4)
        self.assertEqual(ref["n_denied"], 0)

    def test_render_markdown_contains_gate_and_caveats(self):
        md = oracle.render_markdown(self.reports, binary=self.binary)
        self.assertIn("Gate: PASS", md)
        self.assertIn("APW-1", md)
        self.assertIn("APW-2", md)
        self.assertIn("APW-4", md)
        self.assertIn("default-deny", md)
        self.assertIn("partition guarantee", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
