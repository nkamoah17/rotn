# Copyright (c) KAMANU. All rights reserved.
"""Phase 5: SAFE / UNSAFE classification of spend-cap policies.

The spend-cap slice has two endpoints -- ``spendcap-correct`` (SAFE: the sum
quantifies over ``request`` rows, so in-flight fires are charged against the
cap) and ``spendcap-buggy`` (UNSAFE: the sum quantifies over ``response``
rows, so in-flight fires are invisible and a parallel burst overshoots the
cap).  Phase 5 turns that separation into a *classifier*: given a spend-cap
policy, report ``SAFE`` or ``UNSAFE`` (with a concrete counterexample witness
for UNSAFE), and -- the point of the exercise -- show that the same sound
core classifies *unseen* corpus policies (filters, thresholds, forbid/permit
shapes) with no per-policy tuning.

These tests pin the classifier's verdicts on the five first-class policies in
``tests/fixtures/aws_dogwood/spendcap/policies/``:

  * ``spendcap-correct.dw``            SAFE   (request-sum, the endpoint)
  * ``spendcap-buggy.dw``              UNSAFE (response-sum, the endpoint)
  * ``spendcap-resolved-filter.dw``    UNSAFE (response-sum + ``a > 0`` filter;
                                        promoted from corpus 0299)
  * ``spendcap-resolved-range-filter.dw`` UNSAFE (response-sum + range filter;
                                        promoted from corpus 0301)
  * ``spendcap-inflight-filter.dw``    SAFE   (request-sum + ``a > 0`` filter;
                                        the SAFE mirror of 0299)

and lock the ``--classify`` CLI contract (exit codes, the
``classify_report.json`` schema, and the no-policy error path).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import rot.frontends.policy as policy_fe
from rot.modelfind import ModelFinder

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_POLICIES = os.path.join(_REPO_ROOT, "tests", "fixtures", "aws_dogwood",
                         "spendcap", "policies")


def _classify(policy_path, max_inflight=3):
    """Classify one spend-cap policy; return (verdict, witness, event_kind).

    ``verdict`` is ``"SAFE"`` / ``"UNSAFE"`` / ``"UNKNOWN"``; ``witness`` is
    the counterexample state for UNSAFE (else ``None``); ``event_kind`` is
    the event the sum quantifies over (``"request"`` / ``"response"``).
    """
    ir = policy_fe.build_ir(policy_path, max_inflight=max_inflight)
    assert ir.metadata.get("property_kind") == "safety"
    mf = ModelFinder.from_ir(ir)
    result, witness = mf.forall_reachable(
        lambda s: ir.pinned_property.eval(s))
    if result is True:
        verdict = "SAFE"
    elif result is False:
        verdict = "UNSAFE"
    else:
        verdict = "UNKNOWN"
    return verdict, witness, ir.metadata.get("dw_event_kind")


class ClassifyCoreTests(unittest.TestCase):
    """The classifier separates the two endpoints and generalizes to unseen
    corpus policies (filters / forbid-permit shapes) with no per-policy
    tuning."""

    def test_correct_endpoint_is_safe(self):
        verdict, witness, kind = _classify(
            os.path.join(_POLICIES, "spendcap-correct.dw"))
        self.assertEqual(verdict, "SAFE")
        self.assertIsNone(witness, "SAFE must carry no counterexample")
        self.assertEqual(kind, "request")

    def test_buggy_endpoint_is_unsafe_with_witness(self):
        verdict, witness, kind = _classify(
            os.path.join(_POLICIES, "spendcap-buggy.dw"))
        self.assertEqual(verdict, "UNSAFE")
        self.assertEqual(kind, "response")
        self.assertIsNotNone(witness, "UNSAFE must carry a witness")
        self.assertEqual(witness, {"completed": 0, "inflight": 3},
                         "the parallel-fire signature: no settlement, 3 in-flight")

    def test_unseen_resolved_filter_is_unsafe(self):
        """0299 (response-sum + ``a > 0`` filter): UNSAFE, same witness as the
        buggy endpoint -- the filter does not change the verdict."""
        verdict, witness, kind = _classify(
            os.path.join(_POLICIES, "spendcap-resolved-filter.dw"))
        self.assertEqual(verdict, "UNSAFE")
        self.assertEqual(kind, "response")
        self.assertEqual(witness, {"completed": 0, "inflight": 3})

    def test_unseen_resolved_range_filter_is_unsafe(self):
        """0301 (response-sum + range filter): UNSAFE, same witness."""
        verdict, witness, kind = _classify(
            os.path.join(_POLICIES, "spendcap-resolved-range-filter.dw"))
        self.assertEqual(verdict, "UNSAFE")
        self.assertEqual(kind, "response")
        self.assertEqual(witness, {"completed": 0, "inflight": 3})

    def test_unseen_inflight_filter_is_safe(self):
        """The request-sum mirror of 0299 (``a > 0`` filter): SAFE -- the
        mirror of spendcap-resolved-filter.dw with ``request`` in place of
        ``response``."""
        verdict, witness, kind = _classify(
            os.path.join(_POLICIES, "spendcap-inflight-filter.dw"))
        self.assertEqual(verdict, "SAFE")
        self.assertIsNone(witness)
        self.assertEqual(kind, "request")

    def test_event_kind_drives_the_verdict(self):
        """The classification is driven by the event kind the sum quantifies
        over, not by the filter or the threshold: every ``response``-sum
        policy is UNSAFE and every ``request``-sum policy is SAFE."""
        for name, expected in [
            ("spendcap-correct.dw", "SAFE"),
            ("spendcap-buggy.dw", "UNSAFE"),
            ("spendcap-resolved-filter.dw", "UNSAFE"),
            ("spendcap-resolved-range-filter.dw", "UNSAFE"),
            ("spendcap-inflight-filter.dw", "SAFE"),
        ]:
            with self.subTest(policy=name):
                verdict, _witness, kind = _classify(
                    os.path.join(_POLICIES, name))
                self.assertEqual(verdict, expected)
                if expected == "SAFE":
                    self.assertEqual(kind, "request")
                else:
                    self.assertEqual(kind, "response")



class ClassifyCliTests(unittest.TestCase):
    """The ``--classify`` CLI contract: exit codes, the
    ``classify_report.json`` schema, and the no-policy error path."""

    @staticmethod
    def _cmd(policies, out_dir):
        cmd = [sys.executable, os.path.join(_REPO_ROOT, "pipeline.py"),
               "--classify", "--max-inflight", "3", "--out", out_dir,
               "--quiet"]
        for p in policies:
            cmd += ["--policies", p]
        return cmd

    def _run(self, policies):
        out_dir = tempfile.mkdtemp(prefix="rotn_classify_")
        try:
            proc = subprocess.run(self._cmd(policies, out_dir),
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=180)
            report = None
            rpath = os.path.join(out_dir, "classify_report.json")
            if os.path.exists(rpath):
                with open(rpath, encoding="utf-8") as f:
                    report = json.load(f)
            return proc.returncode, report, proc
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_all_safe_exits_0(self):
        rc, report, _ = self._run([
            os.path.join(_POLICIES, "spendcap-correct.dw"),
            os.path.join(_POLICIES, "spendcap-inflight-filter.dw"),
        ])
        self.assertEqual(rc, 0, "all-SAFE classify must exit 0")
        self.assertEqual(report["summary"]["safe"], 2)
        self.assertEqual(report["summary"]["unsafe"], 0)
        for r in report["results"]:
            self.assertEqual(r["verdict"], "SAFE")
            self.assertIsNone(r["witness"])

    def test_any_unsafe_exits_1_with_witness(self):
        rc, report, _ = self._run([
            os.path.join(_POLICIES, "spendcap-correct.dw"),
            os.path.join(_POLICIES, "spendcap-buggy.dw"),
        ])
        self.assertEqual(rc, 1, "any-UNSAFE classify must exit 1")
        self.assertEqual(report["summary"]["safe"], 1)
        self.assertEqual(report["summary"]["unsafe"], 1)
        by_name = {os.path.basename(r["policy"]): r for r in report["results"]}
        self.assertEqual(by_name["spendcap-buggy.dw"]["verdict"], "UNSAFE")
        self.assertEqual(by_name["spendcap-buggy.dw"]["witness"],
                         {"completed": 0, "inflight": 3})
        self.assertEqual(by_name["spendcap-correct.dw"]["verdict"], "SAFE")

    def test_report_schema(self):
        """The report carries the D5 schema: per-policy verdict + witness +
        event kind, and a summary."""
        _rc, report, _ = self._run([
            os.path.join(_POLICIES, "spendcap-resolved-filter.dw"),
        ])
        self.assertEqual(report["n_steps"], 1)
        self.assertEqual(report["max_inflight"], 3)
        r = report["results"][0]
        for key in ("policy", "verdict", "witness", "property",
                    "event_kind", "error"):
            self.assertIn(key, r, "report entry missing %r" % key)
        self.assertEqual(r["property"], "spendcap_within_cap")
        self.assertEqual(r["event_kind"], "response")
        self.assertEqual(r["verdict"], "UNSAFE")
        self.assertEqual(report["summary"],
                         {"safe": 0, "unsafe": 1, "unknown": 0, "error": 0})

    def test_single_policy_flag(self):
        """``--classify --policy A.dw`` (the single-policy form) works."""
        out_dir = tempfile.mkdtemp(prefix="rotn_classify_")
        try:
            cmd = [sys.executable, os.path.join(_REPO_ROOT, "pipeline.py"),
                   "--classify", "--policy",
                   os.path.join(_POLICIES, "spendcap-buggy.dw"),
                   "--max-inflight", "3", "--out", out_dir, "--quiet"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=180)
            self.assertEqual(proc.returncode, 1)
            with open(os.path.join(out_dir, "classify_report.json"),
                      encoding="utf-8") as f:
                report = json.load(f)
            self.assertEqual(report["summary"]["unsafe"], 1)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

    def test_no_policy_errors(self):
        """``--classify`` with no policies is a clean error (exit 3)."""
        out_dir = tempfile.mkdtemp(prefix="rotn_classify_")
        try:
            cmd = [sys.executable, os.path.join(_REPO_ROOT, "pipeline.py"),
                   "--classify", "--out", out_dir]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(proc.returncode, 3,
                             "no-policy classify must exit EXIT_ERROR (3)")
            self.assertIn(b"needs at least one policy", proc.stderr)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

