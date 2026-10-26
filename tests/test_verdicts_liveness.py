# -*- coding: utf-8 -*-
"""verdicts.py -- Phase 6 liveness verdict metadata.

Tests for the ``property_kind`` / ``violation_code`` fields on the audit
verdict plane (``rot.verdicts``) and the empirical trace plane
(``rot.empirical``):

  * constructor defaults (both ``None``; omitted from the markdown);
  * validation (unknown kind / code raise ``ValueError``);
  * serialization round-trip (``to_dict`` -> ``Verdict`` -> ``to_dict``);
  * markdown carries the kind, the code, and the witness trace;
  * ``VerdictReport`` passes the metadata through to the report markdown;
  * ``cegar`` assigns ``POLICY_DENIAL`` on the safety violation path and
    ``LIVENESS_BOUND_EXCEEDED`` on the liveness ``NOT_REACHED`` path, and
    every verdict carries ``prop.kind`` as ``property_kind``;
  * ``EmpiricalResult`` defaults ``property_kind`` to ``None``, accepts and
    reports ``safety`` / ``liveness`` (rejecting anything else), and
    ``empirical.run`` passes the requested kind through to the result.

Run: python tests/test_verdicts_liveness.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rot.cegar import cegar, cegar_liveness  # noqa: E402
from rot.empirical import EmpiricalResult  # noqa: E402
from rot.invariants import KIND_LIVENESS, KIND_SAFETY, Invariant  # noqa: E402
from rot.ir import Const  # noqa: E402
from rot.symbolic import EngineResult, NOT_REACHED, ReachResult  # noqa: E402
from rot.verdicts import (  # noqa: E402
    LIVENESS_BOUND_EXCEEDED,
    POLICY_DENIAL,
    PROVEN,
    VIOLATED,
    Verdict,
    VerdictReport,
)


class _Cfg(object):
    """Minimal stand-in for ``rot.config.Config`` (fields ``cegar`` reads)."""
    cegar_max_iter = 2
    liveness_horizon = 12


def _safety_prop():
    # ``Const(False)`` is false in every concrete state, so a "violated"
    # engine result is always IR-feasible -> the real-violation path.
    return Invariant("test_safety_prop", "test safety invariant",
                     Const(False), kind=KIND_SAFETY)


def _liveness_prop():
    return Invariant("test_eventual_commit", "test liveness invariant",
                     Const(True), kind=KIND_LIVENESS)


class TestVerdictLivenessMetadata(unittest.TestCase):
    def test_defaults_are_none(self):
        v = Verdict(VIOLATED, "p", "symbolic")
        self.assertIsNone(v.property_kind)
        self.assertIsNone(v.violation_code)

    def test_fields_stored(self):
        v = Verdict(VIOLATED, "p", "symbolic",
                    property_kind=KIND_SAFETY,
                    violation_code=POLICY_DENIAL)
        self.assertEqual(v.property_kind, KIND_SAFETY)
        self.assertEqual(v.violation_code, POLICY_DENIAL)

    def test_invalid_kind_raises(self):
        with self.assertRaises(ValueError):
            Verdict(PROVEN, "p", "symbolic", property_kind="liveliness")

    def test_invalid_code_raises(self):
        with self.assertRaises(ValueError):
            Verdict(VIOLATED, "p", "symbolic", violation_code="SOMETHING_ELSE")

    def test_to_dict_round_trip(self):
        v = Verdict(VIOLATED, "no_spurious_abort", "symbolic",
                    counterexample={"aborted": True, "commit": False},
                    assumptions=["quorum stable"],
                    evidence={"checked": True},
                    n_states=42, cegar_iterations=1, note="a real bug",
                    property_kind=KIND_SAFETY,
                    violation_code=POLICY_DENIAL)
        payload = v.to_dict()
        self.assertEqual(payload["property_kind"], KIND_SAFETY)
        self.assertEqual(payload["violation_code"], "POLICY_DENIAL")

        # Round-trip through the serialized payload (incl. JSON).
        from_json = json.loads(v.to_json())
        self.assertEqual(from_json, payload)
        v2 = Verdict(payload["status"], payload["property_name"],
                     payload["engine"],
                     counterexample=payload["counterexample"],
                     assumptions=payload["assumptions"],
                     soundness=payload["soundness"],
                     evidence=payload["evidence"],
                     cegar_iterations=payload["cegar_iterations"],
                     n_states=payload["n_states"],
                     note=payload["note"],
                     property_kind=payload["property_kind"],
                     violation_code=payload["violation_code"])
        self.assertEqual(v2.to_dict(), payload)

    def test_markdown_contains_kind_code_and_witness(self):
        v = Verdict(VIOLATED, "no_spurious_abort", "symbolic",
                    counterexample={"aborted": True, "commit": False},
                    property_kind=KIND_SAFETY,
                    violation_code=POLICY_DENIAL)
        md = v.to_markdown()
        self.assertIn("Property kind: `safety`", md)
        self.assertIn("Violation code: `POLICY_DENIAL`", md)
        self.assertIn("## Counterexample", md)
        self.assertIn("aborted = True", md)
        self.assertIn("commit = False", md)

    def test_markdown_omits_absent_metadata(self):
        md = Verdict(PROVEN, "p", "symbolic").to_markdown()
        self.assertNotIn("Property kind", md)
        self.assertNotIn("Violation code", md)

    def test_report_passes_metadata_through(self):
        v = Verdict(VIOLATED, "eventual_commit", "symbolic",
                    counterexample={},
                    property_kind=KIND_LIVENESS,
                    violation_code=LIVENESS_BOUND_EXCEEDED)
        report = VerdictReport("2pc", "eventual_commit", "symbolic",
                               {}, {}, v)
        md = report.to_markdown()
        self.assertIn("Property kind: `liveness`", md)
        self.assertIn("Violation code: `LIVENESS_BOUND_EXCEEDED`", md)


class TestCegarViolationCodes(unittest.TestCase):
    def test_safety_violation_coded_policy_denial(self):
        prop = _safety_prop()
        engine_result = EngineResult("violated",
                                     witness={"aborted": True}, n_states=7)
        v = cegar(engine_result, prop, _Cfg(), "symbolic")
        self.assertEqual(v.status, VIOLATED)
        self.assertEqual(v.property_kind, KIND_SAFETY)
        self.assertEqual(v.violation_code, POLICY_DENIAL)
        self.assertEqual(v.counterexample, {"aborted": True})

    def test_safety_proven_carries_kind_without_code(self):
        engine_result = EngineResult("proven", n_states=3)
        v = cegar(engine_result, _safety_prop(), _Cfg(), "symbolic")
        self.assertEqual(v.status, PROVEN)
        self.assertEqual(v.property_kind, KIND_SAFETY)
        self.assertIsNone(v.violation_code)

    def test_liveness_not_reached_coded_bound_exceeded(self):
        prop = _liveness_prop()
        reach = ReachResult(NOT_REACHED, horizon=12)
        v = cegar_liveness(reach, prop, _Cfg(), "symbolic")
        self.assertEqual(v.status, VIOLATED)
        self.assertEqual(v.property_kind, KIND_LIVENESS)
        self.assertEqual(v.violation_code, LIVENESS_BOUND_EXCEEDED)


class TestEmpiricalPropertyKind(unittest.TestCase):
    """The empirical plane records the property kind it was asked to judge.

    ``EmpiricalResult`` defaults ``property_kind`` to ``None`` (the trace
    plane does not assume a plane unless told), accepts and reports
    ``safety`` / ``liveness``, and rejects anything else. ``empirical.run``
    passes the requested kind through to the result and the rendered report.
    """

    def _result(self, **kw):
        base = dict(
            trace="replay-1.jsonl",
            schedule=None,
            verdict="CONFORMANT",
            artifact="replay-1.jsonl.verdict.json",
            invariants=[{"name": "no_spurious_abort", "status": "ok",
                         "evidence": "trace"}],
            violations=[],
            reasons=[],
            target="twopc",
            property_name="no_spurious_abort",
            exit_code=0,
            schedule_ok=True,
            schedule_errors=[],
        )
        base.update(kw)
        return EmpiricalResult(**base)

    def test_defaults_to_none(self):
        r = self._result()
        self.assertIsNone(r.property_kind)
        self.assertIsNone(r.as_dict()["property_kind"])
        # the report omits the kind line when none was supplied
        self.assertNotIn("property kind", "\n".join(r.report_lines()))

    def test_carries_property_kind(self):
        r = self._result(property_kind=KIND_LIVENESS)
        self.assertEqual(r.property_kind, KIND_LIVENESS)
        self.assertEqual(r.as_dict()["property_kind"], KIND_LIVENESS)
        self.assertIn("property kind: liveness",
                      "\n".join(r.report_lines()))

    def test_invalid_kind_raises(self):
        with self.assertRaises(ValueError):
            self._result(property_kind="liveliness")

    def test_run_passes_kind_through(self):
        import rot.empirical as emp

        d = tempfile.mkdtemp()
        trace = os.path.join(d, "replay-1.jsonl")
        r = emp.run(trace, property_kind=KIND_LIVENESS)
        self.assertEqual(r.property_kind, KIND_LIVENESS)
        self.assertEqual(r.as_dict()["property_kind"], KIND_LIVENESS)
        self.assertIn("property kind: liveness", emp.render(r))

    def test_run_defaults_to_none(self):
        import rot.empirical as emp

        d = tempfile.mkdtemp()
        trace = os.path.join(d, "replay-1.jsonl")
        r = emp.run(trace)
        self.assertIsNone(r.property_kind)

    def test_run_invalid_kind_raises(self):
        import rot.empirical as emp

        d = tempfile.mkdtemp()
        trace = os.path.join(d, "replay-1.jsonl")
        with self.assertRaises(ValueError):
            emp.run(trace, property_kind="liveliness")


if __name__ == "__main__":
    unittest.main(verbosity=2)