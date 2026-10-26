# -*- coding: utf-8 -*-
"""Tests for ``rot.itf`` -- the Apalache ITF trace parser and ``apalache`` engine.

Covers:
  * ``parse_itf`` on the ``states``-layout fixtures (``violation.itf.json``,
    ``other_spec.itf.json``) and on the legacy ``init``/``action``/``state``
    layout (written inline to a temp file)
  * ``ItfTrace`` normalization (``#meta`` stripping, ``init``/``final_state``,
    ``vars``, ``to_dict`` JSON-serializability) and parse-error handling
  * ``ItfEngine.check()``: a definite refutation of ``agreement`` on the
    violation fixture, ``unknown`` on a trace that never refutes (a single
    concrete path can refute but never prove), ``error`` with no trace
  * ``Config`` round-trip with ``itf_trace`` and ``select_engine()``
  * the REAL pipeline: ``pipeline.run(engine="apalache", itf_trace=...)`` and
    the CLI (``--engine apalache --itf ...``) exit-code mapping
  * the standalone CLI (``python -m rot.itf``)

Pure stdlib, Python 3.6 compatible.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pipeline  # noqa: E402
import rot.invariants as invariants  # noqa: E402
from rot import itf  # noqa: E402
from rot.config import Config  # noqa: E402

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
VIOLATION = os.path.join(_FIXTURES, "violation.itf.json")
OTHER_SPEC = os.path.join(_FIXTURES, "other_spec.itf.json")

_AGREEMENT = invariants.get("agreement", 3)


def _write_json(obj):
    """Write ``obj`` to a temp file and return its path."""
    tmp = tempfile.mkdtemp(prefix="rotn_itf_")
    path = os.path.join(tmp, "trace.itf.json")
    with open(path, "w") as f:
        json.dump(obj, f)
    return path


def _legacy_fixture():
    """A legacy-layout ITF trace: init + one transition to a violating state."""
    def pairs(d):
        return [{"var": k, "value": v} for k, v in sorted(d.items())]
    init = {"applied_1": "none", "applied_2": "none", "applied_3": "none",
            "decision": "none", "phase": "prepare",
            "vote_1": "none", "vote_2": "none", "vote_3": "none"}
    post = {"applied_1": "commit", "applied_2": "abort", "applied_3": "none",
            "decision": "abort", "phase": "decided",
            "vote_1": "yes", "vote_2": "no", "vote_3": "no"}
    return {
        "#meta": {"format": "ITF"},
        "vars": sorted(init.keys()),
        "init": pairs(init),
        "action": [pairs(init)],
        "state": [pairs(post)],
    }


class ParseItfTests(unittest.TestCase):
    def test_states_layout_fixture(self):
        trace = itf.parse_itf(VIOLATION)
        self.assertEqual(trace.format_variant, "states")
        self.assertEqual(len(trace.states), 7)
        self.assertEqual(trace.vars, [
            "vote_1", "vote_2", "vote_3",
            "applied_1", "applied_2", "applied_3",
            "decision", "phase"])
        # Per-state #meta blocks are stripped; the top-level meta is kept.
        for st in trace.states:
            self.assertNotIn("#meta", st)
        self.assertEqual(trace.meta.get("format"), "ITF")
        self.assertEqual(trace.source_path, VIOLATION)

    def test_init_and_final_state(self):
        trace = itf.parse_itf(VIOLATION)
        self.assertEqual(trace.init, trace.states[0])
        self.assertEqual(trace.final_state, trace.states[-1])
        self.assertEqual(trace.init["phase"], "prepare")
        self.assertEqual(trace.final_state["applied_1"], "commit")
        self.assertEqual(trace.final_state["applied_2"], "abort")

    def test_single_state_fixture(self):
        trace = itf.parse_itf(OTHER_SPEC)
        self.assertEqual(trace.format_variant, "states")
        self.assertEqual(len(trace.states), 1)
        self.assertEqual(trace.vars, ["phase"])
        self.assertEqual(trace.init, {"phase": "prepare"})
        self.assertEqual(trace.final_state, trace.init)

    def test_legacy_layout_normalized(self):
        path = _write_json(_legacy_fixture())
        trace = itf.parse_itf(path)
        self.assertEqual(trace.format_variant, "legacy")
        # Normalized to [init] + post-states, all plain dicts.
        self.assertEqual(len(trace.states), 2)
        self.assertEqual(trace.states[0]["phase"], "prepare")
        self.assertEqual(trace.states[1]["applied_1"], "commit")
        self.assertEqual(trace.states[1]["applied_2"], "abort")
        self.assertNotIn("#meta", trace.states[0])

    def test_trace_rejects_empty_states(self):
        self.assertRaises(itf.ItfError, itf.ItfTrace, [], [])

    def test_to_dict_is_json_serializable(self):
        d = itf.parse_itf(VIOLATION).to_dict()
        self.assertEqual(d["n_states"], 7)
        self.assertEqual(d["format"], "states")
        json.dumps(d)  # must not raise

    def test_error_missing_file(self):
        self.assertRaises(itf.ItfError, itf.parse_itf,
                          os.path.join(_FIXTURES, "missing.itf.json"))

    def test_error_invalid_json(self):
        tmp = tempfile.mkdtemp(prefix="rotn_itf_")
        path = os.path.join(tmp, "bad.itf.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        self.assertRaises(itf.ItfError, itf.parse_itf, path)

    def test_error_root_not_object(self):
        path = _write_json([1, 2, 3])
        self.assertRaises(itf.ItfError, itf.parse_itf, path)

    def test_error_empty_states(self):
        path = _write_json({"states": []})
        self.assertRaises(itf.ItfError, itf.parse_itf, path)

    def test_error_no_known_layout(self):
        path = _write_json({"#meta": {"format": "ITF"}})
        self.assertRaises(itf.ItfError, itf.parse_itf, path)

    def test_error_legacy_missing_arrays(self):
        legacy = _legacy_fixture()
        del legacy["state"]
        path = _write_json(legacy)
        self.assertRaises(itf.ItfError, itf.parse_itf, path)


class ItfEngineTests(unittest.TestCase):
    def test_refutes_agreement_with_witness(self):
        eng = itf.ItfEngine(None, trace_path=VIOLATION)
        res = eng.check(None, _AGREEMENT)
        self.assertEqual(res.status, "violated")
        self.assertEqual(res.n_states, 7)
        # A concrete witness that genuinely refutes the invariant.
        self.assertIsInstance(res.witness, dict)
        self.assertEqual(_AGREEMENT.expression.eval(res.witness), False)
        self.assertEqual(res.witness["applied_1"], "commit")
        self.assertEqual(res.witness["applied_2"], "abort")

    def test_holding_trace_reports_unknown(self):
        """A trace that never refutes must be unknown, never proven."""
        eng = itf.ItfEngine(None, trace_path=OTHER_SPEC)
        res = eng.check(None, _AGREEMENT)
        self.assertEqual(res.status, "unknown")
        self.assertIsNone(res.witness)

    def test_legacy_trace_refutes(self):
        path = _write_json(_legacy_fixture())
        eng = itf.ItfEngine(None, trace_path=path)
        res = eng.check(None, _AGREEMENT)
        self.assertEqual(res.status, "violated")
        self.assertEqual(res.witness["applied_1"], "commit")

    def test_trace_from_config(self):
        cfg = Config(engine="apalache", itf_trace=VIOLATION)
        res = itf.ItfEngine(cfg).check(None, _AGREEMENT)
        self.assertEqual(res.status, "violated")

    def test_no_trace_configured_is_error(self):
        eng = itf.ItfEngine(None)
        res = eng.check(None, _AGREEMENT)
        self.assertEqual(res.status, "error")
        self.assertIn("no ITF trace", res.note)

    def test_unreadable_trace_is_error(self):
        eng = itf.ItfEngine(
            None, trace_path=os.path.join(_FIXTURES, "missing.itf.json"))
        res = eng.check(None, _AGREEMENT)
        self.assertEqual(res.status, "error")

    def test_target_arg_accepted(self):
        """``check(model, prop, target)`` matches the other engines' contract."""
        eng = itf.ItfEngine(None, trace_path=VIOLATION)
        res = eng.check(None, _AGREEMENT, target="correct")
        self.assertEqual(res.status, "violated")


class ConfigApalacheTests(unittest.TestCase):
    def test_select_engine_apalache(self):
        self.assertEqual(Config(engine="apalache").select_engine(), "apalache")

    def test_itf_trace_default_none(self):
        self.assertIsNone(Config().itf_trace)

    def test_itf_trace_round_trip(self):
        cfg = Config(engine="apalache", itf_trace=VIOLATION)
        d = cfg.to_dict()
        self.assertEqual(d["engine"], "apalache")
        self.assertEqual(d["resolved_engine"], "apalache")
        self.assertEqual(d["itf_trace"], VIOLATION)
        cfg2 = Config.from_dict(d)
        self.assertEqual(cfg2.engine, "apalache")
        self.assertEqual(cfg2.itf_trace, VIOLATION)
        self.assertEqual(cfg2.select_engine(), "apalache")


class PipelineApalacheTests(unittest.TestCase):
    """End-to-end: the real pipeline with engine='apalache'."""

    def _run(self, fixture):
        tmp = tempfile.mkdtemp(prefix="rotn_itf_")
        verdict = pipeline.run(
            target_name="correct", property_name="agreement",
            engine="apalache", itf_trace=fixture,
            out_dir=tmp, quiet=True)
        return verdict, tmp

    def test_violation_trace_violated_with_report(self):
        verdict, tmp = self._run(VIOLATION)
        self.assertEqual(verdict.status, "violated")
        self.assertTrue(verdict.is_violated())
        # A genuine witness: it refutes agreement when re-evaluated.
        self.assertIsInstance(verdict.counterexample, dict)
        self.assertEqual(
            _AGREEMENT.expression.eval(verdict.counterexample), False)
        # The auditable report names the engine and the trace.
        jpath = os.path.join(tmp, "correct_agreement.json")
        with open(jpath, "r") as f:
            data = json.load(f)
        self.assertEqual(data["target"], "correct")
        self.assertEqual(data["engine"], "apalache")
        self.assertEqual(data["config"]["itf_trace"], VIOLATION)
        self.assertEqual(data["verdict"]["status"], "violated")

    def test_holding_trace_unknown(self):
        verdict, _ = self._run(OTHER_SPEC)
        self.assertEqual(verdict.status, "unknown")

    def test_cli_exit_codes(self):
        tmp = tempfile.mkdtemp(prefix="rotn_itf_cli_")
        rc = pipeline.main(["correct", "--property", "agreement",
                            "--engine", "apalache", "--itf", VIOLATION,
                            "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_VIOLATED)
        rc = pipeline.main(["correct", "--property", "agreement",
                            "--engine", "apalache", "--itf", OTHER_SPEC,
                            "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_UNKNOWN)
        # No --itf at all: the engine reports an error -> exit 3.
        rc = pipeline.main(["correct", "--property", "agreement",
                            "--engine", "apalache",
                            "--out", tmp, "--quiet"])
        self.assertEqual(rc, pipeline.EXIT_ERROR)


class StandaloneCliTests(unittest.TestCase):
    """``python -m rot.itf``: 0 = holds/UNDEF, 10 = refuted, 2 = usage error."""

    def test_refuted_trace_exits_10(self):
        self.assertEqual(itf.main([VIOLATION]), 10)

    def test_holding_trace_exits_0(self):
        self.assertEqual(itf.main([OTHER_SPEC]), 0)

    def test_bad_path_exits_2(self):
        self.assertEqual(
            itf.main([os.path.join(_FIXTURES, "missing.itf.json")]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)