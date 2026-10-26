# -*- coding: utf-8 -*-
"""Tests for the OPTIONAL, NON-SOUND LLM baseline (rot/llm_baseline.py).

Invariants under test:
  * the baseline NEVER raises -- every failure path folds into a report dict
    carrying a `disclaimer`, with status in {skipped, ok, unavailable, error}
  * disabled -> a clear `skipped` no-op
  * enabled with no API key -> `unavailable` (offline, deterministic)
  * (fake client) valid JSON -> `ok` with parsed fields
  * (fake client) garbage -> `ok` with empty fields; raising client -> `error`
  * the pipeline flag is OPT-IN and NEVER changes the verdict / exit code
  * config defaults are off (llm_enabled False, no model)

Pure stdlib, Python 3.6 compatible. Run: python tests/test_llm_baseline.py
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.config as config  # noqa: E402
import rot.llm_baseline as llm  # noqa: E402
import pipeline  # noqa: E402

_LLM_ENV_VARS = ("OPENAI_API_KEY", "LLM_BASE_URL", "LLM_MODEL")


def _cfg(**over):
    d = dict(llm_enabled=True, llm_model="test-model",
             llm_base_url="http://test.invalid")
    d.update(over)
    return config.Config(**d)


class FakeClient(object):
    """Test double for the LLM transport.

    Implements the tiny client protocol that ``llm_baseline`` depends on --
    ``available()`` and ``complete(prompt)`` -- so the driver can be exercised
    end-to-end without any network access.
    """

    def __init__(self, response=None, raise_exc=None, available=True):
        self._response = response
        self._raise = raise_exc
        self._available = available
        self.prompts = []

    def available(self):
        return self._available

    def complete(self, prompt):
        self.prompts.append(prompt)
        if self._raise is not None:
            raise self._raise
        return self._response


def _save_and_clear_llm_env():
    saved = {}
    for var in _LLM_ENV_VARS:
        if var in os.environ:
            saved[var] = os.environ.pop(var)
    return saved


def _restore_llm_env(saved):
    os.environ.update(saved)


class LlmBaselinePureTests(unittest.TestCase):
    """Unit tests that never touch the network (a fake client is injected)."""

    def test_disabled_is_a_clear_noop(self):
        rep = llm.llm_baseline(_cfg(llm_enabled=False), "SPEC", ["agreement"],
                               "proven")
        self.assertEqual(rep["status"], "skipped")
        self.assertIn("disclaimer", rep)
        self.assertIsNone(rep.get("raw"))

    def test_unavailable_without_api_key(self):
        # A client that reports itself unavailable (e.g. no API key) folds to
        # `unavailable` with a helpful message and no exception.
        rep = llm.llm_baseline(_cfg(), "SPEC", ["agreement"], "proven",
                               client=FakeClient(available=False))
        self.assertEqual(rep["status"], "unavailable")
        self.assertIn("API key", rep.get("error", ""))
        self.assertIn("disclaimer", rep)

    def test_ok_parses_json_response(self):
        payload = {
            "interesting_invariants": ["agreement", "validity"],
            "likely_bug": "participant applies before phase=decided",
            "counterexample": [
                {"step": 1, "actor": "p1", "action": "prepare", "state": "prepared"},
                {"step": 2, "actor": "p1", "action": "apply", "state": "applied"},
            ],
        }
        client = FakeClient(json.dumps(payload))
        rep = llm.llm_baseline(_cfg(), "SPEC", ["agreement"], "proven",
                               client=client)
        self.assertEqual(rep["status"], "ok")
        self.assertEqual(rep["model"], "test-model")
        self.assertEqual(rep["interesting_invariants"],
                         ["agreement", "validity"])
        self.assertEqual(rep["likely_bug"],
                         "participant applies before phase=decided")
        self.assertEqual(len(rep["counterexample"]), 2)
        self.assertEqual(rep["counterexample"][0]["actor"], "p1")
        self.assertIn("disclaimer", rep)
        self.assertEqual(len(client.prompts), 1)

    def test_garbage_response_is_ok_but_empty(self):
        # A non-raising garbage answer is NOT an error: it parses to empty
        # fields. The baseline never fabricates a counterexample from it.
        client = FakeClient("no json here, just prose")
        rep = llm.llm_baseline(_cfg(), "SPEC", ["agreement"], "proven",
                               client=client)
        self.assertEqual(rep["status"], "ok")
        self.assertIsNone(rep["interesting_invariants"])
        self.assertIsNone(rep["likely_bug"])
        self.assertIsNone(rep["counterexample"])
        self.assertIn("disclaimer", rep)

    def test_complete_raising_folds_to_error(self):
        client = FakeClient(raise_exc=RuntimeError("boom"))
        rep = llm.llm_baseline(_cfg(), "SPEC", ["agreement"], "proven",
                               client=client)
        self.assertEqual(rep["status"], "error")
        self.assertIn("boom", rep.get("error", ""))
        self.assertIn("disclaimer", rep)

    def test_missing_keys_are_none(self):
        # A well-formed JSON object missing the expected keys still yields an
        # `ok` report, with the absent fields left as None (never invented).
        client = FakeClient(json.dumps({"status": "ok"}))
        rep = llm.llm_baseline(_cfg(), "SPEC", ["agreement"], "proven",
                               client=client)
        self.assertEqual(rep["status"], "ok")
        self.assertIsNone(rep["interesting_invariants"])
        self.assertIsNone(rep["likely_bug"])
        self.assertIsNone(rep["counterexample"])

    def test_parse_model_response_basic(self):
        r = llm.parse_model_response(json.dumps({
            "interesting_invariants": ["a", "b"],
            "likely_bug": "x",
            "counterexample": [
                {"step": 1, "actor": "p", "action": "a", "state": "s"}],
        }))
        self.assertEqual(r["interesting_invariants"], ["a", "b"])
        self.assertEqual(r["likely_bug"], "x")
        self.assertEqual(len(r["counterexample"]), 1)

    def test_parse_model_response_strips_fences(self):
        r = llm.parse_model_response('```json\n{"likely_bug": "x"}\n```')
        self.assertEqual(r["likely_bug"], "x")

    def test_parse_model_response_rejects_bare_string_ce(self):
        # A bare string is never trusted as a concrete counterexample.
        r = llm.parse_model_response(
            json.dumps({"counterexample": "just a string"}))
        self.assertIsNone(r["counterexample"])

    def test_parse_model_response_garbage_is_empty(self):
        r = llm.parse_model_response("totally not json")
        self.assertEqual(r["interesting_invariants"], [])
        self.assertIsNone(r["likely_bug"])
        self.assertIsNone(r["counterexample"])


class LlmBaselineConfigTests(unittest.TestCase):
    def test_defaults_are_off(self):
        cfg = config.Config()
        self.assertFalse(cfg.llm_enabled)
        self.assertIsNone(cfg.llm_model)
        self.assertIsNone(cfg.llm_base_url)

    def test_defaults_can_be_set(self):
        cfg = config.Config(llm_enabled=True, llm_model="m",
                            llm_base_url="http://x")
        self.assertTrue(cfg.llm_enabled)
        self.assertEqual(cfg.llm_model, "m")
        self.assertEqual(cfg.llm_base_url, "http://x")


class LlmBaselinePipelineTests(unittest.TestCase):
    """The pipeline flag is opt-in and must NEVER change verdict / exit code.

    The LLM env is cleared so the baseline deterministically degrades to
    `unavailable` (no network) while still exercising the full opt-in path.
    """

    def _run_main(self, args, saved):
        try:
            return pipeline.main(args)
        finally:
            _restore_llm_env(saved)

    def test_correct_proven_with_and_without_flag(self):
        saved = _save_and_clear_llm_env()
        tmp = tempfile.mkdtemp(prefix="rotn_llm_")
        try:
            without = pipeline.main(["correct", "--property", "agreement",
                                    "--engine", "symbolic", "--out", tmp,
                                    "--quiet"])
            withflag = self._run_main(
                ["correct", "--property", "agreement", "--engine", "symbolic",
                 "--out", tmp, "--quiet", "--llm-baseline"], saved)
        finally:
            _restore_llm_env(saved)
        self.assertEqual(without, pipeline.EXIT_PROVEN)
        self.assertEqual(withflag, pipeline.EXIT_PROVEN)

    def test_buggy_violated_with_and_without_flag(self):
        saved = _save_and_clear_llm_env()
        tmp = tempfile.mkdtemp(prefix="rotn_llm_")
        try:
            without = pipeline.main(["buggy", "--property", "agreement",
                                    "--engine", "symbolic", "--out", tmp,
                                    "--quiet"])
            withflag = self._run_main(
                ["buggy", "--property", "agreement", "--engine", "symbolic",
                 "--out", tmp, "--quiet", "--llm-baseline"], saved)
        finally:
            _restore_llm_env(saved)
        self.assertEqual(without, pipeline.EXIT_VIOLATED)
        self.assertEqual(withflag, pipeline.EXIT_VIOLATED)

    def test_audit_artifact_written_when_enabled(self):
        saved = _save_and_clear_llm_env()
        tmp = tempfile.mkdtemp(prefix="rotn_llm_")
        try:
            self._run_main(["correct", "--property", "agreement",
                            "--engine", "symbolic", "--out", tmp, "--quiet",
                            "--llm-baseline"], saved)
        finally:
            _restore_llm_env(saved)
        path = os.path.join(tmp, "correct_agreement_llmbaseline.json")
        self.assertTrue(os.path.isfile(path), "missing %s" % path)
        with open(path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["status"], "unavailable")
        self.assertIn("disclaimer", data)

    def test_no_artifact_when_flag_absent(self):
        tmp = tempfile.mkdtemp(prefix="rotn_llm_")
        pipeline.main(["correct", "--property", "agreement",
                       "--engine", "symbolic", "--out", tmp, "--quiet"])
        path = os.path.join(tmp, "correct_agreement_llmbaseline.json")
        self.assertFalse(os.path.isfile(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)