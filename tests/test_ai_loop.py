# -*- coding: utf-8 -*-
"""The AI-authored demo loop (Phase 4): intent -> policy -> verdict.

The loop runs end to end: the canonical APW-2 example (the intent an AI
author turns into a policy, the AI's natural first draft, and ROTN's
verdict -- VIOLATED with a named witness) plus the cross-language check
against the Dogwood twin.

Run: python tests/test_ai_loop.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ai_loop as ai_loop  # noqa: E402
import rot.frontends.policy as fe  # noqa: E402
import rot.dw as dw  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI = os.path.join(_REPO, "samples", "ai_authoring")
APW2_BUGGY = os.path.join(AI, "apw2-buggy.rego")
APW2_CORRECT = os.path.join(AI, "apw2-correct.rego")
INTENT = os.path.join(AI, "intent.md")
DW_BUGGY = os.path.join(_REPO, "samples", "apw2-buggy.dw")
DW_CORRECT = os.path.join(_REPO, "samples", "apw2-correct.dw")


class DefaultLoopTests(unittest.TestCase):
    """The default loop: intent + apw2-buggy.rego -> VIOLATED, cross-checked."""

    def test_default_paths_exist(self):
        intent, policy = ai_loop.default_paths()
        self.assertTrue(os.path.isfile(intent))
        self.assertTrue(os.path.isfile(policy))

    def test_default_is_apw2_buggy(self):
        intent, policy = ai_loop.default_paths()
        self.assertTrue(policy.endswith("apw2-buggy.rego"))

    def test_run_returns_full_result(self):
        r = ai_loop.run()
        self.assertIn("intent", r)
        self.assertIn("policy_text", r)
        self.assertEqual(r["frontend"], "opa")
        self.assertEqual(r["shape"], "approval_replay")
        self.assertEqual(r["property"], "approval_single_use")
        self.assertEqual(r["property_kind"], "safety")
        self.assertEqual(r["verdict"], "violated")
        self.assertEqual(r["witness"], {"approved": True, "orders": 2})
        self.assertEqual(r["exit_code"], 1)

    def test_intent_is_natural_language(self):
        r = ai_loop.run()
        self.assertIn("cart", r["intent"].lower())
        self.assertIn("order", r["intent"].lower())


class CrossLanguageTests(unittest.TestCase):
    """The loop's cross-language check agrees with the Dogwood twin."""

    def test_cross_language_present(self):
        r = ai_loop.run()
        self.assertIsNotNone(r["cross_language"])
        cross = r["cross_language"]
        self.assertTrue(cross["dogwood_policy"].endswith("apw2-buggy.dw"))
        self.assertTrue(cross["same_ir"])
        self.assertEqual(cross["dogwood_verdict"], "violated")
        self.assertTrue(cross["same_verdict"])

    def test_cross_language_matches_direct_lowering(self):
        r = ai_loop.run()
        self.assertEqual(r["cross_language"]["same_ir"],
                         bool(fe.build_ir(APW2_BUGGY)
                              == dw.parse_file(DW_BUGGY).to_ir()))

    def test_correct_policy_cross_language(self):
        r = ai_loop.run(policy_path=APW2_CORRECT)
        self.assertEqual(r["verdict"], "proven")
        self.assertEqual(r["exit_code"], 0)
        self.assertIsNotNone(r["cross_language"])
        self.assertTrue(r["cross_language"]["same_ir"])
        self.assertEqual(r["cross_language"]["dogwood_verdict"], "proven")


class LoopErrorTests(unittest.TestCase):
    def test_missing_intent(self):
        with self.assertRaises(RuntimeError):
            ai_loop.run(intent_path=os.path.join(AI, "nope.md"))

    def test_missing_policy(self):
        with self.assertRaises(RuntimeError):
            ai_loop.run(policy_path=os.path.join(AI, "nope.rego"))

    def test_out_dir_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            r = ai_loop.run(out_dir=d)
            self.assertTrue(os.path.isfile(os.path.join(d, "ai-loop-report.json")))


if __name__ == "__main__":
    unittest.main()