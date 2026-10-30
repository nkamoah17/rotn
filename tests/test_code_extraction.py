# -*- coding: utf-8 -*-
"""End-to-end gate for Code-to-TLA+ extraction (spec §7, D3).

This is the **gate** (D4): it proves that the narrow-waist front-end extracts
the control the code *enforces* (E1, not intent), and that the Verify plane
discharges that control with **PROVEN / VIOLATED + exact witness /
OUT_OF_SCOPE** (E2/E3/E4) -- never a prose description, never a silent
UNKNOWN.  It exercises the full pipeline::

    extract(source) -> Candidate
       -> lower_candidate(Candidate) -> ProtocolIR   (reuses the lighthouse
                                                           SpendCap / NoExfil
                                                           shape-lowering)
       -> verify_candidate(IR, cfg) -> Verdict       (linearize -> Invariant ->
                                                      engine -> cegar)

Five fixtures cover the two P1 shapes (budget, label_flow) in both enforced
and bypassable form, plus one out-of-scope module (E2).
"""

import os
import unittest

from rot.config import Config
from rot.frontends.code import (extract_file, PATTERN_BUDGET,
                                PATTERN_LABEL_FLOW)
from rot.lower import lower_candidate
from rot.cegar import verify_candidate
from rot.verdicts import Verdict, UNKNOWN

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "code")
CFG = Config(max_states=100000)


def _fixture(name):
    return os.path.join(FIX, name + ".py")


def _verdict_for(path):
    """Run the gate on ``path`` and return the final :class:`Verdict`.

    Out-of-scope candidates (E2) short-circuit to ``OUT_OF_SCOPE`` -- no
    lowering, no engine -- exactly as the gate must do.
    """
    cand = extract_file(path)
    if cand.out_of_scope:
        return Verdict.out_of_scope(
            cand.provenance.get("filename", "source"), "symbolic",
            reason=cand.reason)
    ir_model = lower_candidate(cand)
    return verify_candidate(ir_model, CFG)


class FrontendExtractionTest(unittest.TestCase):
    """The front-end extracts the control the code ENFORCES (E1) and reports
    anything outside P1 as OUT_OF_SCOPE (E2)."""

    def test_budget_enforced_is_extracted(self):
        c = extract_file(_fixture("budget_enforced"))
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_BUDGET)
        self.assertTrue(c.enforced, "an in-flight term => enforced (safe)")
        self.assertEqual(c.params, {"amount": 100, "cap": 200})
        self.assertTrue(c.candidate, "E1: a candidate, not intent")
        self.assertEqual(c.provenance.get("function"), "can_spend")

    def test_budget_bypassable_is_extracted(self):
        c = extract_file(_fixture("budget_bypassable"))
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_BUDGET)
        self.assertFalse(c.enforced, "settled-only => bypassable")
        self.assertEqual(c.params, {"amount": 100, "cap": 200})

    def test_label_flow_enforced_is_extracted(self):
        c = extract_file(_fixture("label_flow_enforced"))
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_LABEL_FLOW)
        self.assertTrue(c.enforced)
        self.assertEqual(c.params["label"], "holding_private")

    def test_label_flow_bypassable_is_extracted(self):
        c = extract_file(_fixture("label_flow_bypassable"))
        self.assertFalse(c.out_of_scope)
        self.assertEqual(c.pattern, PATTERN_LABEL_FLOW)
        self.assertFalse(c.enforced, "unconditional allow => bypassable")

    def test_out_of_scope_is_honest(self):
        c = extract_file(_fixture("out_of_scope"))
        self.assertTrue(c.out_of_scope, "E2: no P1 control => OUT_OF_SCOPE")
        self.assertFalse(c.candidate)
        self.assertIsNone(c.pattern)

    def test_pinned_property_is_emitted(self):
        # The front-end emits the pinned property (ProtocolIR candidate).
        c = extract_file(_fixture("budget_enforced"))
        self.assertIsNotNone(c.pinned_property)
        c2 = extract_file(_fixture("label_flow_enforced"))
        self.assertIsNotNone(c2.pinned_property)


class LoweringTest(unittest.TestCase):
    """``lower_candidate`` reuses the lighthouse shapes and stamps the
    candidate scope (E1 / E4)."""

    def test_budget_lowered_to_spendcap(self):
        c = extract_file(_fixture("budget_enforced"))
        m = lower_candidate(c)
        self.assertIn("spendcap", m.name)
        self.assertTrue(m.metadata.get("candidate"), "E1: candidate tag")
        self.assertEqual(m.metadata.get("pattern_class"), "P1")
        self.assertEqual(m.metadata.get("pattern"), "budget")
        names = {v.name for v in m.variables}
        self.assertIn("inflight", names)
        self.assertIn("completed", names)

    def test_label_flow_lowered_to_noexfil(self):
        c = extract_file(_fixture("label_flow_bypassable"))
        m = lower_candidate(c)
        self.assertIn("noexfil", m.name)
        names = {v.name for v in m.variables}
        self.assertIn("exfiltrated", names)
        self.assertIn("holding_private", names)

    def test_out_of_scope_candidate_refused(self):
        c = extract_file(_fixture("out_of_scope"))
        with self.assertRaises(ValueError):
            lower_candidate(c)


class EndToEndGateTest(unittest.TestCase):
    """The full gate: extract -> lower -> verify -> PROVEN / VIOLATED +
    exact witness / OUT_OF_SCOPE (E1/E2/E3/E4)."""

    def test_budget_enforced_is_proven(self):
        v = _verdict_for(_fixture("budget_enforced"))
        self.assertTrue(v.is_proven(), "an enforced budget must be PROVEN")
        self.assertIsNone(v.counterexample, "a PROVEN verdict has no witness")

    def test_budget_bypassable_violated_with_exact_witness(self):
        v = _verdict_for(_fixture("budget_bypassable"))
        self.assertTrue(v.is_violated(), "a bypassable budget must be VIOLATED")
        # E3: the EXACT witness (the parallel-fire bypass), not a prose claim.
        self.assertEqual(v.counterexample, {"completed": 0, "inflight": 3})

    def test_label_flow_enforced_is_proven(self):
        v = _verdict_for(_fixture("label_flow_enforced"))
        self.assertTrue(v.is_proven(), "an enforced flow control must hold")

    def test_label_flow_bypassable_violated_with_exact_witness(self):
        v = _verdict_for(_fixture("label_flow_bypassable"))
        self.assertTrue(v.is_violated())
        self.assertEqual(v.counterexample,
                         {"holding_private": True, "exfiltrated": True})

    def test_out_of_scope_verdict(self):
        v = _verdict_for(_fixture("out_of_scope"))
        self.assertTrue(v.is_out_of_scope(), "E2: OUT_OF_SCOPE, not UNKNOWN")
        self.assertNotEqual(v.status, UNKNOWN)

    def test_verdict_evidence_carry_candidate_scope(self):
        # E1 + E4: the verdict evidence states it is a candidate, scoped to the
        # extracted control + provenance -- never an unconditional claim.
        v = _verdict_for(_fixture("budget_bypassable"))
        ev = v.evidence
        self.assertTrue(ev.get("candidate"), "E1: candidate tag in evidence")
        self.assertEqual(ev.get("pattern"), "budget")
        self.assertEqual(ev.get("enforced"), False)
        self.assertIn("function", ev.get("provenance", {}),
                      "E4: per-instance provenance")
        self.assertIn("scope", ev, "E4: scope statement present")


if __name__ == "__main__":
    unittest.main()