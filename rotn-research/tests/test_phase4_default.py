#!/usr/bin/env python3
"""Phase 4 gates: the two-layer agreement is the default cross-check, and the
default Ingest path (CPG-first / Joern-primary) agrees with the A/B winner.

The gates (plan §Phase 4):
  * On the oracle corpus, the default path's verdicts match the A/B
    winner's verdicts.
  * A static threat to a PROVEN is downgraded to ``unknown`` (never a silent
    false negative).
  * A ``VIOLATED`` is never upgraded (the cross-check refines, never weakens).

Deterministic, offline, stdlib-only (the A/B + the CPG cross-check are pure).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rotn_research.ab import (run_ab, resolve_frontend, default_frontend)  # noqa: E402
from rot.cegar import verify_candidate  # noqa: E402
from rot.config import Config  # noqa: E402
from rot.cpg_crosscheck import (  # noqa: E402
    SoundnessResult, AGREEMENT, UNSOUND,
)
from rot.crosscheck import apply_two_layer  # noqa: E402
from rot.frontends import cpg_reader  # noqa: E402
from rot.frontends.cpg.extractor import extract_cpg  # noqa: E402
from rot.lower import lower_candidate  # noqa: E402
from rot.verdicts import PROVEN, VIOLATED, UNKNOWN, Verdict  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                   "cpg", "connector.cpg.json")
CFG = Config(max_states=200000)


def _fake_verdict(status):
    v = Verdict(status, "test_prop", "symbolic")
    v.evidence = {}
    return v


class DefaultRoutingGate(unittest.TestCase):
    """The default Ingest path is CPG-first (Joern-primary §3)."""

    def test_cpg_is_default_when_artifact_present(self):
        # A CPG artifact makes the CPG frontend the default production path.
        self.assertEqual(resolve_frontend(None, cpg_present=True), "cpg")
        self.assertEqual(
            resolve_frontend(None, cpg_present=True, source_dir="s"), "cpg")
        self.assertEqual(resolve_frontend("auto", cpg_present=True), "cpg")

    def test_source_then_oracle_fallback(self):
        # No CPG artifact: the source frontend, then the oracle registry.
        self.assertEqual(resolve_frontend(None, source_dir="s"), "java")
        self.assertEqual(resolve_frontend(None), "targets")

    def test_explicit_choice_always_wins(self):
        # An explicit frontend choice always wins over the default.
        self.assertEqual(resolve_frontend("cpg"), "cpg")
        self.assertEqual(resolve_frontend("java", cpg_present=True), "java")
        self.assertEqual(resolve_frontend("targets", cpg_present=True),
                         "targets")
        self.assertEqual(resolve_frontend("code", cpg_present=True), "code")

    def test_default_frontend_is_a_valid_ab_winner(self):
        # The A/B winner is a real frontend (reproducible, citable).
        winner = default_frontend()
        self.assertIn(winner, ("cpg", "code", "java", "targets"))


class TwoLayerDefaultGate(unittest.TestCase):
    """The two-layer agreement is the default cross-check (fail-closed)."""

    def test_static_threat_downgrades_proven_to_unknown(self):
        # A static threat to a PROVEN is downgraded to UNKNOWN (never a
        # silent false negative) -- the Phase 4 default cross-check.
        soundness = SoundnessResult(UNSOUND, note="threat edge in G")
        result = apply_two_layer(_fake_verdict(PROVEN), PROVEN,
                                 soundness.to_dict())
        self.assertEqual(result.status, UNKNOWN)
        self.assertIn("static", result.evidence["two_layer"]["disagreement"])

    def test_violated_is_never_upgraded(self):
        # A VIOLATED is never upgraded by the cross-check (refines, never
        # weakens): even a "threat" keeps the refutation.
        soundness = SoundnessResult(UNSOUND, note="threat edge in G")
        result = apply_two_layer(_fake_verdict(VIOLATED), VIOLATED,
                                 soundness.to_dict())
        self.assertEqual(result.status, VIOLATED)

    def test_proven_requires_both_layers(self):
        # PROVEN only if (formal == PROVEN) and (no taint-critical threat).
        sound_ok = SoundnessResult(AGREEMENT).to_dict()
        self.assertEqual(
            apply_two_layer(_fake_verdict(PROVEN), PROVEN, sound_ok).status,
            PROVEN)
        sound_bad = SoundnessResult(UNSOUND).to_dict()
        self.assertEqual(
            apply_two_layer(_fake_verdict(PROVEN), PROVEN, sound_bad).status,
            UNKNOWN)

    def test_cpg_path_stamps_two_layer_by_default(self):
        # The CPG frontend path applies the two-layer agreement by default
        # (Layer A formal + Layer B static<->formal) and stamps it on the
        # verdict evidence (auditable in the report).
        model = cpg_reader.load_cpg(FIX)
        cand = extract_cpg(model)
        ir = lower_candidate(cand)
        verdict = verify_candidate(ir, CFG, cpg=model)
        self.assertIn("abstraction_soundness", verdict.evidence)


class ABAgreementGate(unittest.TestCase):
    """On the oracle corpus, the default (CPG) path's verdicts match the A/B
    winner's verdicts (both catch the known bug; neither false-PROVENs)."""

    @classmethod
    def setUpClass(cls):
        cls.result = run_ab()

    def test_winner_passes_hard_gate(self):
        self.assertTrue(self.result.winner)
        agg = self.result.per_frontend[self.result.winner]
        self.assertTrue(agg["hard_gate_pass"])

    def test_default_path_matches_ab_winner_on_oracle_corpus(self):
        winner = self.result.winner
        by_key = {(c.frontend, c.fixture): c for c in self.result.cells}
        compared = 0
        for c in self.result.cells:
            if c.frontend != "cpg" or c.status != "available":
                continue
            w = by_key.get((winner, c.fixture))
            if w is None or w.status != "available":
                continue
            self.assertEqual(
                c.verdict_status, w.verdict_status,
                "default (cpg) and A/B winner (%s) disagree on %s"
                % (winner, c.fixture))
            compared += 1
        self.assertGreaterEqual(
            compared, 1, "no shared (cpg, winner) cells on the oracle corpus")


if __name__ == "__main__":
    unittest.main(verbosity=2)
