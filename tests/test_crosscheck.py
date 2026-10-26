# -*- coding: utf-8 -*-
"""Tests for ``rot.crosscheck`` -- the three-engine (SMT/Z3 + TLC +
policy-direct) cross-check.

The join policy is a pure function of the three engines' statuses, so the
core logic is tested with *stubbed* engine seams (no Z3 or TLC jar needed).
Two gated end-to-end tests (real SMT + TLC + policy-direct) and one
pipeline-dispatch test run only when the TLC jar is resolvable.

Run: python tests/test_crosscheck.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rot import crosscheck
from rot.crosscheck import CrossChecker, join_status, join_status3
from rot.config import Config
from rot.invariants import spendcap_within_cap
from rot.linearization import linearize
from rot.spendcap import build_ir
from rot.symbolic import EngineResult
from rot.verdicts import Verdict

try:
    import z3  # noqa: F401
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False

PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"


def _stub(smt_status, tlc_status, pd_status=None,
          smt_counterexample=None, tlc_witness=None, pd_witness=None,
          smt_trace=None, tlc_note="tlc-note", pd_note="pd-note"):
    """Build a ``CrossChecker`` whose three engines are stubbed out.

    ``check()`` then exercises only the join + verdict-building logic, so
    these tests run without Z3 or a TLC jar.

    ``pd_status`` is the policy-direct engine's status.  It defaults to the
    "dominant" decision status so the pre-existing two-engine tests keep
    their meaning: when both decision engines agree on PROVEN/VIOLATED the
    policy-direct engine agrees too; when they disagree the policy-direct
    status is irrelevant (the join is UNKNOWN regardless).
    """
    if pd_status is None:
        pd_status = smt_status if smt_status == tlc_status else PROVEN
    prop = spendcap_within_cap()
    checker = CrossChecker(None, None, prop, None)
    checker._smt_verdict = lambda: Verdict(
        status=smt_status, property_name=prop.name, engine="smtz3",
        counterexample=smt_counterexample, trace=smt_trace,
        note="smt-note")
    checker._tlc_result = lambda: EngineResult(
        status=tlc_status, witness=tlc_witness, note=tlc_note)
    checker._policy_direct_verdict = lambda: EngineResult(
        status=pd_status, witness=pd_witness, note=pd_note)
    return checker


class JoinLogicTest(unittest.TestCase):
    """``join_status``: PROVEN/VIOLATED need both engines to agree."""

    def test_both_proven_is_proven(self):
        self.assertEqual(join_status(PROVEN, PROVEN), PROVEN)

    def test_both_violated_is_violated(self):
        self.assertEqual(join_status(VIOLATED, VIOLATED), VIOLATED)

    def test_disagreement_proven_violated_is_unknown(self):
        self.assertEqual(join_status(PROVEN, VIOLATED), UNKNOWN)

    def test_disagreement_violated_proven_is_unknown(self):
        self.assertEqual(join_status(VIOLATED, PROVEN), UNKNOWN)

    def test_smt_unknown_forces_unknown_even_if_tlc_proves(self):
        # Z3 unavailable -> SMT returns unknown; TLC cannot mint a decision.
        self.assertEqual(join_status(UNKNOWN, PROVEN), UNKNOWN)

    def test_tlc_unknown_forces_unknown_even_if_smt_proves(self):
        self.assertEqual(join_status(PROVEN, UNKNOWN), UNKNOWN)

    def test_both_unknown_is_unknown(self):
        self.assertEqual(join_status(UNKNOWN, UNKNOWN), UNKNOWN)

    def test_error_and_unsound_collapse_to_unknown(self):
        self.assertEqual(join_status("error", PROVEN), UNKNOWN)
        self.assertEqual(join_status(PROVEN, "unsound"), UNKNOWN)
        self.assertEqual(join_status("error", "unsound"), UNKNOWN)


class WitnessMatchTest(unittest.TestCase):
    """``witness_match``: do BOTH independent engines point at the SAME attack
    state?  A pure function of the two witnesses (and the joined status)."""

    def test_same_state_is_a_match(self):
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match(ce, ce, VIOLATED), True)

    def test_key_order_is_irrelevant(self):
        # Canonical fingerprint: same state, different key order -> match.
        a = {"completed": 0, "inflight": 3}
        b = {"inflight": 3, "completed": 0}
        self.assertIs(crosscheck.witness_match(a, b, VIOLATED), True)

    def test_different_states_are_not_a_match(self):
        self.assertIs(
            crosscheck.witness_match({"completed": 0, "inflight": 3},
                                     {"completed": 100, "inflight": 2},
                                     VIOLATED),
            False)

    def test_missing_witness_is_not_a_match(self):
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match(ce, None, VIOLATED), False)
        self.assertIs(crosscheck.witness_match(None, ce, VIOLATED), False)
        self.assertIs(crosscheck.witness_match(None, None, VIOLATED), False)

    def test_non_dict_witness_is_not_a_match(self):
        self.assertIs(crosscheck.witness_match("0,3", {"completed": 0},
                                               VIOLATED), False)

    def test_proven_join_is_na_not_mismatch(self):
        # A PROVEN run has no counterexample to compare -> N/A (None), not
        # False.  This is what lets K=1 (masked) read as "no witness".
        self.assertIsNone(crosscheck.witness_match(None, None, PROVEN))

    def test_unknown_join_is_na_not_mismatch(self):
        self.assertIsNone(crosscheck.witness_match(None, None, UNKNOWN))

    def test_match_without_explicit_join_defaults_to_compare(self):
        # joined=None means "just compare the two witnesses".
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match(ce, ce), True)
        self.assertIs(crosscheck.witness_match(ce, {"completed": 1, "inflight": 3}),
                      False)


class Join3LogicTest(unittest.TestCase):
    """``join_status3``: PROVEN/VIOLATED need ALL THREE engines to agree."""

    def test_all_three_proven_is_proven(self):
        self.assertEqual(join_status3(PROVEN, PROVEN, PROVEN), PROVEN)

    def test_all_three_violated_is_violated(self):
        self.assertEqual(join_status3(VIOLATED, VIOLATED, VIOLATED), VIOLATED)

    def test_policy_direct_disagreement_forces_unknown(self):
        # SMT and TLC agree (PROVEN) but the policy-direct engine disagrees:
        # the model-independence axis vetoes the decision.
        self.assertEqual(join_status3(PROVEN, PROVEN, VIOLATED), UNKNOWN)
        self.assertEqual(join_status3(PROVEN, PROVEN, UNKNOWN), UNKNOWN)

    def test_smt_disagreement_forces_unknown(self):
        self.assertEqual(join_status3(VIOLATED, PROVEN, PROVEN), UNKNOWN)

    def test_tlc_disagreement_forces_unknown(self):
        self.assertEqual(join_status3(PROVEN, VIOLATED, PROVEN), UNKNOWN)

    def test_error_and_unsound_collapse_to_unknown(self):
        self.assertEqual(join_status3(PROVEN, PROVEN, "error"), UNKNOWN)
        self.assertEqual(join_status3("unsound", PROVEN, PROVEN), UNKNOWN)
        self.assertEqual(join_status3(PROVEN, "error", "unsound"), UNKNOWN)


class WitnessMatch3Test(unittest.TestCase):
    """``witness_match3``: do all three engines point at the SAME state?"""

    def test_all_three_same_state_is_match(self):
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match3(ce, ce, ce, VIOLATED), True)

    def test_policy_direct_different_state_is_mismatch(self):
        # SMT and TLC agree, but the policy-direct engine found a different
        # attack state: the credibility core must flag a mismatch.
        self.assertIs(crosscheck.witness_match3(
            {"completed": 0, "inflight": 3},
            {"completed": 0, "inflight": 3},
            {"completed": 100, "inflight": 2},
            VIOLATED), False)

    def test_none_when_not_violated(self):
        # A PROVEN run has no counterexample to compare -> N/A (None).
        self.assertIsNone(crosscheck.witness_match3(None, None, None, PROVEN))
        self.assertIsNone(crosscheck.witness_match3(None, None, None, UNKNOWN))

    def test_missing_witness_is_not_a_match(self):
        # All three VIOLATED but one engine produced no witness: cannot
        # confirm identity -> not a match (False), but not N/A either.
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match3(ce, ce, None, VIOLATED), False)
        self.assertIs(crosscheck.witness_match3(None, ce, ce, VIOLATED), False)

    def test_match_without_explicit_join_defaults_to_compare(self):
        ce = {"completed": 0, "inflight": 3}
        self.assertIs(crosscheck.witness_match3(ce, ce, ce), True)
        self.assertIs(crosscheck.witness_match3(
            ce, ce, {"completed": 1, "inflight": 3}), False)


class ConfigTest(unittest.TestCase):
    """``crosscheck`` is a first-class engine in ``select_engine()``."""

    def test_select_engine_returns_crosscheck(self):
        self.assertEqual(Config(engine="crosscheck").select_engine(),
                         "crosscheck")

    def test_auto_policy_never_yields_crosscheck(self):
        # crosscheck is opt-in; "auto" still resolves to tlc/symbolic.
        self.assertIn(Config(engine="auto").select_engine(),
                      ("tlc", "symbolic"))

    def test_unknown_engine_still_raises(self):
        with self.assertRaises(ValueError):
            Config(engine="bogus").select_engine()


class VerdictBuildingTest(unittest.TestCase):
    """Verdict shape: status, engine tag, per-engine evidence, counterexample."""

    def test_both_proven_verdict(self):
        verdict = _stub(PROVEN, PROVEN).check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(verdict.engine, "crosscheck")
        self.assertIsNone(verdict.counterexample)
        self.assertIn("crosscheck", verdict.evidence)

    def test_both_violated_verdict_carries_counterexample(self):
        verdict = _stub(VIOLATED, VIOLATED,
                        smt_counterexample={"completed": 0, "inflight": 3},
                        tlc_witness={"completed": 0, "inflight": 3}).check()
        self.assertEqual(verdict.status, VIOLATED)
        self.assertEqual(verdict.counterexample,
                         {"completed": 0, "inflight": 3})

    def test_disagreement_is_unknown_with_no_counterexample(self):
        verdict = _stub(PROVEN, VIOLATED).check()
        self.assertEqual(verdict.status, UNKNOWN)
        self.assertIsNone(verdict.counterexample)

    def test_smt_unknown_preserved(self):
        verdict = _stub(UNKNOWN, PROVEN).check()
        self.assertEqual(verdict.status, UNKNOWN)
        cc = verdict.evidence["crosscheck"]
        self.assertEqual(cc["smt"]["status"], UNKNOWN)
        self.assertEqual(cc["smt"]["normalized"], UNKNOWN)
        self.assertEqual(cc["tlc"]["status"], PROVEN)
        self.assertEqual(cc["joined"], UNKNOWN)

    def test_evidence_breakdown_records_each_engine(self):
        verdict = _stub(PROVEN, PROVEN).check()
        cc = verdict.evidence["crosscheck"]
        self.assertEqual(cc["smt"]["engine"], "smtz3")
        self.assertEqual(cc["tlc"]["engine"], "tlc")
        self.assertEqual(cc["smt"]["note"], "smt-note")
        self.assertEqual(cc["tlc"]["note"], "tlc-note")
        self.assertIn("policy", cc)

    def test_trace_carried_when_both_violated(self):
        trace = [("completed", "spend_ok", "g", "c", {"inflight": 1})]
        verdict = _stub(VIOLATED, VIOLATED,
                        smt_counterexample={"inflight": 3},
                        smt_trace=trace).check()
        self.assertEqual(verdict.status, VIOLATED)
        self.assertEqual(verdict.trace, trace)

    def test_violated_without_smt_counterexample_falls_back_to_tlc_witness(self):
        verdict = _stub(VIOLATED, VIOLATED,
                        tlc_witness={"completed": 0, "inflight": 3}).check()
        self.assertEqual(verdict.status, VIOLATED)
        self.assertEqual(verdict.counterexample,
                         {"completed": 0, "inflight": 3})

    def test_property_kind_is_safety(self):
        verdict = _stub(PROVEN, PROVEN).check()
        self.assertEqual(verdict.property_kind, "safety")


class ApalacheSeamTest(unittest.TestCase):
    """The optional Apalache MC: recorded, informational, never in the join."""

    def _checker(self, smt_status, tlc_status, apalache_status,
                 pd_status=None,
                 smt_ce=None, tlc_witness=None, apalache_witness=None,
                 apalache_note="apalache-note"):
        # ``pd_status`` defaults to the dominant decision status (see _stub)
        # so the pre-existing two-engine Apalache tests keep their meaning.
        if pd_status is None:
            pd_status = smt_status if smt_status == tlc_status else PROVEN
        prop = spendcap_within_cap()
        checker = CrossChecker(None, None, prop, Config(apalache_enabled=True))
        checker._smt_verdict = lambda: Verdict(
            status=smt_status, property_name=prop.name, engine="smtz3",
            counterexample=smt_ce, note="smt-note")
        checker._tlc_result = lambda: EngineResult(
            status=tlc_status, witness=tlc_witness, note="tlc-note")
        checker._apalache_result = lambda: EngineResult(
            status=apalache_status, witness=apalache_witness,
            n_states=7, note=apalache_note)
        checker._policy_direct_verdict = lambda: EngineResult(
            status=pd_status, note="pd-note")
        return checker

    def test_apalache_absent_when_disabled(self):
        # cfg=None (and any default Config) leaves the seam off.
        verdict = _stub(PROVEN, PROVEN).check()
        self.assertIsNone(verdict.evidence["crosscheck"]["apalache"])

    def test_apalache_recorded_when_enabled(self):
        ce = {"completed": 0, "inflight": 3}
        verdict = self._checker(VIOLATED, VIOLATED, VIOLATED,
                                smt_ce=ce, tlc_witness=ce,
                                apalache_witness=ce).check()
        ap = verdict.evidence["crosscheck"]["apalache"]
        self.assertEqual(ap["engine"], "apalache-mc")
        self.assertEqual(ap["status"], VIOLATED)
        self.assertEqual(ap["note"], "apalache-note")
        self.assertEqual(ap["n_states"], 7)
        self.assertEqual(ap["witness"], ce)

    def test_apalache_cannot_mint_a_decision(self):
        # SMT proves, TLC violates: Apalache agreeing with TLC changes
        # nothing -- the join stays UNKNOWN.
        verdict = self._checker(PROVEN, VIOLATED, VIOLATED).check()
        self.assertEqual(verdict.status, UNKNOWN)
        self.assertIsNone(verdict.counterexample)

    def test_apalache_disagreement_changes_nothing(self):
        # Both decision engines violate; Apalache proves.  Still VIOLATED.
        verdict = self._checker(VIOLATED, VIOLATED, PROVEN).check()
        self.assertEqual(verdict.status, VIOLATED)

    def test_apalache_error_is_recorded_informationally(self):
        # e.g. jar missing: the error is recorded, the join is untouched.
        prop = spendcap_within_cap()
        checker = CrossChecker(None, None, prop, Config(apalache_enabled=True))
        checker._smt_verdict = lambda: Verdict(
            status=PROVEN, property_name=prop.name, engine="smtz3",
            note="smt-note")
        checker._tlc_result = lambda: EngineResult(status=PROVEN,
                                                   note="tlc-note")
        checker._apalache_result = lambda: EngineResult(
            status="error", note="apalache.jar not found")
        checker._policy_direct_verdict = lambda: EngineResult(
            status=PROVEN, note="pd-note")
        verdict = checker.check()
        self.assertEqual(verdict.status, PROVEN)
        self.assertEqual(verdict.evidence["crosscheck"]["apalache"]["status"],
                         "error")
        self.assertEqual(verdict.evidence["crosscheck"]["apalache"]["note"],
                         "apalache.jar not found")

    def test_apalache_error_with_both_violated_stays_violated(self):
        # SMT and TLC both violate (the join mints VIOLATED); the third
        # engine Apalache errors (e.g. jar missing).  The Apalache evidence
        # is present and informational, and the SMT+TLC joined verdict is
        # unchanged -- a single engine can never alter the decision.
        ce = {"completed": 0, "inflight": 3}
        verdict = self._checker(VIOLATED, VIOLATED, "error",
                                smt_ce=ce, tlc_witness=ce,
                                apalache_note="apalache.jar not found").check()
        self.assertEqual(verdict.status, VIOLATED)
        self.assertEqual(verdict.counterexample, ce)
        # The Apalache evidence is present (recorded informationally)...
        ap = verdict.evidence["crosscheck"]["apalache"]
        self.assertEqual(ap["status"], "error")
        self.assertEqual(ap["note"], "apalache.jar not found")
        # ...and the SMT+TLC join is a pure function of those two: still
        # VIOLATED, untouched by Apalache's error.
        self.assertEqual(verdict.evidence["crosscheck"]["joined"], VIOLATED)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class EndToEndTest(unittest.TestCase):
    """Real SMT (Z3) + TLC engines on the spendcap slice. Skipped if no jar."""

    @classmethod
    def setUpClass(cls):
        cls.cfg = Config()
        if not cls.cfg.tlc_available():
            raise unittest.SkipTest("TLC jar unavailable")

    def _check(self, buggy):
        ir = build_ir(buggy=buggy)
        prop = spendcap_within_cap()
        linear_model = linearize(ir)
        return CrossChecker(ir, linear_model, prop, self.cfg).check()

    def test_buggy_is_violated(self):
        verdict = self._check(buggy=True)
        self.assertEqual(verdict.status, VIOLATED)
        self.assertIsNotNone(verdict.counterexample)

    def test_correct_is_proven(self):
        verdict = self._check(buggy=False)
        self.assertEqual(verdict.status, PROVEN)
        self.assertIsNone(verdict.counterexample)


@unittest.skipUnless(_Z3_AVAILABLE, "z3 not installed")
class PipelineDispatchTest(unittest.TestCase):
    """The pipeline wires engine="crosscheck" into the safety path. Skipped
    if TLC is unavailable (the dispatch needs both engines)."""

    @classmethod
    def setUpClass(cls):
        if not Config().tlc_available():
            raise unittest.SkipTest("TLC jar unavailable")

    def test_pipeline_buggy_reports_violated(self):
        import pipeline
        verdict = pipeline.run(target_name="spendcap-buggy",
                               engine="crosscheck")
        self.assertEqual(verdict.status, VIOLATED)
        self.assertEqual(verdict.engine, "crosscheck")
        self.assertIn("crosscheck", verdict.evidence)

    def test_pipeline_correct_reports_proven(self):
        import pipeline
        verdict = pipeline.run(target_name="spendcap-correct",
                               engine="crosscheck")
        self.assertEqual(verdict.status, PROVEN)


# ---------------------------------------------------------------------------
# Report layer: crosscheck_report.json, witnesses, CLI
# ---------------------------------------------------------------------------

ITF_FIXTURE = os.path.join(
    "tests", "fixtures", "aws_dogwood", "spendcap", "apalache-buggy.itf.json")


def _run_report(smt_status, tlc_status, pd_status=None,
                smt_ce=None, tlc_witness=None, pd_witness=None):
    """A minimal per-run report in the shape of VerdictReport.to_dict().

    ``pd_status`` defaults to the dominant decision status (see _stub) so
    the pre-existing two-engine report tests keep their meaning.
    """
    if pd_status is None:
        pd_status = smt_status if smt_status == tlc_status else PROVEN
    joined = join_status3(smt_status, tlc_status, pd_status)
    return {
        "target": "policy-spendcap-buggy.dw",
        "property_name": "spendcap_within_cap",
        "engine": "crosscheck",
        "config": {},
        "abstraction": {},
        "verdict": {
            "status": joined,
            "evidence": {
                "crosscheck": {
                    "policy": "PROVEN/VIOLATED require ALL THREE engines",
                    "smt": {"engine": "smtz3", "status": smt_status,
                            "note": "smt-note", "counterexample": smt_ce},
                    "tlc": {"engine": "tlc", "status": tlc_status,
                            "note": "tlc-note", "n_states": 42,
                            "complete": True, "witness": tlc_witness},
                    "policy_direct": {"engine": "policy_direct",
                                      "status": pd_status,
                                      "note": "pd-note",
                                      "witness": pd_witness},
                    "joined": joined,
                },
            },
        },
    }


class ReportBuildTest(unittest.TestCase):
    """build_crosscheck_report: the curated crosscheck_report.json schema."""

    def test_schema_and_agreement_all_three_violated(self):
        ce = {"completed": 0, "inflight": 3}
        rep = crosscheck.build_crosscheck_report(
            _run_report(VIOLATED, VIOLATED, pd_status=VIOLATED,
                        smt_ce=ce, tlc_witness=ce, pd_witness=ce))
        self.assertEqual(rep["report"], "crosscheck")
        self.assertEqual(rep["version"], crosscheck.REPORT_VERSION)
        self.assertEqual(rep["target"], "policy-spendcap-buggy.dw")
        self.assertEqual(rep["property"], "spendcap_within_cap")
        self.assertEqual(rep["verdict"], VIOLATED)
        self.assertEqual(set(rep["engines"]),
                         {"smtz3", "tlc", "policy_direct", "apalache"})
        self.assertEqual(rep["engines"]["tlc"]["n_states"], 42)
        self.assertEqual(rep["counterexamples"]["smtz3"], ce)
        self.assertEqual(rep["counterexamples"]["tlc"], ce)
        self.assertEqual(rep["counterexamples"]["policy_direct"], ce)
        # Each engine records its model family: SMT/TLC check the IR
        # state-machine, policy_direct checks a different model family.
        self.assertEqual(rep["engines"]["smtz3"]["model"], "ir_state_machine")
        self.assertEqual(rep["engines"]["tlc"]["model"], "ir_state_machine")
        self.assertEqual(rep["engines"]["policy_direct"]["model"],
                         "direct_policy")
        # Apalache was not run: present in the stable schema, all-None, and
        # excluded from the agreement decision.
        self.assertIsNone(rep["engines"]["apalache"]["status"])
        self.assertIsNone(rep["engines"]["apalache"]["normalized"])
        self.assertIsNone(rep["counterexamples"]["apalache"])
        self.assertIsNone(rep["agreement"]["apalache"])
        self.assertEqual(rep["witnesses"], [])
        ag = rep["agreement"]
        self.assertEqual(ag["smtz3"], VIOLATED)
        self.assertEqual(ag["tlc"], VIOLATED)
        self.assertEqual(ag["policy_direct"], VIOLATED)
        self.assertEqual(ag["joined"], VIOLATED)
        self.assertIs(ag["agree"], True)
        self.assertIs(ag["witness_match"], True)  # same 3-parallel-fire state
        self.assertIn("agree", rep["note"])
        # The independence block records the engine-vs-model distinction.
        self.assertIn("independent model checkers", rep["independence"]["engine"])
        self.assertIn("different model family", rep["independence"]["model"])

    def test_witness_match_false_when_engines_find_different_states(self):
        # All three engines VIOLATED (agree) but pointing at DIFFERENT attack
        # states -- the credibility core should flag this as a mismatch.
        rep = crosscheck.build_crosscheck_report(
            _run_report(VIOLATED, VIOLATED, pd_status=VIOLATED,
                        smt_ce={"completed": 0, "inflight": 3},
                        tlc_witness={"completed": 100, "inflight": 2},
                        pd_witness={"completed": 0, "inflight": 3}))
        self.assertIs(rep["agreement"]["agree"], True)
        self.assertIs(rep["agreement"]["witness_match"], False)

    def test_witness_match_none_when_both_proven(self):
        # A PROVEN run has no counterexample to compare -> N/A (None), not
        # False.  This is what lets K=1 (masked) read as "no witness".
        rep = crosscheck.build_crosscheck_report(_run_report(PROVEN, PROVEN))
        self.assertIs(rep["agreement"]["agree"], True)
        self.assertIsNone(rep["agreement"]["witness_match"])

    def test_schema_all_three_proven(self):
        rep = crosscheck.build_crosscheck_report(
            _run_report(PROVEN, PROVEN, pd_status=PROVEN))
        self.assertEqual(rep["verdict"], PROVEN)
        self.assertIs(rep["agreement"]["agree"], True)
        self.assertIsNone(rep["counterexamples"]["smtz3"])
        self.assertIsNone(rep["counterexamples"]["tlc"])
        self.assertIsNone(rep["counterexamples"]["policy_direct"])

    def test_policy_direct_disagreement_forces_unknown(self):
        # SMT and TLC agree (PROVEN) but the policy-direct engine says
        # VIOLATED: the model-independence axis vetoes the decision.
        rep = crosscheck.build_crosscheck_report(
            _run_report(PROVEN, PROVEN, pd_status=VIOLATED))
        self.assertEqual(rep["verdict"], UNKNOWN)
        self.assertEqual(rep["agreement"]["joined"], UNKNOWN)
        self.assertIs(rep["agreement"]["agree"], False)
        self.assertIn("do not agree", rep["note"])

    def test_disagreement_is_not_agreement(self):
        rep = crosscheck.build_crosscheck_report(_run_report(PROVEN, VIOLATED))
        self.assertEqual(rep["agreement"]["joined"], UNKNOWN)
        self.assertIs(rep["agreement"]["agree"], False)
        self.assertIn("do not agree", rep["note"])

    def test_unknown_engine_forces_no_agreement(self):
        rep = crosscheck.build_crosscheck_report(_run_report(PROVEN, UNKNOWN))
        self.assertEqual(rep["agreement"]["joined"], UNKNOWN)
        self.assertIs(rep["agreement"]["agree"], False)

    def test_add_witness_appends_entry(self):
        rep = crosscheck.build_crosscheck_report(
            _run_report(VIOLATED, VIOLATED))
        crosscheck.add_witness(rep, {
            "name": "apalache-itf",
            "status": VIOLATED,
            "note": "refuted at state 4",
            "counterexample": {"completed": 0, "inflight": 3},
            "source": ITF_FIXTURE,
        })
        self.assertEqual(len(rep["witnesses"]), 1)
        w = rep["witnesses"][0]
        self.assertEqual(w["name"], "apalache-itf")
        self.assertEqual(w["status"], VIOLATED)
        self.assertEqual(w["counterexample"], {"completed": 0, "inflight": 3})
        self.assertEqual(w["source"], ITF_FIXTURE)

    def test_add_witness_requires_name_and_status(self):
        rep = crosscheck.build_crosscheck_report(_run_report(PROVEN, PROVEN))
        with self.assertRaises(ValueError):
            crosscheck.add_witness(rep, {"status": VIOLATED})
        with self.assertRaises(ValueError):
            crosscheck.add_witness(rep, "not-a-dict")
        self.assertEqual(rep["witnesses"], [])

    def test_apalache_in_report_when_present(self):
        ce = {"completed": 0, "inflight": 3}
        run = _run_report(VIOLATED, VIOLATED, smt_ce=ce, tlc_witness=ce)
        run["verdict"]["evidence"]["crosscheck"]["apalache"] = {
            "engine": "apalache-mc", "status": VIOLATED,
            "note": "apalache-note", "n_states": 9, "witness": ce}
        rep = crosscheck.build_crosscheck_report(run)
        self.assertEqual(rep["engines"]["apalache"]["status"], VIOLATED)
        self.assertEqual(rep["engines"]["apalache"]["normalized"], VIOLATED)
        self.assertEqual(rep["engines"]["apalache"]["n_states"], 9)
        self.assertEqual(rep["counterexamples"]["apalache"], ce)
        self.assertEqual(rep["agreement"]["apalache"], VIOLATED)
        self.assertIs(rep["agreement"]["agree"], True)  # join unaffected

    def test_apalache_excluded_from_agree(self):
        # SMT proves, TLC violates, Apalache violates: agree must stay
        # False -- Apalache cannot mint or rescue a decision.
        run = _run_report(PROVEN, VIOLATED)
        run["verdict"]["evidence"]["crosscheck"]["apalache"] = {
            "engine": "apalache-mc", "status": VIOLATED,
            "note": "apalache-note", "n_states": 9,
            "witness": {"completed": 0, "inflight": 3}}
        rep = crosscheck.build_crosscheck_report(run)
        self.assertIs(rep["agreement"]["agree"], False)
        self.assertEqual(rep["agreement"]["joined"], UNKNOWN)
        self.assertEqual(rep["agreement"]["apalache"], VIOLATED)


class ItfWitnessTest(unittest.TestCase):
    """The bundled ITF trace refutes spendcap_within_cap (rot.itf replay)."""

    def test_fixture_trace_refutes_spendcap(self):
        from rot.invariants import get
        from rot.itf import ItfEngine
        prop = get("spendcap_within_cap")
        res = ItfEngine(None, trace_path=ITF_FIXTURE).check(None, prop)
        self.assertEqual(res.status, VIOLATED)
        self.assertEqual(res.witness, {"completed": 0, "inflight": 3})
        self.assertEqual(res.n_states, 4)

    def test_clean_trace_does_not_refute(self):
        # A trace that never exceeds the cap must NOT be a violation;
        # rot.itf can only refute, so it reports 'unknown', never proven.
        import tempfile
        from rot.invariants import get
        from rot.itf import ItfEngine
        trace = {
            "vars": ["completed", "inflight"],
            "states": [
                {"completed": 0, "inflight": 0},
                {"completed": 100, "inflight": 1},
                {"completed": 200, "inflight": 0},
            ],
        }
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "clean.itf.json")
        with open(path, "w") as f:
            json.dump(trace, f)
        prop = get("spendcap_within_cap")
        res = ItfEngine(None, trace_path=path).check(None, prop)
        self.assertEqual(res.status, UNKNOWN)
        self.assertIsNone(res.witness)


class CliTest(unittest.TestCase):
    """python -m rot.crosscheck: report build + ITF witness + exit codes."""

    def _write_run_report(self, tmp):
        run = _run_report(VIOLATED, VIOLATED,
                          smt_ce={"completed": 0, "inflight": 3},
                          tlc_witness={"completed": 0, "inflight": 3})
        path = os.path.join(tmp, "run_report.json")
        with open(path, "w") as f:
            json.dump(run, f)
        return path

    def test_main_with_itf_witness(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        run_path = self._write_run_report(tmp)
        out_path = os.path.join(tmp, "crosscheck_report.json")
        rc = crosscheck.main([
            run_path,
            "--witness", "apalache-itf=" + ITF_FIXTURE,
            "--out", out_path,
            "--quiet",
        ])
        self.assertEqual(rc, 0)
        with open(out_path) as f:
            rep = json.load(f)
        self.assertEqual(rep["report"], "crosscheck")
        self.assertIs(rep["agreement"]["agree"], True)
        self.assertEqual(rep["agreement"]["joined"], VIOLATED)
        self.assertEqual(rep["counterexamples"]["smtz3"],
                         {"completed": 0, "inflight": 3})
        self.assertEqual(rep["counterexamples"]["tlc"],
                         {"completed": 0, "inflight": 3})
        wit = [w for w in rep["witnesses"]
               if w.get("name") == "apalache-itf"]
        self.assertEqual(len(wit), 1)
        self.assertEqual(wit[0]["status"], VIOLATED)
        self.assertEqual(wit[0]["counterexample"],
                         {"completed": 0, "inflight": 3})
        self.assertEqual(wit[0]["source"], ITF_FIXTURE)

    def test_main_default_out_path(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        run_path = self._write_run_report(tmp)
        rc = crosscheck.main([run_path, "--quiet"])
        self.assertEqual(rc, 0)
        default_out = os.path.join(tmp, "crosscheck_report.json")
        self.assertTrue(os.path.isfile(default_out))

    def test_main_bad_witness_spec_fails_cleanly(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        run_path = self._write_run_report(tmp)
        rc = crosscheck.main([run_path, "--witness", "no-equals-here",
                              "--quiet"])
        self.assertEqual(rc, 2)

    def test_witness_with_unreadable_trace_is_recorded_as_error(self):
        # An unconvincing witness (missing trace) degrades to an 'error'
        # entry; it never aborts the report build or the join.
        import tempfile
        tmp = tempfile.mkdtemp()
        run_path = self._write_run_report(tmp)
        out_path = os.path.join(tmp, "report.json")
        rc = crosscheck.main([
            run_path,
            "--witness", "apalache-itf=" + os.path.join(tmp, "missing.itf.json"),
            "--out", out_path, "--quiet",
        ])
        self.assertEqual(rc, 0)
        with open(out_path) as f:
            rep = json.load(f)
        self.assertEqual(len(rep["witnesses"]), 1)
        self.assertEqual(rep["witnesses"][0]["status"], "error")
        self.assertIs(rep["agreement"]["agree"], True)  # join unaffected

    def test_side_by_side_lists_engines_and_witness(self):
        ce = {"completed": 0, "inflight": 3}
        rep = crosscheck.build_crosscheck_report(
            _run_report(VIOLATED, VIOLATED, smt_ce=ce, tlc_witness=ce))
        crosscheck.add_witness(rep, {
            "name": "apalache-itf", "status": VIOLATED,
            "counterexample": ce,
        })
        text = crosscheck.format_side_by_side(rep)
        for token in ("smtz3", "tlc", "apalache-itf", "AGREE",
                      "agreement", "spendcap_within_cap"):
            self.assertIn(token, text)

    def test_side_by_side_includes_apalache_row_when_present(self):
        ce = {"completed": 0, "inflight": 3}
        run = _run_report(VIOLATED, VIOLATED, smt_ce=ce, tlc_witness=ce)
        run["verdict"]["evidence"]["crosscheck"]["apalache"] = {
            "engine": "apalache-mc", "status": VIOLATED,
            "note": "apalache-note", "n_states": 9, "witness": ce}
        rep = crosscheck.build_crosscheck_report(run)
        text = crosscheck.format_side_by_side(rep)
        self.assertIn("apalache", text)
        self.assertIn("informational", text)

    def test_side_by_side_omits_apalache_row_when_absent(self):
        rep = crosscheck.build_crosscheck_report(_run_report(PROVEN, PROVEN))
        text = crosscheck.format_side_by_side(rep)
        # The apalache row is only printed when the engine actually ran.
        for line in text.splitlines():
            self.assertFalse(line.strip().startswith("apalache"))


if __name__ == "__main__":
    unittest.main()

