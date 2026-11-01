# -*- coding: utf-8 -*-
"""Phase 7 gate: evidence -- the three evidence layers
(joern-primary-ab-plan Phase 7).

The verifier's output is an auditable **evidence artifact**, not just a
verdict.  The gates (plan Phase 7):

  * **the A/B winner table** (``rotn_research.ab.winner_table``) is compact,
    deterministic, memoized, and agrees with the full A/B result (the
    default frontend, chosen by measurement, not assertion);
  * **the two-layer agreement** (``rot.cpg4.two_layer_section``) is
    fail-closed: a ``PROVEN`` the static ground truth threatens is
    ``unknown`` (never a silent false negative); a ``VIOLATED`` is never
    upgraded; the rule is cited on every row;
  * **the coach** (Product 2) reads both branches of the SAME decision:
    ``allowed_now`` is the complement of ``blocked`` (the two readings of
    one guard never disagree), and the deny branch is named
    (``spend_deny`` / ``contact_deny``) with its guard;
  * **the claim packet** (``rot.cpg4``) carries the three evidence layers
    (``two_layer`` + ``ab`` + ``retention``) and the **wedge** (the A/B
    winner frontend + the two-layer verdicts + the source-pinned
    counterexample); the ``manifest_id`` is still byte-stable;
  * **the VerdictReport** (``rot.verdicts``) carries the same sections
    (JSON + Markdown) when a run has them -- and is unchanged when it
    does not (the positional signature is backward-compatible);
  * **Product 3** (``rot.compliance.claim_packet_compliance``) reads the
    packet as SOC 2 + AIUC-1 evidence: ``proven`` only when every shape's
    two-layer verdict is PROVEN; any VIOLATED -> ``violated`` (AIUC-1 is
    touched); UNKNOWN is never read as proven (fail-closed); ``None`` in
    -> ``None`` out.

Deterministic, offline, stdlib-only.

Run: python -m pytest tests/test_phase7_evidence.py -v
"""

import json
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rotn_research.ab import (AB_TABLE_SCHEMA, reset_winner_table_cache, winner_table)  # noqa: E402
from rot.compliance import (AIUC_1, SOC2_CC61, SOC2_CC63,  # noqa: E402
                            claim_packet_compliance)
from rot.config import Config  # noqa: E402
from rot.crosscheck import TWO_LAYER_RULE  # noqa: E402
from rot.cpg4 import (P1_SHAPES, build_claim_packet, claim_packet_for_cpg,  # noqa: E402
                      coach_vertical, two_layer_section, verticals)
from rot.frontends.cpg_model import (CpgField, CpgMethod, CpgModel,
                                     CpgType)  # noqa: E402
from rot.verdicts import PROVEN, VIOLATED, Verdict, VerdictReport  # noqa: E402

CFG = Config(max_states=100000)
FIX_CPG = os.path.join(_TESTS_DIR, "fixtures", "cpg", "connector.cpg.json")


def _cpg_model():
    """The committed CPG fixture (a Joern/Java scrape of connector.java)."""
    return CpgModel.from_file(FIX_CPG)


def _no_control_model():
    """A plain logging helper: no P1 control (E2 -> OUT_OF_SCOPE)."""
    O = "n.Logger"
    m = CpgModel(
        meta={"source": "n/Logger.java"},
        types=[CpgType("Logger", O, owner="n")],
        fields=[CpgField("sink", O + ".sink",
                         type_name="java.io.PrintStream", owner=O)],
        methods=[CpgMethod("log", O + ".log", owner=O, line=3, end_line=4,
                           calls=[], read_fields=["sink"], written_fields=[],
                           defs=["msg"], args=["msg"], ret_type="void")],
        edges=[], taint_sources=[], taint_sinks=[],
    )
    assert not m.validate()
    return m


def _fake_verdict(status, static=None):
    """A minimal verdict with (optionally) a static soundness record."""
    v = Verdict(status, "test_prop", "symbolic")
    ev = {}
    if static is not None:
        ev["abstraction_soundness"] = static
    v.evidence = ev
    return v


def _fake_verticals(**shapes):
    """A verticals dict shaped like :func:`rot.cpg4.verticals` output."""
    return dict((shape, {"candidate": None, "ir": None, "verdict": verdict})
                for shape, verdict in shapes.items())


# ---------------------------------------------------------------------------
# the A/B winner table (the citable decision)
# ---------------------------------------------------------------------------

class WinnerTableTest(unittest.TestCase):
    """The compact A/B winner table: the decision, citable and stable."""

    def test_table_shape(self):
        t = winner_table()
        self.assertIsNotNone(t, "the bench corpus is present in this repo")
        self.assertEqual(t["schema"], AB_TABLE_SCHEMA)
        self.assertIn(t["winner"], t["per_frontend"],
                      "the winner must be one of the frontends measured")
        self.assertTrue(t["corpus"], "the corpus list must not be empty")
        for frontend, agg in t["per_frontend"].items():
            self.assertIsInstance(agg["hard_gate_pass"], bool, frontend)
            self.assertGreaterEqual(agg["cells"], 0, frontend)
            self.assertGreaterEqual(agg["unavailable"], 0, frontend)
            self.assertIsInstance(agg["ranking"], list, frontend)

    def test_winner_agrees_with_full_ab(self):
        # The compact table's winner is the full A/B's lexicographic winner.
        from rotn_research.ab import lexicographic_winner, run_ab
        self.assertEqual(winner_table()["winner"],
                         lexicographic_winner(run_ab()))

    def test_memoized(self):
        # Repeated calls return the SAME object (the bench corpus is static).
        self.assertIs(winner_table(), winner_table())

    def test_reset_is_deterministic(self):
        t1 = winner_table()
        reset_winner_table_cache()
        t2 = winner_table()
        self.assertIsNot(t1, t2, "the reset must recompute a fresh table")
        self.assertEqual(t1, t2, "recomputation must be deterministic")


# ---------------------------------------------------------------------------
# the two-layer agreement section (fail-closed)
# ---------------------------------------------------------------------------

class TwoLayerSectionTest(unittest.TestCase):
    """The two-layer section is a pure, fail-closed join of the layers."""

    def test_fixture_statuses(self):
        tl = two_layer_section(verticals(_cpg_model(), CFG))
        self.assertEqual(set(tl), set(P1_SHAPES))
        # budget ENFORCED + static agreement -> PROVEN stands.
        self.assertEqual(tl["budget"]["status"], "proven")
        self.assertTrue(tl["budget"]["agreement"])
        # label_flow BYPASSABLE -> VIOLATED stands (never upgraded).
        self.assertEqual(tl["label_flow"]["status"], "violated")
        for row in tl.values():
            self.assertEqual(row["rule"], TWO_LAYER_RULE)

    def test_static_threat_blocks_proven(self):
        # A PROVEN the static ground truth threatens is UNKNOWN (fail-
        # closed): never a silent false negative, the disagreement named.
        tl = two_layer_section(_fake_verticals(
            shape=_fake_verdict(PROVEN, static={"status": "unsound"})))
        row = tl["shape"]
        self.assertEqual(row["status"], "unknown")
        self.assertFalse(row["agreement"])
        self.assertNotEqual(row["disagreement"], "")

    def test_violated_is_never_upgraded(self):
        # Even a clean static record keeps the refutation (refines, never
        # weakens).
        tl = two_layer_section(_fake_verticals(
            shape=_fake_verdict(VIOLATED, static={"status": "agreement"})))
        self.assertEqual(tl["shape"]["status"], "violated")

    def test_no_static_layer_does_not_block(self):
        # No CPG ground truth -> the static layer does not apply; the formal
        # verdict stands (Layer B = not applicable, not a threat).
        tl = two_layer_section(_fake_verticals(shape=_fake_verdict(PROVEN)))
        self.assertEqual(tl["shape"]["status"], "proven")
        self.assertIsNone(tl["shape"]["static"])



# ---------------------------------------------------------------------------
# the coach: both branches of the same decision (Product 2)
# ---------------------------------------------------------------------------

class CoachPhase7Test(unittest.TestCase):
    """The coach says both readings of the one extracted control."""

    def test_allowed_now_is_the_complement_of_blocked(self):
        # blocked XOR allowed_now: the two readings of the SAME guard never
        # disagree (one extraction, two sinks).
        for shape in P1_SHAPES:
            coach = coach_vertical(_cpg_model(), shape, CFG)
            blocked = coach["to_proceed"]["blocked"]
            self.assertEqual(coach["allowed_now"], (not blocked),
                             "%s: allowed_now must be not blocked" % shape)

    def test_deny_branch_is_named_with_guard(self):
        # The deny branch is the *other* branch of the same policy decision,
        # read from the same IR, named + guarded.
        coach_b = coach_vertical(_cpg_model(), "budget", CFG)
        self.assertEqual(coach_b["deny_branch"]["action"], "spend_deny")
        self.assertTrue(coach_b["deny_branch"]["guard"])
        coach_l = coach_vertical(_cpg_model(), "label_flow", CFG)
        self.assertEqual(coach_l["deny_branch"]["action"], "contact_deny")
        self.assertTrue(coach_l["deny_branch"]["guard"])

    def test_no_control_has_no_deny_branch(self):
        # Out of scope: no decision action is recognized, so there is no deny
        # branch to name (honest, not fabricated).
        coach = coach_vertical(_no_control_model(), "budget", CFG)
        self.assertIsNone(coach["action"])
        self.assertNotIn("deny_branch", coach)


# ---------------------------------------------------------------------------
# the claim packet: the three evidence layers + the wedge
# ---------------------------------------------------------------------------

class ClaimPacketPhase7Test(unittest.TestCase):
    """The claim packet carries the evidence layers and stays stable."""

    def test_packet_carries_evidence_sections(self):
        p = claim_packet_for_cpg(_cpg_model(), CFG)
        for key in ("two_layer", "wedge", "ab", "retention"):
            self.assertIn(key, p, "missing packet section: " + key)
        self.assertEqual(set(p["two_layer"]), set(P1_SHAPES))
        self.assertEqual(set(p["retention"]), set(P1_SHAPES))

    def test_wedge_is_assembled_from_the_sections(self):
        # The wedge is the packet's own sections joined: the A/B winner
        # frontend + the two-layer verdicts + the source-pinned
        # counterexample.
        p = claim_packet_for_cpg(_cpg_model(), CFG)
        wedge = p["wedge"]
        self.assertEqual(wedge["frontend"], p["ab"]["winner"])
        self.assertEqual(
            wedge["two_layer"],
            dict((s, p["two_layer"][s]["status"]) for s in sorted(P1_SHAPES)))
        for shape in P1_SHAPES:
            self.assertIn(shape, wedge["counterexample"])

    def test_wedge_counterexample_is_source_pinned(self):
        # The VIOLATED shape's witness is pinned to the decision method's
        # source line (citable); the PROVEN shape carries no witness.
        p = claim_packet_for_cpg(_cpg_model(), CFG)
        ce = p["wedge"]["counterexample"]
        self.assertEqual(ce["label_flow"]["status"], "violated")
        self.assertTrue(ce["label_flow"]["witness_lines"],
                        "a VIOLATED must name its witness lines")
        self.assertIsNotNone(ce["label_flow"]["source"]["start_line"])
        self.assertEqual(ce["budget"]["status"], "proven")
        self.assertIsNone(ce["budget"]["witness"])

    def test_ab_section_is_the_winner_table(self):
        # The packet's ab section is exactly the compact winner table.
        p = claim_packet_for_cpg(_cpg_model(), CFG)
        self.assertEqual(p["ab"], winner_table())

    def test_ab_is_part_of_the_body(self):
        # The ab section is in the hashed body (present -> a different
        # manifest_id than the packet without it).
        m = _cpg_model()
        vdict = verticals(m, CFG)
        cdict = dict((s, coach_vertical(m, s, CFG)) for s in P1_SHAPES)
        with_ab = build_claim_packet(m, vdict, cdict,
                                     shapes=list(P1_SHAPES), ab=winner_table())
        without_ab = build_claim_packet(m, vdict, cdict,
                                       shapes=list(P1_SHAPES), ab=None)
        self.assertIn("ab", with_ab)
        self.assertNotIn("ab", without_ab)
        self.assertNotEqual(with_ab["manifest_id"], without_ab["manifest_id"])

    def test_manifest_still_byte_stable(self):
        # The evidence layers do not break reproducibility: same scrape +
        # config -> same manifest_id (the A/B table is memoized/deterministic).
        m = _cpg_model()
        self.assertEqual(claim_packet_for_cpg(m, CFG)["manifest_id"],
                         claim_packet_for_cpg(m, CFG)["manifest_id"])

    def test_packet_json_serializable(self):
        p1 = claim_packet_for_cpg(_cpg_model(), CFG)
        p2 = claim_packet_for_cpg(_cpg_model(), CFG)
        self.assertEqual(json.loads(json.dumps(p1, sort_keys=True)),
                         json.loads(json.dumps(p2, sort_keys=True)))


# ---------------------------------------------------------------------------
# the VerdictReport: the same sections, optional
# ---------------------------------------------------------------------------

class VerdictReportPhase7Test(unittest.TestCase):
    """The report carries the evidence layers when a run has them."""

    def _sections(self):
        return {
            "two_layer": {
                "formal": PROVEN, "static": "agreement", "status": "proven",
                "agreement": True, "disagreement": "", "rule": TWO_LAYER_RULE,
            },
            "ab": winner_table(),
            "retention": {
                "shape": "budget",
                "kept": [{"from": "a", "to": "b", "type": "REACHING_DEF",
                          "status": "kept", "relevance": "taint_critical",
                          "evidence": "on a source -> sink path"}],
                "dropped": [], "unknown": [], "irrelevant": [],
            },
        }

    def _verdict(self):
        v = Verdict(PROVEN, "P1 budget control", "symbolic")
        v.evidence = {"candidate": True, "pattern": "budget"}
        return v

    def test_sections_in_to_dict(self):
        sec = self._sections()
        r = VerdictReport("t", "P1 budget control", "symbolic", {}, {},
                          self._verdict(), **sec)
        d = r.to_dict()
        self.assertEqual(d["two_layer"], sec["two_layer"])
        self.assertEqual(d["ab"], sec["ab"])
        self.assertEqual(d["retention"], sec["retention"])

    def test_sections_in_to_markdown(self):
        r = VerdictReport("t", "P1 budget control", "symbolic", {}, {},
                          self._verdict(), **self._sections())
        md = r.to_markdown()
        self.assertIn("## Two-layer agreement", md)
        self.assertIn("## A/B winner", md)
        self.assertIn("## Retention manifest", md)

    def test_backward_compatible_without_sections(self):
        # The positional signature is unchanged; absent sections add neither
        # JSON keys nor Markdown headings.
        r = VerdictReport("t", "prop", "symbolic", {}, {}, self._verdict())
        d = r.to_dict()
        for key in ("two_layer", "ab", "retention"):
            self.assertNotIn(key, d)
        for heading in ("## Two-layer agreement", "## A/B winner",
                        "## Retention manifest"):
            self.assertNotIn(heading, r.to_markdown())


# ---------------------------------------------------------------------------
# Product 3: the claim packet as underwriter evidence
# ---------------------------------------------------------------------------

class ClaimPacketComplianceTest(unittest.TestCase):
    """The packet reads as SOC 2 + AIUC-1 evidence (fail-closed)."""

    def test_fixture_packet_is_violated(self):
        # The committed fixture's label_flow is BYPASSABLE -> the packet
        # reads violated (the agent can act beyond policy: AIUC-1).
        p = claim_packet_for_cpg(_cpg_model(), CFG)
        sec = claim_packet_compliance(p)
        self.assertEqual(sec["result"], "violated")
        self.assertTrue({AIUC_1, SOC2_CC61, SOC2_CC63}
                        <= set(sec["controls_touched"]))
        self.assertTrue(sec["evidence"]["discharge"])
        # The evidence cites the packet itself (schema + manifest_id).
        self.assertEqual(sec["evidence"]["claim_packet"]["manifest_id"],
                         p["manifest_id"])

    def test_proven_only_when_every_shape_is_proven(self):
        sec = claim_packet_compliance({
            "two_layer": {"budget": {"status": "proven"},
                          "label_flow": {"status": "proven"}},
        })
        self.assertEqual(sec["result"], "proven")

    def test_unknown_is_never_read_as_proven(self):
        # Fail-closed: one undecided shape blocks the proven reading.
        sec = claim_packet_compliance({
            "two_layer": {"budget": {"status": "proven"},
                          "label_flow": {"status": "unknown"}},
        })
        self.assertEqual(sec["result"], "unknown")

    def test_violated_dominates(self):
        sec = claim_packet_compliance({
            "two_layer": {"budget": {"status": "proven"},
                          "label_flow": {"status": "violated"}},
        })
        self.assertEqual(sec["result"], "violated")

    def test_fallback_reads_the_verticals_verdicts(self):
        # A pre-Phase-7 packet (no two_layer section) is read off the
        # verticals' verdicts -- the same fail-closed reading.
        sec = claim_packet_compliance({
            "verticals": {"budget": {"verdict": {"status": "proven"}},
                          "label_flow": {"verdict": {"status": "proven"}}},
        })
        self.assertEqual(sec["result"], "proven")

    def test_none_in_none_out(self):
        self.assertIsNone(claim_packet_compliance(None))


# ---------------------------------------------------------------------------
# the production CPG path: the written report carries the sections
# ---------------------------------------------------------------------------

class PipelinePhase7Test(unittest.TestCase):
    """``pipeline._run_cpg_frontend`` writes a report with the evidence."""

    def test_report_carries_the_evidence_sections(self):
        from pipeline import _run_cpg_frontend
        with tempfile.TemporaryDirectory() as tmp:
            verdict = _run_cpg_frontend(FIX_CPG, None, tmp, quiet=True)
            json_paths = [f for f in os.listdir(tmp) if f.endswith(".json")]
            self.assertTrue(json_paths, "the report JSON must be written")
            with open(os.path.join(tmp, sorted(json_paths)[0])) as fh:
                report = json.load(fh)
            self.assertIn("two_layer", report)
            self.assertIn("ab", report)
            self.assertIn("retention", report)
            # The verdict's own evidence carries the retention manifest
            # (the lossiness discipline ran on the production path).
            self.assertIn("retention", report["verdict"]["evidence"])
            # The two-layer section composes with the final verdict.
            self.assertEqual(report["two_layer"]["formal"], verdict.status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
