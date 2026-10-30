# -*- coding: utf-8 -*-
"""CPG-4 gate: one CPG -> N verticals -> one claim packet.

The assembly gate for the **CPG-4 producer** (``rot.cpg4``): the single
:class:`rot.frontends.cpg_model.CpgModel` scrape drives *both* P1 verticals
(budget + label_flow) -- each through the *same* CPG-2 producer, the *same*
``lower_candidate``, and the *same* CPG-3 soundness cross-check -- and the
results are assembled into **one** deterministic, byte-stable,
JSON-serialisable claim packet with:

* the ``verticals`` (candidate + verdict + the citable source line + the
  witness pinned to a source line),
* the ``abstraction_manifest`` (the ``AbstractionEntry`` rows -- the
  CPG->IR mapping, the auditability contract),
* the ``non_claims`` (spec §6: what the packet does NOT claim),
* the ``coach`` (the source-pinned ``to_proceed`` + ``why``),
* the ``ledger`` (the ordered derivation trail),
* the ``manifest_id`` (SHA-256 over the canonical body -- the manifest
  reproduces: the same scrape + config yield the same id).

The gate (the spec "Done when"): (1) on the fixture, both verticals produce
PROVEN / VIOLATED (the VIOLATED carries the exact witness); (2) the coach's
``to_proceed`` cites a source line (citable); (3) the claim packet's
``manifest_id`` is byte-stable (two calls agree); (4) the full-repo suite does
not regress (run via pytest, not here).

The fixture models are reused from the CPG-2 gate (``test_cpg_extraction``) --
one structural vocabulary.

Run: python -m pytest tests/test_cpg4.py -v
"""

import json
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rot.config import Config
from rot.frontends.cpg import extract_cpg
from rot.frontends.code import PATTERN_BUDGET, PATTERN_LABEL_FLOW
from rot.cpg4 import (SCHEMA, NON_CLAIMS, P1_SHAPES,
                      claim_packet_for_cpg, verticals, vertical,
                      extract_all, lower_all,
                      source_pin, witness_lines, allowed_channels,
                      abstraction_entries, build_claim_packet,
                      coach_vertical, manifest_id)
from test_cpg_extraction import (_cpg_model, _bypassable_budget_model,
                                 _guarded_label_flow_model, _no_control_model)

CFG = Config(max_states=100000)


def _packet(model):
    return claim_packet_for_cpg(model, CFG)


class ClaimPacketGateTest(unittest.TestCase):
    """The spec "Done when" gate on the committed CPG fixture (budget
    ENFORCED + label_flow BYPASSABLE)."""

    def test_both_verticals_produce_verdicts(self):
        p = _packet(_cpg_model())
        b = p["verticals"]["budget"]
        lf = p["verticals"]["label_flow"]
        # budget ENFORCED -> PROVEN (no witness).
        self.assertEqual(b["verdict"]["status"], "proven")
        self.assertIsNone(b["verdict"]["counterexample"])
        # label_flow BYPASSABLE -> VIOLATED with the exact witness.
        self.assertEqual(lf["verdict"]["status"], "violated")
        self.assertEqual(lf["verdict"]["counterexample"],
                         {"holding_private": True, "exfiltrated": True})

    def test_coach_cites_source_line(self):
        """The coach's ``to_proceed`` cites a source line (citable)."""
        p = _packet(_cpg_model())
        for shape in P1_SHAPES:
            coach = p["coach"][shape]
            src = coach["to_proceed"]["source"]
            self.assertIn("filename", src, shape + ": no filename in source")
            self.assertIn("start_line", src, shape + ": no line in source")
            self.assertTrue(src["start_line"] is not None)
            # The human-readable ``why`` names the source line.
            self.assertIn(str(src["start_line"]), coach["why"],
                          "the 'why' must cite the source line")

    def test_manifest_id_byte_stable(self):
        """Two calls over the same scrape + config yield the same id."""
        m = _cpg_model()
        self.assertEqual(claim_packet_for_cpg(m, CFG)["manifest_id"],
                         claim_packet_for_cpg(m, CFG)["manifest_id"])
        # A different scrape yields a different id (the hash is not constant).
        self.assertNotEqual(
            claim_packet_for_cpg(m, CFG)["manifest_id"],
            claim_packet_for_cpg(_bypassable_budget_model(), CFG)["manifest_id"])

    def test_claim_packet_json_serializable(self):
        p = _packet(_cpg_model())
        s = json.dumps(p, sort_keys=True)
        self.assertIsInstance(s, str)
        # And it round-trips to an equal structure.
        self.assertEqual(json.loads(s), json.loads(json.dumps(p)))

    def test_claim_packet_required_keys(self):
        p = _packet(_cpg_model())
        for key in ("schema", "source", "shapes", "verticals",
                    "abstraction_manifest", "non_claims", "coach",
                    "ledger", "manifest_id"):
            self.assertIn(key, p, "missing claim-packet key: " + key)
        self.assertEqual(p["schema"], SCHEMA)
        self.assertEqual(p["shapes"], list(P1_SHAPES))

    def test_non_claims_present(self):
        p = _packet(_cpg_model())
        self.assertEqual(p["non_claims"], list(NON_CLAIMS))
        self.assertGreaterEqual(len(p["non_claims"]), 4,
                                "spec §6: the packet must name what it does "
                                "NOT claim")

    def test_abstraction_manifest_well_formed(self):
        p = _packet(_cpg_model())
        rows = p["abstraction_manifest"]
        self.assertTrue(rows, "the claim packet must carry the CPG->IR "
                              "abstraction manifest")
        for row in rows:
            for field in ("feature", "status", "evidence", "abstraction",
                          "risk"):
                self.assertIn(field, row)
            self.assertIn(row["status"], ("covered", "assumed", "unverified"))


class VerticalsTest(unittest.TestCase):
    """One CPG drives N verticals with no re-derivation."""

    def test_verticals_returns_both_shapes(self):
        v = verticals(_cpg_model(), CFG)
        self.assertEqual(sorted(v), list(P1_SHAPES))
        for shape in P1_SHAPES:
            self.assertIn("candidate", v[shape])
            self.assertIn("verdict", v[shape])

    def test_no_rederivation(self):
        """The vertical's candidate value-matches the CPG-2 producer's output
        (the same producer -- not a re-derived one)."""
        model = _cpg_model()
        v = vertical(model, PATTERN_BUDGET, CFG)
        self.assertEqual(v["candidate"].to_dict(),
                         extract_cpg(model, shape=PATTERN_BUDGET).to_dict())

    def test_extract_all_and_lower_all(self):
        cands = extract_all(_cpg_model())
        self.assertEqual(sorted(cands), list(P1_SHAPES))
        irs = lower_all(cands)
        self.assertEqual(sorted(irs), list(P1_SHAPES))
        self.assertEqual(irs[PATTERN_BUDGET].name, "spendcap-correct")
        self.assertEqual(irs[PATTERN_LABEL_FLOW].name, "noexfil-bypassable")

    def test_out_of_scope_honest_not_silent(self):
        """An out-of-scope vertical is an honest OUT_OF_SCOPE (E2), never a
        silent UNKNOWN, and never dropped from the claim packet."""
        v = vertical(_no_control_model(), PATTERN_BUDGET, CFG)
        self.assertTrue(v["verdict"].is_out_of_scope())
        self.assertIsNone(v["ir"], "no IR for an out-of-scope vertical")
        p = _packet(_no_control_model())
        self.assertIn("budget", p["verticals"], "out-of-scope is kept")
        self.assertEqual(p["verticals"]["budget"]["verdict"]["status"],
                         "out_of_scope")
        self.assertEqual(p["verticals"]["budget"]["verdict"]["status"],
                         "out_of_scope")


class SourcePinningTest(unittest.TestCase):
    """The source-pinning helpers (the citable source line)."""

    def test_source_pin_citable(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_BUDGET)
        pin = source_pin(c)
        self.assertEqual(pin["function"], "canSpend")
        self.assertIn("start_line", pin)
        self.assertIn("end_line", pin)
        self.assertIn("filename", pin)
        self.assertEqual(pin["filename"], "connector.java")

    def test_witness_lines_maps_witness(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW)
        witness = {"holding_private": True, "exfiltrated": True}
        rows = witness_lines(c, witness)
        self.assertEqual([r["variable"] for r in rows],
                         ["exfiltrated", "holding_private"])
        for r in rows:
            self.assertEqual(r["line"], source_pin(c)["start_line"])
            self.assertEqual(r["filename"], "connector.java")

    def test_witness_lines_empty_without_witness(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_BUDGET)
        self.assertEqual(witness_lines(c, None), [])

    def test_allowed_channels_derived_label_flow(self):
        # The fixture's egress is unguarded -> a bypassable channel.
        c = extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW)
        chans = allowed_channels(c)
        self.assertEqual(len(chans), 1)
        self.assertEqual(chans[0]["status"], "bypassable")
        self.assertFalse(chans[0]["guarded"])
        # A guarded egress -> a controlled channel.
        cg = extract_cpg(_guarded_label_flow_model(),
                         shape=PATTERN_LABEL_FLOW)
        chans = allowed_channels(cg)
        self.assertEqual(chans[0]["status"], "controlled")
        self.assertTrue(chans[0]["guarded"])

    def test_allowed_channels_empty_for_budget(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_BUDGET)
        self.assertEqual(allowed_channels(c), [])


class AbstractionManifestTest(unittest.TestCase):
    """The ``AbstractionEntry`` rows (the CPG->IR mapping)."""

    def test_budget_rows(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_BUDGET)
        rows = abstraction_entries(c)
        self.assertEqual(len(rows), 2)
        self.assertIn("cap", rows[0]["feature"])
        self.assertEqual(rows[1]["status"], "assumed",
                         "the cap constant is an assumption, not a claim")

    def test_label_flow_rows(self):
        c = extract_cpg(_cpg_model(), shape=PATTERN_LABEL_FLOW)
        rows = abstraction_entries(c)
        self.assertEqual(len(rows), 2)
        self.assertIn("egress", rows[0]["feature"])
        self.assertEqual(rows[1]["status"], "assumed",
                         "the source/sink classifier is name-based")

    def test_manifest_id_pure(self):
        # The hash is a pure function of the canonical body.
        body = {"a": 1, "b": [1, 2, 3]}
        self.assertEqual(manifest_id(body),
                         manifest_id({"b": [1, 2, 3], "a": 1}))
        self.assertNotEqual(manifest_id(body), manifest_id({"a": 2, "b": []}))


class CoachTest(unittest.TestCase):
    """The P2 coach on a CPG-derived vertical (source-pinned)."""

    def test_budget_coach_shape(self):
        c = coach_vertical(_cpg_model(), PATTERN_BUDGET, CFG)
        self.assertEqual(c["action"], "spend_ok")
        self.assertIn("source", c["to_proceed"])
        self.assertIn("filename", c["to_proceed"]["source"])

    def test_label_flow_coach_shape(self):
        c = coach_vertical(_cpg_model(), PATTERN_LABEL_FLOW, CFG)
        self.assertEqual(c["action"], "contact_outsider")
        self.assertIn("allowed_channels", c,
                      "label_flow coach carries the derived label flow")

    def test_build_claim_packet_assembles(self):
        model = _cpg_model()
        v = verticals(model, CFG)
        c = dict((s, coach_vertical(model, s, CFG)) for s in P1_SHAPES)
        p = build_claim_packet(model, v, c)
        self.assertIn("manifest_id", p)
        self.assertEqual(p["shapes"], list(P1_SHAPES))
        self.assertTrue(p["ledger"], "the derivation trail is present")


if __name__ == "__main__":
    unittest.main(verbosity=2)