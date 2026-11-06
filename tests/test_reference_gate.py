# -*- coding: utf-8 -*-
"""WS4 -- bidirectional reference gate (``rot replay --gate --bidirectional``).

Verifies ``rot.gate`` (the v2 gate, docs/reference-gate.md):

  * the pure rule helpers (G1-G4), the property evaluator, and the probe-set
    builders -- no toolchain required;
  * the waiver machinery (strict-subset parser, owner+expiry, expired fails);
  * the outcome + exit-code combination (spec §4/§5);
  * the report schema (spec §6) and the Markdown render;
  * the end-to-end gate (``run_bidirectional_gate``) against the locally-built
    ``dogwood`` reference interpreter -- skipped when the binary is absent,
    matching the codebase's engine-degradation convention (binary legs are
    skippable; the stdlib legs always run).

Run: python tests/test_reference_gate.py
"""

import datetime
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.gate as gate  # noqa: E402
import rot.oracle as oracle  # noqa: E402


# A minimal property meta (APW-1 spend-cap shape) for the pure rule tests.
SPENDCAP_META = {
    "action": "Send",
    "field": "amount",
    "kind": "sum",
    "cap": 200,
    "property": "spendcap_within_cap",
}


def _admitted(seq, amount):
    """A reference-admitted decision event (the ``Send`` gated action)."""
    return {"seq": seq, "action": "Send", "amount": amount}


def _ref(seq_decision):
    """A fake ``rot.oracle.run_dogwood_replay`` result (spec: ``decisions``)."""
    return {"ok": True, "error": None, "exit": 0,
            "decisions": [{"seq": s, "timepoint": 0, "decision": d}
                          for s, d in seq_decision],
            "raw": ""}


# ---------------------------------------------------------------------------
# SemanticsProfile (spec §2)
# ---------------------------------------------------------------------------

class ProfileTests(unittest.TestCase):
    def test_default_profile_is_the_pinned_commit(self):
        p = gate.SemanticsProfile()
        self.assertEqual(p.name, gate.DEFAULT_PROFILE_NAME)
        self.assertEqual(p.commit, gate.DEFAULT_COMMIT)
        self.assertIn("reflexive_windows", p.assumptions)

    def test_parse_profile_full_and_short_commit(self):
        full = gate.parse_profile("dogwood-ref@%s" % gate.DEFAULT_COMMIT)
        short = gate.parse_profile("dogwood-ref@%s" % gate.DEFAULT_COMMIT_SHORT)
        self.assertEqual(full.commit, gate.DEFAULT_COMMIT)
        self.assertEqual(short.commit, gate.DEFAULT_COMMIT_SHORT)

    def test_parse_profile_none_defaults(self):
        self.assertEqual(gate.parse_profile(None), gate.SemanticsProfile())

    def test_parse_profile_empty_commit_raises(self):
        with self.assertRaises(ValueError):
            gate.parse_profile("dogwood-ref@")

    def test_parse_profile_rejects_non_string(self):
        with self.assertRaises(ValueError):
            gate.parse_profile(1234)


# ---------------------------------------------------------------------------
# Waivers (spec §4) -- strict-subset parser, owner+expiry, expired fails
# ---------------------------------------------------------------------------

def _write_waivers_yaml(content):
    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="rotn-waiver-")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class WaiverTests(unittest.TestCase):
    def test_parse_valid_waiver(self):
        path = _write_waivers_yaml(
            "- class: APW-4\n  rule: G2\n  owner: nkamoah17\n"
            "  expiry: 2027-02-04\n  reason: per-recipient cap\n")
        try:
            waivers, warnings = gate.parse_waivers(path)
            self.assertEqual(len(waivers), 1)
            w = waivers[0]
            self.assertEqual(w.apw, "APW-4")
            self.assertEqual(w.rule, "G2")
            self.assertEqual(w.owner, "nkamoah17")
            self.assertEqual(w.expiry, datetime.date(2027, 2, 4))
            self.assertIn("per-recipient", w.reason)
            self.assertEqual(w.waiver_id, "APW-4/G2/nkamoah17")
            self.assertEqual(warnings, [])
        finally:
            os.remove(path)

    def test_parse_rejects_extra_key(self):
        path = _write_waivers_yaml(
            "- class: APW-4\n  rule: G2\n  owner: x\n  expiry: 2027-02-04\n"
            "  reason: r\n  severity: critical\n")
        try:
            with self.assertRaises(ValueError):
                gate.parse_waivers(path)
        finally:
            os.remove(path)

    def test_parse_rejects_missing_required_key(self):
        # ``reason`` is optional; a missing *required* key (``owner``) raises.
        path = _write_waivers_yaml(
            "- class: APW-4\n  rule: G2\n  expiry: 2027-02-04\n  reason: r\n")
        try:
            with self.assertRaises(ValueError):
                gate.parse_waivers(path)
        finally:
            os.remove(path)

    def test_parse_rejects_bad_date(self):
        path = _write_waivers_yaml(
            "- class: APW-4\n  rule: G2\n  owner: x\n  expiry: 02/04/2027\n"
            "  reason: r\n")
        try:
            with self.assertRaises(ValueError):
                gate.parse_waivers(path)
        finally:
            os.remove(path)

    def test_parse_missing_file_is_empty_not_error(self):
        waivers, warnings = gate.parse_waivers(
            os.path.join("nonexistent", "waivers.yaml"))
        self.assertEqual(waivers, [])
        self.assertIsInstance(warnings, list)

    def test_is_expired_strictly_before_today(self):
        today = datetime.date(2026, 11, 6)
        w_past = gate.Waiver("APW-4", "G2", "x",
                             datetime.date(2026, 11, 5), "r")
        w_today = gate.Waiver("APW-4", "G2", "x",
                              datetime.date(2026, 11, 6), "r")
        w_future = gate.Waiver("APW-4", "G2", "x",
                               datetime.date(2026, 11, 7), "r")
        self.assertTrue(w_past.is_expired(today))
        self.assertFalse(w_today.is_expired(today))
        self.assertFalse(w_future.is_expired(today))

    def test_find_waiver_matches_class_and_rule(self):
        active = gate.Waiver("APW-4", "G2", "x",
                             datetime.date(2099, 1, 1), "r")
        expired = gate.Waiver("APW-1", "G2", "y",
                              datetime.date(2020, 1, 1), "r")
        waivers = [active, expired]
        self.assertIs(gate.find_waiver(waivers, "APW-4", "G2"),
                      active)
        # An expired waiver is NOT applied (the divergence stays a DISAGREE).
        self.assertIsNone(gate.find_waiver(waivers, "APW-1", "G2"))
        self.assertIsNone(gate.find_waiver(waivers, "APW-2", "G2"))


# ---------------------------------------------------------------------------
# Rules G1-G4 (spec §3) -- fake decision streams, no toolchain
# ---------------------------------------------------------------------------

class RuleTests(unittest.TestCase):
    # -- G1: violation soundness -------------------------------------------
    def test_g1_holds_when_reference_admits_violation(self):
        admitted = [_admitted(0, 200), _admitted(2, 100)]
        g1 = gate.check_g1(SPENDCAP_META, admitted)
        self.assertTrue(g1["reference_admitted"])
        self.assertTrue(g1["property_false_on_admitted"])
        self.assertTrue(g1["holds"])

    def test_g1_fails_when_reference_denies_the_violation(self):
        admitted = [_admitted(2, 100)]
        g1 = gate.check_g1(SPENDCAP_META, admitted)
        self.assertTrue(g1["reference_admitted"])
        self.assertFalse(g1["property_false_on_admitted"])
        self.assertFalse(g1["holds"])

    def test_g1_fails_when_reference_admits_nothing(self):
        g1 = gate.check_g1(SPENDCAP_META, [])
        self.assertFalse(g1["reference_admitted"])
        self.assertFalse(g1["holds"])

    # -- G2: proof soundness -------------------------------------------------
    def test_g2_holds_when_property_holds_on_every_trace(self):
        traces = [{"property_holds": True}, {"property_holds": True}]
        self.assertTrue(gate.check_g2(SPENDCAP_META, traces)["holds"])

    def test_g2_fails_when_any_trace_violates(self):
        traces = [{"property_holds": True}, {"property_holds": False}]
        self.assertFalse(gate.check_g2(SPENDCAP_META, traces)["holds"])

    def test_g2_fails_on_empty_trace_set(self):
        self.assertFalse(gate.check_g2(SPENDCAP_META, [])["holds"])

    # -- G3: decision agreement --------------------------------------------
    def test_g3_holds_when_all_decisions_match(self):
        g3 = gate.check_g3({0: "ALLOW", 2: "DENY"}, {0: "ALLOW", 2: "DENY"})
        self.assertTrue(g3["holds"])
        self.assertEqual(g3["mismatched"], [])

    def test_g3_fails_on_any_mismatch(self):
        g3 = gate.check_g3({0: "ALLOW", 2: "DENY"}, {0: "DENY", 2: "DENY"})
        self.assertFalse(g3["holds"])
        self.assertEqual(g3["mismatched"],
                         [{"seq": 0, "rot": "ALLOW", "ref": "DENY"}])

    def test_g3_ignores_events_missing_on_one_side(self):
        g3 = gate.check_g3({0: "ALLOW", 4: "DENY"}, {0: "ALLOW"})
        self.assertTrue(g3["holds"])

    # -- G4: non-vacuity -----------------------------------------------------
    def test_g4_holds_when_reference_allows_and_denies(self):
        traces = [{"reference_decisions": [
            {"seq": 0, "decision": "ALLOW"},
            {"seq": 2, "decision": "DENY"}]}]
        g4 = gate.check_g4(traces, permit=True)
        self.assertTrue(g4["admitted_any"])
        self.assertTrue(g4["denied_any"])
        self.assertTrue(g4["holds"])

    def test_g4_fails_when_reference_never_denies(self):
        traces = [{"reference_decisions": [
            {"seq": 0, "decision": "ALLOW"},
            {"seq": 2, "decision": "ALLOW"}]}]
        g4 = gate.check_g4(traces, permit=True)
        self.assertTrue(g4["admitted_any"])
        self.assertFalse(g4["denied_any"])
        self.assertFalse(g4["holds"])

    def test_g4_fails_when_reference_never_allows(self):
        traces = [{"reference_decisions": [
            {"seq": 0, "decision": "DENY"},
            {"seq": 2, "decision": "DENY"}]}]
        g4 = gate.check_g4(traces, permit=True)
        self.assertFalse(g4["admitted_any"])
        self.assertTrue(g4["denied_any"])
        self.assertFalse(g4["holds"])

    def test_g4_not_applicable_for_non_permit(self):
        g4 = gate.check_g4([], permit=False)
        self.assertTrue(g4["holds"])
        self.assertIn("non-permit", g4.get("note", ""))

    def test_g4_collects_across_all_traces(self):
        traces = [
            {"reference_decisions": [{"seq": 0, "decision": "ALLOW"}]},
            {"reference_decisions": [{"seq": 0, "decision": "DENY"}]},
        ]
        self.assertTrue(gate.check_g4(traces, permit=True)["holds"])


# ---------------------------------------------------------------------------
# Property evaluator (spec §2, over the reference-admitted events)
# ---------------------------------------------------------------------------

class PropertyTests(unittest.TestCase):
    def test_sum_kind(self):
        meta = dict(SPENDCAP_META)
        self.assertTrue(gate.property_holds(meta, [_admitted(0, 100),
                                                   _admitted(2, 100)]))
        self.assertFalse(gate.property_holds(meta, [_admitted(0, 100),
                                                    _admitted(2, 150)]))

    def test_count_kind(self):
        meta = {"action": "PlaceOrder", "field": "amount", "kind": "count",
                "cap": 1, "property": "approval_single_use"}
        one = [{"seq": 0, "action": "PlaceOrder", "amount": 100}]
        two = [{"seq": 0, "action": "PlaceOrder", "amount": 100},
               {"seq": 2, "action": "PlaceOrder", "amount": 100}]
        self.assertTrue(gate.property_holds(meta, one))
        self.assertFalse(gate.property_holds(meta, two))

    def test_distinct_kind(self):
        meta = {"action": "Send", "field": "recipient", "kind": "distinct",
                "cap": 3, "property": "distinct_within_cap"}

        def _send(seq, recipient):
            return {"seq": seq, "action": "Send", "recipient": recipient}

        # r1, r2, r3 -> 3 distinct <= cap 3 -> holds (r1 repeats, still 3).
        admitted = [_send(0, "r1"), _send(2, "r2"), _send(4, "r3"),
                    _send(6, "r1")]
        self.assertTrue(gate.property_holds(meta, admitted))
        # r1..r4 -> 4 distinct > cap 3 -> fails.
        admitted = [_send(0, "r1"), _send(2, "r2"), _send(4, "r3"),
                    _send(6, "r4")]
        self.assertFalse(gate.property_holds(meta, admitted))

    def test_only_gated_action_counts(self):
        meta = dict(SPENDCAP_META)
        other = {"seq": 0, "action": "GetCart", "amount": 999999}
        self.assertTrue(gate.property_holds(meta, [other, _admitted(2, 100)]))

    def test_unknown_kind_raises(self):
        meta = {"action": "Send", "field": "amount", "kind": "bogus",
                "cap": 1, "property": "x"}
        with self.assertRaises(ValueError):
            gate.property_holds(meta, [])


# ---------------------------------------------------------------------------
# admitted_events + ref_decision_by_seq (the reference-leg bridge)
# ---------------------------------------------------------------------------

class AdmittedEventsTests(unittest.TestCase):
    def test_ref_decision_by_seq_maps_seq_to_decision(self):
        ref = _ref([(0, "ALLOW"), (2, "DENY")])
        self.assertEqual(gate.ref_decision_by_seq(ref),
                         {0: "ALLOW", 2: "DENY"})

    def test_admitted_events_keeps_only_allowed(self):
        events = [_admitted(0, 100), _admitted(2, 100)]
        ref = _ref([(0, "ALLOW"), (2, "DENY")])
        admitted = gate.admitted_events(events, ref)
        self.assertEqual([e["seq"] for e in admitted], [0])

    def test_admitted_events_in_trace_order(self):
        events = [_admitted(0, 100), _admitted(2, 100), _admitted(4, 100)]
        ref = _ref([(4, "ALLOW"), (0, "ALLOW"), (2, "DENY")])
        admitted = gate.admitted_events(events, ref)
        self.assertEqual([e["seq"] for e in admitted], [0, 4])


# ---------------------------------------------------------------------------
# Trace parsing + probe set (spec §2)
# ---------------------------------------------------------------------------

_APW1_LIKE_LINES = [
    '@0 scope(p: "a") Drupe::Action::"Send"::request(input: { amount: 100 }, r: "x")',
    '@1 scope(p: "a") Drupe::Action::"Send"::response(input: { amount: 100 }, r: "x")',
    '@2 scope(p: "a") Drupe::Action::"Send"::request(input: { amount: 100 }, r: "x")',
    '@3 scope(p: "a") Drupe::Action::"Send"::response(input: { amount: 100 }, r: "x")',
]


class TraceParsingTests(unittest.TestCase):
    def test_decision_events_from_lines_extracts_request_lines(self):
        events = gate.decision_events_from_lines(_APW1_LIKE_LINES,
                                                 SPENDCAP_META)
        self.assertEqual([e["seq"] for e in events], [0, 2])
        self.assertEqual([e["action"] for e in events], ["Send", "Send"])
        self.assertEqual([e["amount"] for e in events], [100, 100])

    def test_decision_events_ignores_responses(self):
        events = gate.decision_events_from_lines(_APW1_LIKE_LINES,
                                                 SPENDCAP_META)
        self.assertEqual(len(events), 2)

    def test_concurrent_interleaving_groups_requests_before_responses(self):
        lines = gate.concurrent_interleaving(_APW1_LIKE_LINES, SPENDCAP_META)
        kinds = []
        for line in lines:
            if "::request(" in line:
                kinds.append("req")
            elif "::response(" in line:
                kinds.append("resp")
        self.assertEqual(kinds, ["req", "req", "resp", "resp"])
        self.assertTrue(lines[0].startswith("@0"))
        self.assertTrue(lines[3].startswith("@3"))

    def test_probe_set_sha256_is_deterministic(self):
        probes = [{"id": "witness", "lines": _APW1_LIKE_LINES}]
        h1 = gate.probe_set_sha256(probes)
        h2 = gate.probe_set_sha256(probes)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)
        probes2 = [{"id": "witness", "lines": _APW1_LIKE_LINES + ["@4 x"]}]
        self.assertNotEqual(gate.probe_set_sha256(probes),
                            gate.probe_set_sha256(probes2))


# ---------------------------------------------------------------------------
# Outcome + exit codes (spec §4/§5)
# ---------------------------------------------------------------------------

class OutcomeTests(unittest.TestCase):
    def _waiver(self, cls_, rule, expiry):
        return gate.Waiver(cls_, rule, "nkamoah17", expiry, "r")

    def test_all_hold_is_agree(self):
        rules = {"G1": {"holds": True}, "G2": {"holds": True},
                 "G3": {"holds": True}, "G4": {"holds": True}}
        outcome, waiver = gate.determine_outcome(rules, "proven", True, [])
        self.assertEqual(outcome, gate.AGREE)
        self.assertIsNone(waiver)

    def test_g2_failure_is_disagree_proven(self):
        rules = {"G1": {"holds": True}, "G2": {"holds": False},
                 "G3": {"holds": True}, "G4": {"holds": True}}
        outcome, _ = gate.determine_outcome(rules, "proven", True, [])
        self.assertEqual(outcome, gate.DISAGREE_PROVEN)

    def test_g1_failure_on_violated_is_disagree_violated(self):
        rules = {"G1": {"holds": False}, "G2": {"holds": True},
                 "G3": {"holds": True}, "G4": {"holds": True}}
        outcome, _ = gate.determine_outcome(rules, "violated", True, [])
        self.assertEqual(outcome, gate.DISAGREE_VIOLATED)

    def test_g4_failure_is_vacuous(self):
        rules = {"G1": {"holds": True}, "G2": {"holds": True},
                 "G3": {"holds": True}, "G4": {"holds": False}}
        outcome, _ = gate.determine_outcome(rules, "proven", True, [])
        self.assertEqual(outcome, gate.VACUOUS)

    def test_worst_outcome_wins(self):
        rules = {"G2": {"holds": False}, "G4": {"holds": False}}
        outcome, _ = gate.determine_outcome(rules, "proven", True, [])
        self.assertEqual(outcome, gate.DISAGREE_PROVEN)

    def test_active_waiver_downgrades_to_labeled_divergence(self):
        rules = {"G2": {"holds": False}}
        waiver = self._waiver("APW-4", "G2", datetime.date(2099, 1, 1))
        outcome, got = gate.determine_outcome(
            rules, "proven", True, [waiver], "APW-4")
        self.assertEqual(outcome, gate.LABELED_DIVERGENCE)
        self.assertIs(got, waiver)

    def test_expired_waiver_does_not_downgrade(self):
        rules = {"G2": {"holds": False}}
        waiver = self._waiver("APW-4", "G2", datetime.date(2020, 1, 1))
        outcome, got = gate.determine_outcome(
            rules, "proven", True, [waiver], "APW-4")
        self.assertEqual(outcome, gate.DISAGREE_PROVEN)
        self.assertIsNone(got)

    def test_waiver_on_wrong_rule_does_not_apply(self):
        rules = {"G2": {"holds": False}}
        waiver = self._waiver("APW-4", "G1", datetime.date(2099, 1, 1))
        outcome, _ = gate.determine_outcome(
            rules, "proven", True, [waiver], "APW-4")
        self.assertEqual(outcome, gate.DISAGREE_PROVEN)

    def test_worse_outcome_helper(self):
        self.assertEqual(gate._worse_outcome(gate.AGREE,
                                             gate.DISAGREE_PROVEN),
                         gate.DISAGREE_PROVEN)
        self.assertEqual(gate._worse_outcome(gate.VACUOUS,
                                             gate.LABELED_DIVERGENCE),
                         gate.VACUOUS)

    def test_exit_code_all_agree_is_zero(self):
        self.assertEqual(gate.gate_exit_code(
            [gate.AGREE, gate.LABELED_DIVERGENCE], 0), 0)

    def test_exit_code_any_disagree_is_one(self):
        self.assertEqual(gate.gate_exit_code(
            [gate.AGREE, gate.DISAGREE_PROVEN], 0), 1)
        self.assertEqual(gate.gate_exit_code(
            [gate.AGREE, gate.VACUOUS], 0), 1)

    def test_exit_code_unknown_over_threshold_is_two(self):
        # 3 UNKNOWNs vs threshold 1 -> 3 > 1 -> exit 2.
        self.assertEqual(gate.gate_exit_code(
            [gate.AGREE, gate.UNKNOWN, gate.UNKNOWN, gate.UNKNOWN], 3), 2)
        # 1 UNKNOWN vs threshold 1 -> 1 > 1 is False -> stays a pass.
        self.assertEqual(gate.gate_exit_code([gate.UNKNOWN], 1), 0)
        # Raising the threshold to the count keeps it a pass (3rd arg).
        self.assertEqual(gate.gate_exit_code(
            [gate.UNKNOWN, gate.UNKNOWN, gate.UNKNOWN], 3, 3), 0)

    def test_exit_code_disagree_dominates_unknown(self):
        self.assertEqual(gate.gate_exit_code(
            [gate.DISAGREE_VIOLATED, gate.UNKNOWN, gate.UNKNOWN], 3), 1)


# ---------------------------------------------------------------------------
# Report schema (spec §6)
# ---------------------------------------------------------------------------

class ReportSchemaTests(unittest.TestCase):
    REQUIRED_ROW_FIELDS = (
        "policy", "policy_sha256", "apw_class", "profile",
        "reference_commit", "engine", "bounds", "witness",
        "probe_set_sha256", "traces", "rules", "outcome", "waiver_id",
    )

    def test_base_row_has_the_spec_minimum_fields(self):
        cls = {"apw": "APW-1", "buggy": "b.dw", "correct": "c.dw",
               "trace": "t.log"}
        row = gate._base_row(cls, dict(SPENDCAP_META), gate.SemanticsProfile(),
                             "hash")
        for field in self.REQUIRED_ROW_FIELDS:
            self.assertIn(field, row, "missing spec §6 field %r" % field)
        self.assertEqual(row["profile"]["name"], gate.DEFAULT_PROFILE_NAME)
        self.assertEqual(row["reference_commit"], gate.DEFAULT_COMMIT)
        self.assertEqual(row["apw_class"], "APW-1")

    def test_trace_entry_has_the_spec_minimum_fields(self):
        probe = {"id": "witness", "kind": "witness"}
        admitted = [_admitted(0, 100)]
        ref = _ref([(0, "ALLOW")])
        entry = gate._trace_entry(probe, admitted, ref, SPENDCAP_META)
        for field in ("id", "reference_decisions", "admitted_total",
                      "property_holds"):
            self.assertIn(field, entry)
        self.assertEqual(entry["id"], "witness")
        self.assertEqual(entry["admitted_total"], 1)
        self.assertTrue(entry["property_holds"])
        self.assertEqual(entry["reference_decisions"],
                         [{"seq": 0, "decision": "ALLOW"}])

    def test_render_markdown_contains_outcome_table_and_waiver(self):
        result = {
            "profile": gate.SemanticsProfile().to_dict(),
            "reference_commit": gate.DEFAULT_COMMIT,
            "engine": gate.ENGINE_LABEL,
            "exit_code": 0,
            "rows": [{
                "apw_class": "APW-4",
                "outcome": gate.LABELED_DIVERGENCE,
                "waiver_id": "APW-4/G2/nkamoah17",
                "property": "distinct_within_cap",
                "model_verdict": {"buggy": "VIOLATED", "correct": "PROVEN"},
                "policy_sha256": "abc123" * 5,
                "probe_set_sha256": "def456" * 5,
                "traces": [], "rules": {},
            }],
        }
        md = gate.render_markdown(result)
        self.assertIn("APW-4", md)
        self.assertIn(gate.LABELED_DIVERGENCE, md)
        self.assertIn("APW-4/G2/nkamoah17", md)
        self.assertIn("Waived", md)

    def test_write_report_emits_json_and_md(self):
        result = {
            "profile": gate.SemanticsProfile().to_dict(),
            "reference_commit": gate.DEFAULT_COMMIT,
            "engine": gate.ENGINE_LABEL,
            "exit_code": 0,
            "rows": [],
        }
        out_dir = tempfile.mkdtemp(prefix="rotn-gate-report-")
        try:
            json_path, md_path = gate.write_report(result, out_dir)
            self.assertTrue(os.path.isfile(json_path))
            self.assertTrue(os.path.isfile(md_path))
            import json
            with open(json_path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["engine"], gate.ENGINE_LABEL)
        finally:
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# End-to-end gate against the real dogwood reference (binary legs)
# ---------------------------------------------------------------------------

@unittest.skipIf(oracle.find_dogwood() is None,
                 "dogwood reference binary not present (Phase-0 build absent)")
class ReferenceGateEndToEndTests(unittest.TestCase):
    """Binary-dependent: run the full bidirectional gate against the local
    ``dogwood`` reference interpreter. Skipped when the binary is absent."""

    def test_first_run_outcomes_match_spec_section_7(self):
        result = gate.run_bidirectional_gate(
            binary=oracle.find_dogwood(), unknown_threshold=3)
        by_apw = {r["apw_class"]: r for r in result["rows"]}
        # APW-1: AGREE (reference 2 ALLOW / 2 DENY on the witness).
        self.assertEqual(by_apw["APW-1"]["outcome"], gate.AGREE)
        # APW-4: LABELED-DIVERGENCE (waived per gate/waivers.yaml).
        self.assertEqual(by_apw["APW-4"]["outcome"], gate.LABELED_DIVERGENCE)
        self.assertEqual(by_apw["APW-4"]["waiver_id"],
                         "APW-4/G2/nkamoah17")
        # APW-3 / APW-5 / APW-6: UNKNOWN (no lowering, never a pass).
        for apw in ("APW-3", "APW-5", "APW-6"):
            self.assertEqual(by_apw[apw]["outcome"], gate.UNKNOWN)
        # The exit code is a valid spec §5 value.
        self.assertIn(result["exit_code"], (0, 1, 2, 3))

    def test_apw2_is_measured_not_silent_pass(self):
        result = gate.run_bidirectional_gate(
            binary=oracle.find_dogwood(), unknown_threshold=3)
        by_apw = {r["apw_class"]: r for r in result["rows"]}
        apw2 = by_apw["APW-2"]
        # APW-2 is either AGREE or an honest DISAGREE-PROVEN (the
        # concurrent-replay divergence); it must never be a silent pass.
        self.assertIn(apw2["outcome"],
                      (gate.AGREE, gate.DISAGREE_PROVEN))


if __name__ == "__main__":
    unittest.main(verbosity=2)