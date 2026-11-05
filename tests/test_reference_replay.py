# -*- coding: utf-8 -*-
"""Phase 3 -- reference-interpreter oracle (``rot replay --oracle dogwood``).

Verifies the "Dogwood admits it, ROTN catches it" side-by-side:

  * the pure helpers (decision parsing, summarising, the gate predicate, and
    the three gate-class fixtures) are correct -- these run with no toolchain;
  * the end-to-end gate (``run_gate``) replays the APW-1/2/4 buggy+correct
    policies + witness traces against the locally-built ``dogwood`` reference
    interpreter and asserts the gate (ROTN=VIOLATED and the buggy policy
    admits the violation on the same trace).  Skipped when the ``dogwood``
    binary is absent, matching the codebase's engine-degradation convention.

Run: python tests/test_reference_replay.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.oracle as oracle  # noqa: E402


class OracleHelperTests(unittest.TestCase):
    """Pure helpers -- no toolchain required."""

    def test_parse_decisions_extracts_seq_timepoint_decision(self):
        raw = ("@0 (time point 0): ALLOW  [rules: 0]\n"
               "@2 (time point 1): DENY\n"
               "some other line\n"
               "@4 (time point 2): DENY")
        got = oracle.parse_decisions(raw)
        self.assertEqual(
            got,
            [{"seq": 0, "timepoint": 0, "decision": "ALLOW"},
             {"seq": 2, "timepoint": 1, "decision": "DENY"},
             {"seq": 4, "timepoint": 2, "decision": "DENY"}])

    def test_parse_decisions_ignores_noise(self):
        self.assertEqual(oracle.parse_decisions("no decisions here"), [])
        self.assertEqual(oracle.parse_decisions(""), [])

    def test_summarize_counts_admitted_and_denied(self):
        d = [{"decision": "ALLOW"}, {"decision": "DENY"},
             {"decision": "DENY"}]
        s = oracle.summarize(d)
        self.assertEqual(s["n_decisions"], 3)
        self.assertEqual(s["n_admitted"], 1)
        self.assertEqual(s["n_denied"], 2)
        self.assertTrue(s["admitted_any"])
        self.assertTrue(s["denied_any"])

    def test_side_by_side_gate_requires_both_legs(self):
        admits = {"ok": True, "error": None, "decisions": [
            {"seq": 0, "timepoint": 0, "decision": "ALLOW"}],
            "raw": "", "exit": 0}
        denies = {"ok": True, "error": None, "decisions": [
            {"seq": 0, "timepoint": 0, "decision": "DENY"}],
            "raw": "", "exit": 0}
        ok = oracle.side_by_side("violated", {"inflight": 3}, "p", admits)
        self.assertTrue(ok["gate"]["agreement"])
        no = oracle.side_by_side("violated", {"inflight": 3}, "p", denies)
        self.assertFalse(no["gate"]["agreement"])
        no2 = oracle.side_by_side("proven", None, "p", admits)
        self.assertFalse(no2["gate"]["agreement"])
        self.assertTrue(no2["gate"]["reference_admitted"])
        self.assertFalse(no2["gate"]["rot_violated"])

    def test_gate_classes_are_three_and_point_at_existing_files(self):
        classes = oracle.gate_classes()
        self.assertEqual([c["apw"] for c in classes],
                         ["APW-1", "APW-2", "APW-4"])
        for c in classes:
            for key in ("buggy", "correct", "trace", "schema"):
                self.assertTrue(
                    os.path.isfile(c[key]),
                    "missing %s for %s: %s" % (key, c["apw"], c[key]))

    def test_gate_fixtures_lower_to_their_apw_class(self):
        """The gate proves what it claims: each gate class's buggy fixture
        must lower to *that* APW class's protocol.

        Regression: the APW-2 row pointed at ``apw2-permit-buggy.dw`` (the
        Classmethod ``formerly within <approval-event>`` gating shape) while
        the dispatcher classified that shape as taint-egress (APW-3) -- the
        gate "passed" APW-2 by proving the *wrong* bug class.  This test
        pins the fixture-to-class mapping the gate relies on.
        """
        from rot.dw import parse_file
        expected = {
            "APW-1": "SPENDCAP",
            "APW-2": "APPROVAL_REPLAY",
            "APW-4": "DISTINCT_COUNT",
        }
        for c in oracle.gate_classes():
            ir = parse_file(c["buggy"]).to_ir()
            self.assertEqual(
                ir.metadata.get("protocol"), expected[c["apw"]],
                "%s gate fixture %s lowers to the wrong class (protocol=%r)"
                % (c["apw"], os.path.basename(c["buggy"]),
                   ir.metadata.get("protocol")))
            self.assertEqual(ir.metadata.get("buggy"), True,
                             "%s gate fixture must be the buggy variant"
                             % c["apw"])

    # -- E4: events_to_trace (pure, no binary) -------------------------------

    E4_META = {
        "session_id": "sess-42",
        "action": "TransferTarget___transfer",
        "resource": "arn:aws:bedrock-agentcore:us-east-1:123:gateway/gw",
    }

    def _events(self, n, amount=100):
        return [{"seq": i, "kind": "request", "amount": amount,
                 "ts": "2026-11-05T00:00:0%dZ" % i,
                 "live_verdict": "ADMITTED"} for i in range(1, n + 1)]

    def test_events_to_trace_five_events_ten_timepoints(self):
        lines = oracle.events_to_trace(self._events(5), self.E4_META)
        self.assertEqual(len(lines), 10)
        # @N numbering is a contiguous 0..9, request before response per fire
        self.assertEqual([l.split(" ", 1)[0] for l in lines],
                         ["@%d" % i for i in range(10)])
        for k in range(5):
            self.assertIn("::request(", lines[2 * k])
            self.assertIn("request_context(input: { amount: 100 })",
                          lines[2 * k])
            self.assertIn("::response(", lines[2 * k + 1])
            self.assertNotIn("request_context(", lines[2 * k + 1])
            # per-event requestId on BOTH lines of the pair
            for l in (lines[2 * k], lines[2 * k + 1]):
                self.assertIn('requestId: "req-%d"' % (k + 1), l)
                self.assertNotIn('requestId: "req-%d"' % (k + 2), l)

    def test_events_to_trace_line_zero_is_exact(self):
        meta = self.E4_META
        principal = 'AgentCore::OAuthUser::"%s"' % meta["session_id"]
        resource = 'AgentCore::Gateway::"%s"' % meta["resource"]
        action = 'AgentCore::Action::"TransferTarget___transfer"'
        scope = "scope(principal: %s, resource: %s)" % (principal, resource)
        fields = ("input: { amount: 100 }, callerPrincipal: %s, "
                  "callerResource: %s, requestId: \"req-1\""
                  % (principal, resource))
        expected = ("@0 %s request_context(input: { amount: 100 }) "
                    "%s::request(%s)" % (scope, action, fields))
        self.assertEqual(oracle.events_to_trace(self._events(1),
                                                self.E4_META)[0], expected)

    def test_events_to_trace_agentcore_namespace_everywhere(self):
        for l in oracle.events_to_trace(self._events(2), self.E4_META):
            self.assertIn("AgentCore::OAuthUser::", l)
            self.assertIn("AgentCore::Gateway::", l)
            self.assertIn('AgentCore::Action::"TransferTarget___transfer"',
                          l)
            self.assertIn("123:gateway/gw", l)

    def test_events_to_trace_accepts_prendered_meta(self):
        meta = {"session_id": "s",
                "action_cedar": 'Acme::Action::"DoThing"',
                "resource_cedar": 'Acme::Widget::"w1"'}
        lines = oracle.events_to_trace(self._events(1), meta)
        self.assertIn('Acme::Action::"DoThing"::request(', lines[0])
        self.assertIn('Acme::Widget::"w1"', lines[0])

    def test_events_to_trace_rejects_bad_events_and_meta(self):
        self.assertRaises(ValueError, oracle.events_to_trace,
                          [{"seq": 1, "amount": "one"}], self.E4_META)
        self.assertRaises(ValueError, oracle.events_to_trace,
                          [1, 2, 3], self.E4_META)
        self.assertRaises(ValueError, oracle.events_to_trace,
                          self._events(1), {"action": "x"})  # no resource
        self.assertEqual(oracle.events_to_trace([], self.E4_META), [])


@unittest.skipIf(oracle.find_dogwood() is None,
                 "dogwood reference binary not present (Phase-0 build absent)")
class ReferenceReplayGateTests(unittest.TestCase):
    """End-to-end: replay the gate classes against the reference interpreter."""

    @classmethod
    def setUpClass(cls):
        cls.binary = oracle.find_dogwood()
        cls.reports = oracle.run_gate(cls.binary)
        cls.by_apw = {r["apw"]: r for r in cls.reports}

    def test_gate_classes_present(self):
        self.assertEqual(set(self.by_apw), {"APW-1", "APW-2", "APW-4"})

    def test_each_class_rotn_is_violated(self):
        for apw in ("APW-1", "APW-2", "APW-4"):
            r = self.by_apw[apw]
            self.assertEqual(
                r["rot"]["verdict"], "violated",
                "%s ROTN verdict: %s" % (apw, r["rot"]))

    def test_each_buggy_policy_admits_in_the_reference(self):
        for apw in ("APW-1", "APW-2", "APW-4"):
            r = self.by_apw[apw]
            self.assertTrue(
                r["dogwood_reference_buggy"]["admitted_any"],
                "%s buggy policy did not admit in the reference: %s"
                % (apw, r["dogwood_reference_buggy"]))

    def test_gate_agrees(self):
        self.assertTrue(
            oracle.gate_passed(self.reports),
            "gate failed: %s" % [(r["apw"], r["gate"]) for r in self.reports])

    def test_apw1_correct_policy_denies_in_the_reference(self):
        """The corrected APW-1 (request-sum) enforces the cap in the
        reference: the 4th request is denied."""
        ref = self.by_apw["APW-1"]["dogwood_reference_correct"]
        self.assertTrue(ref["denied_any"])
        self.assertIn(3, ref["denied_timepoints"])

    def test_apw2_correct_policy_consumes_the_approval(self):
        """The corrected APW-2 admits exactly one order then denies the
        replayed ones (approval consumed)."""
        ref = self.by_apw["APW-2"]["dogwood_reference_correct"]
        self.assertEqual(ref["n_admitted"], 1)
        self.assertEqual(ref["n_denied"], 3)

    def test_apw4_buggy_admits_all_recipients(self):
        """The buggy APW-4 (settled-only counter) admits the whole
        cross-recipient in-flight burst in the reference."""
        ref = self.by_apw["APW-4"]["dogwood_reference_buggy"]
        self.assertEqual(ref["n_admitted"], 4)
        self.assertEqual(ref["n_denied"], 0)

    def test_render_markdown_contains_gate_and_caveats(self):
        md = oracle.render_markdown(self.reports, binary=self.binary)
        self.assertIn("Gate: PASS", md)
        self.assertIn("APW-1", md)
        self.assertIn("APW-2", md)
        self.assertIn("APW-4", md)
        self.assertIn("default-deny", md)
        self.assertIn("partition guarantee", md)


class E4ReadingTests(unittest.TestCase):
    """The pure E4 decision logic in agentcore_repro/64_replay_reference.py
    (the canonical readings + the event-field-mismatch detector).
    No dogwood binary, no AWS."""

    @classmethod
    def setUpClass(cls):
        import importlib
        import os
        import sys
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        repro = os.path.join(here, "agentcore_repro")
        if repro not in sys.path:
            sys.path.insert(0, repro)
        cls.e4 = importlib.import_module("64_replay_reference")

    @classmethod
    def _decs(cls, allow, deny):
        out = []
        for k in sorted(allow):
            out.append({"seq": 2 * (k - 1), "decision": "ALLOW"})
        for k in sorted(deny):
            out.append({"seq": 2 * (k - 1), "decision": "DENY"})
        return out

    def test_all_allow_is_predicate_mismatch(self):
        decs = self._decs([1, 2, 3, 4, 5], [])
        err = ("mentions field `eventResource`, which is not declared "
               "on that event (declared fields: callerPrincipal, "
               "callerResource, input.amount, requestId, sessionId)")
        label, detail = self.e4.e4_read(decs, {}, False, err)
        self.assertIn("PREDICATE-MISMATCH", label)
        self.assertIn("eventResource", detail)

    def test_all_deny_is_scope_mismatch(self):
        decs = self._decs([], [1, 2, 3, 4, 5])
        label, _ = self.e4.e4_read(decs, {}, True, "OK")
        self.assertIn("SCOPE-MISMATCH", label)

    def test_deny_from_3_is_spec_conformant(self):
        decs = self._decs([1, 2], [3, 4, 5])
        label, detail = self.e4.e4_read(decs, {}, True, "OK")
        self.assertIn("SPEC-CONFORMANT", label)
        self.assertIn("reflexive", label.lower())
        self.assertIn("j <= i", detail)

    def test_deny_from_4_is_non_reflexive(self):
        decs = self._decs([1, 2, 3], [4, 5])
        label, detail = self.e4.e4_read(decs, {}, True, "OK")
        self.assertIn("LIVE/REFERENCE GAP", label)
        self.assertIn("NON-REFLEXIVE", detail.upper())

    def test_no_decisions_is_reported(self):
        label, _ = self.e4.e4_read([], {}, True, "OK")
        self.assertIn("NO REFERENCE DECISIONS", label)

    def test_adapt_recognizes_eventresource_mismatch(self):
        err = ("error: predicate `X::request` mentions field "
               "`eventResource`, which is not declared on that event "
               "(declared fields: callerPrincipal, callerResource, "
               "input.amount, requestId, sessionId)")
        text = ("when temporal { formerly within 24h (A::request{ "
                "eventResource: resource, input.amount: a }) }")
        adapted, unknown, declared = \
            self.e4._adapt_field_mismatch(text, err)
        self.assertEqual(unknown, "eventResource")
        self.assertIn("callerResource", declared)
        self.assertNotIn("eventResource", adapted)
        self.assertIn("callerResource: resource", adapted)

    def test_adapt_rejects_other_failures(self):
        self.assertEqual(
            self.e4._adapt_field_mismatch("permit(p, a, r);",
                                          "error: unknown type `Foo`"),
            (None, None, None))
        err = ("mentions field `eventPrincipal`, which is not declared "
               "on that event (declared fields: callerPrincipal, "
               "callerResource, input.amount, requestId, sessionId)")
        self.assertEqual(
            self.e4._adapt_field_mismatch("eventPrincipal: x", err),
            (None, None, None))
        # the known field, but the build does not declare the target
        err2 = ("mentions field `eventResource`, which is not declared "
                "on that event (declared fields: callerPrincipal, "
                "input.amount, requestId, sessionId)")
        self.assertEqual(
            self.e4._adapt_field_mismatch("eventResource: r", err2),
            (None, None, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
