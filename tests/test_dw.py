# -*- coding: utf-8 -*-
"""Tests for ``rot.dw`` -- the Dogwood ``.dw`` spend-cap policy parser.

Covers:
  * parsing the two shipped ``.dw`` files (``request`` correct / ``response`` buggy)
  * the ``request`` vs ``response`` discriminator (``is_buggy`` / ``matches_model``)
  * the ``to_ir`` bridge (``.dw`` -> ``rot.spendcap`` IR, with provenance)
  * structural error handling (missing ``@id`` / unknown event kind / cap mismatch)

Python 3.6 compatible.
"""

import unittest

import rot.spendcap as spendcap
import rot.ir as ir
from rot.dw import DwParseError, DwPolicy, parse_file, parse_policy
from rot.expr_render import render_expr
from rot.ir import ProtocolIR

POLICIES = "tests/fixtures/aws_dogwood/spendcap/policies"
CORRECT = POLICIES + "/spendcap-correct.dw"
BUGGY = POLICIES + "/spendcap-buggy.dw"

CORRECT_TEXT = (
    '@id("spendcap_correct")\n'
    'permit (\n'
    '    principal,\n'
    '    action == Drupe::Action::"Transfer",\n'
    '    resource\n'
    ')\n'
    'when temporal {\n'
    '    (sum a for (a: Long), (t: Timepoint). where (\n'
    '        formerly within 24h '
    '(Drupe::Action::"Transfer"::request{ input.amount: a } && tp(t))\n'
    '    )) <= 200\n'
    '};\n'
)
BUGGY_TEXT = CORRECT_TEXT.replace('::request{', '::response{').replace(
    "spendcap_correct", "spendcap_buggy")


class TestParseFiles(unittest.TestCase):
    def test_parse_correct_file(self):
        p = parse_file(CORRECT)
        self.assertIsInstance(p, DwPolicy)
        self.assertEqual(p.policy_id, "spendcap_correct")
        self.assertEqual(p.action, "Transfer")
        self.assertEqual(p.event_kind, "request")
        self.assertFalse(p.is_buggy)
        self.assertEqual(p.cap, spendcap.CAP)   # 200
        self.assertEqual(p.window, "24h")

    def test_parse_buggy_file(self):
        p = parse_file(BUGGY)
        self.assertEqual(p.policy_id, "spendcap_buggy")
        self.assertEqual(p.action, "Transfer")
        self.assertEqual(p.event_kind, "response")
        self.assertTrue(p.is_buggy)
        self.assertEqual(p.cap, spendcap.CAP)

    def test_the_only_difference_is_the_event_kind(self):
        c, b = parse_file(CORRECT), parse_file(BUGGY)
        self.assertNotEqual(c.event_kind, b.event_kind)
        self.assertEqual(c.action, b.action)
        self.assertEqual(c.cap, b.cap)
        self.assertEqual(c.window, b.window)


class TestSemantics(unittest.TestCase):
    def test_is_buggy_flag(self):
        self.assertFalse(parse_policy(CORRECT_TEXT).is_buggy)   # request
        self.assertTrue(parse_policy(BUGGY_TEXT).is_buggy)      # response

    def test_matches_model(self):
        self.assertTrue(parse_policy(CORRECT_TEXT).matches_model(False))
        self.assertFalse(parse_policy(CORRECT_TEXT).matches_model(True))
        self.assertTrue(parse_policy(BUGGY_TEXT).matches_model(True))
        self.assertFalse(parse_policy(BUGGY_TEXT).matches_model(False))


class TestToIr(unittest.TestCase):
    def test_to_ir_correct_accounts_for_inflight(self):
        p = parse_file(CORRECT)
        ir = p.to_ir()
        self.assertEqual(ir.name, "spendcap-correct")
        by = dict((a.name, a) for a in ir.actions)
        # the correct spend_ok guard includes the in-flight term (inflight * AMOUNT)
        self.assertIn("inflight *", render_expr(by["spend_ok"].guard))
        self.assertEqual(ir.metadata.get("dw_event_kind"), "request")
        self.assertEqual(ir.metadata.get("dw_cap"), spendcap.CAP)

    def test_to_ir_buggy_ignores_inflight(self):
        p = parse_file(BUGGY)
        ir = p.to_ir()
        self.assertEqual(ir.name, "spendcap-buggy")
        by = dict((a.name, a) for a in ir.actions)
        # the buggy spend_ok guard does NOT include the in-flight term
        self.assertNotIn("inflight *", render_expr(by["spend_ok"].guard))
        self.assertEqual(ir.metadata.get("dw_event_kind"), "response")

    def test_to_ir_matches_spendcap_build_ir(self):
        # the .dw bridge must reproduce the hand-written model exactly
        self.assertEqual(parse_file(CORRECT).to_ir(), spendcap.build_ir(n=1, buggy=False))
        self.assertEqual(parse_file(BUGGY).to_ir(), spendcap.build_ir(n=1, buggy=True))


class TestErrors(unittest.TestCase):
    def test_missing_id_raises(self):
        with self.assertRaises(DwParseError):
            parse_policy("permit ( principal, action, resource ) when temporal { x <= 1 };")

    def test_missing_event_kind_raises(self):
        with self.assertRaises(DwParseError):
            parse_policy(CORRECT_TEXT.replace('::request{', '::foo{'))

    def test_unknown_event_kind_rejected(self):
        with self.assertRaises(DwParseError):
            DwPolicy(policy_id="x", action="Transfer", event_kind="foo", cap=200)

    def test_cap_mismatch_raises_in_to_ir(self):
        p = parse_policy(CORRECT_TEXT.replace("<= 200", "<= 500"))
        self.assertEqual(p.cap, 500)
        with self.assertRaises(DwParseError):
            p.to_ir()

    def test_non_string_raises(self):
        with self.assertRaises(DwParseError):
            parse_policy(12345)


class TestMisc(unittest.TestCase):
    def test_comments_are_stripped(self):
        text = "// a leading comment line\n" + CORRECT_TEXT
        self.assertEqual(parse_policy(text).event_kind, "request")

    def test_summary(self):
        s = parse_policy(CORRECT_TEXT).summary()
        self.assertEqual(s["event_kind"], "request")
        self.assertFalse(s["buggy"])
        self.assertEqual(s["cap"], 200)

    def test_repr(self):
        r = repr(parse_policy(CORRECT_TEXT))
        self.assertIn("request", r)
        self.assertIn("buggy=False", r)


class TestComplexFixtures(unittest.TestCase):
    """The 6 corpus/example ``.dw`` fixtures that parse to a ``Policy`` or
    ``Document`` AST (not the simple ``DwPolicy`` spend-cap shape) must still
    lower to a valid ``ProtocolIR`` with the correct ``buggy`` flag.

    The ``buggy`` flag is inferred from the event kind the aggregate
    quantifies over: ``response`` (settled-only, the "buggy" side) vs
    ``request`` (in-flight, the "correct" side).
    """

    # (fixture path, expected event kind)
    FIXTURES = [
        ("tests/fixtures/aws_dogwood/spendcap/corpus/0299_sum_resolved_filter/policy_1.dw",
         "response"),
        ("tests/fixtures/aws_dogwood/spendcap/corpus/0301_sum_resolved_range_filter/policy_1.dw",
         "response"),
        ("tests/fixtures/aws_dogwood/spendcap/corpus/mcagg_0299_sum_resolved_filter/policy_1.dw",
         "response"),
        ("tests/fixtures/aws_dogwood/spendcap/examples/alert_total_transfer_over_200/policy.dw",
         "request"),
        ("tests/fixtures/aws_dogwood/spendcap/examples/cap_open_agent_prs_windowed/policy.dw",
         "response"),
        ("tests/fixtures/aws_dogwood/spendcap/examples/refund_budget_settled_plus_current/policy.dw",
         "response"),
    ]

    def test_all_lower_to_valid_ir(self):
        for path, _kind in self.FIXTURES:
            with self.subTest(fixture=path):
                node = parse_file(path)
                self.assertTrue(hasattr(node, "to_ir"),
                                "parsed node %r has no to_ir()" % type(node).__name__)
                ir = node.to_ir()
                self.assertIsInstance(ir, ProtocolIR)
                self.assertIsNotNone(ir.pinned_property)
                self.assertEqual(ir.validate(), [])

    def test_buggy_flag_matches_event_kind(self):
        for path, kind in self.FIXTURES:
            with self.subTest(fixture=path):
                ir = parse_file(path).to_ir()
                self.assertEqual(ir.metadata.get("dw_event_kind"), kind)

    def test_public_build_ir_entry_point(self):
        from rot.frontends.policy import build_ir
        for path, _kind in self.FIXTURES:
            with self.subTest(fixture=path):
                ir = build_ir(path)
                self.assertIsInstance(ir, ProtocolIR)
                self.assertIsNotNone(ir.pinned_property)
                self.assertEqual(ir.validate(), [])
                self.assertEqual(ir.metadata.get("property_name"),
                                 "spendcap_within_cap")

    def test_count_window_matches_oracle(self):
        """The count-window shape must reproduce the hand-written oracle."""
        import rot.shapes as shapes
        path = ("tests/fixtures/aws_dogwood/spendcap/examples/"
                "cap_open_agent_prs_windowed/policy.dw")
        self.assertEqual(parse_file(path).to_ir(),
                         shapes.build_count_window_ir(3))

    def test_exists_sum_matches_oracle(self):
        """The exists-sum shape must reproduce the hand-written oracle."""
        import rot.shapes as shapes
        fixtures = [
            ("tests/fixtures/aws_dogwood/spendcap/corpus/"
             "0299_sum_resolved_filter/policy_1.dw",
             1000, ">", "response", 4),
            ("tests/fixtures/aws_dogwood/spendcap/corpus/"
             "0301_sum_resolved_range_filter/policy_1.dw",
             1000, ">", "response", 4),
            ("tests/fixtures/aws_dogwood/spendcap/corpus/"
             "mcagg_0299_sum_resolved_filter/policy_1.dw",
             1000, ">", "response", 4),
            ("tests/fixtures/aws_dogwood/spendcap/examples/"
             "alert_total_transfer_over_200/policy.dw",
             200, ">", "request", 4),
        ]
        for path, cap, op, kind, k in fixtures:
            with self.subTest(fixture=path):
                self.assertEqual(parse_file(path).to_ir(),
                                 shapes.build_exists_sum_ir(cap, op, kind, k))

    def test_refund_budget_matches_oracle(self):
        """The refund-budget shape must reproduce the hand-written oracle."""
        import rot.shapes as shapes
        path = ("tests/fixtures/aws_dogwood/spendcap/examples/"
                "refund_budget_settled_plus_current/policy.dw")
        self.assertEqual(parse_file(path).to_ir(),
                         shapes.build_refund_budget_ir(100, "<="))

    def test_taint_egress_matches_oracle(self):
        """The taint-egress shape must reproduce the hand-written oracle.

        The two fixtures differ only in the trigger event's kind
        (``request`` vs. ``response``) -- the SAFE / UNSAFE distinction.
        """
        import rot.shapes as shapes
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "taint-egress-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "taint-egress-buggy.dw")
        # correct (request-trigger) must match the SAFE oracle
        self.assertEqual(
            parse_file(correct).to_ir(),
            shapes.build_taint_egress_ir(buggy=False,
                                         trigger_action="ReadConfidential",
                                         trigger_kind="request"))
        # buggy (response-trigger) must match the UNSAFE oracle
        self.assertEqual(
            parse_file(buggy).to_ir(),
            shapes.build_taint_egress_ir(buggy=True,
                                         trigger_action="ReadConfidential",
                                         trigger_kind="response"))

    def test_taint_egress_protocol_and_buggy_flag(self):
        """The taint-egress IR must be tagged and the buggy flag correct."""
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "taint-egress-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "taint-egress-buggy.dw")
        ir_c = parse_file(correct).to_ir()
        ir_b = parse_file(buggy).to_ir()
        self.assertEqual(ir_c.metadata.get("protocol"), "TAINT_EGRESS")
        self.assertEqual(ir_c.metadata.get("buggy"), False)
        self.assertEqual(ir_c.metadata.get("dw_event_kind"), "request")
        self.assertEqual(ir_b.metadata.get("protocol"), "TAINT_EGRESS")
        self.assertEqual(ir_b.metadata.get("buggy"), True)
        self.assertEqual(ir_b.metadata.get("dw_event_kind"), "response")
        # the only structural difference is the egress guard:
        #   correct -> NOT holding_private ; buggy -> True (unguarded)
        egress_c = dict((a.name, a) for a in ir_c.actions)
        egress_b = dict((a.name, a) for a in ir_b.actions)
        self.assertNotEqual(egress_c["contact_outsider"].guard.to_dict(),
                            egress_b["contact_outsider"].guard.to_dict())
        # and the deny branch is the negation in the correct variant
        self.assertEqual(egress_c["contact_outsider"].guard.to_dict(),
                         ir.Not(ir.V("holding_private")).to_dict())
        self.assertEqual(egress_b["contact_outsider"].guard.to_dict(),
                         ir.T().to_dict())

    # ------------------------------------------------------------------
    # APW-2: approval-replay (single-use approval)
    # ------------------------------------------------------------------

    def test_approval_replay_matches_oracle(self):
        """The approval-replay shape must reproduce the hand-written oracle.

        The two fixtures differ only in the *presence* of the ``since`` clause
        -- the SAFE (consumed) / UNSAFE (replayable) distinction:
          * correct -- a :class:`rot.dw.Since` node (single-use trigger);
          * buggy   -- a bare negated event reference (replayable trigger).
        """
        import rot.shapes as shapes
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "approval-replay-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "approval-replay-buggy.dw")
        self.assertEqual(
            parse_file(correct).to_ir(),
            shapes.build_approval_replay_ir(buggy=False))
        self.assertEqual(
            parse_file(buggy).to_ir(),
            shapes.build_approval_replay_ir(buggy=True))

    def test_approval_replay_protocol_and_buggy_flag(self):
        """The approval-replay IR must be tagged and the buggy flag correct."""
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "approval-replay-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "approval-replay-buggy.dw")
        ir_c = parse_file(correct).to_ir()
        ir_b = parse_file(buggy).to_ir()
        self.assertEqual(ir_c.metadata.get("protocol"), "APPROVAL_REPLAY")
        self.assertEqual(ir_c.metadata.get("buggy"), False)
        self.assertEqual(ir_b.metadata.get("protocol"), "APPROVAL_REPLAY")
        self.assertEqual(ir_b.metadata.get("buggy"), True)
        # the only structural difference is the place_order *effects*:
        #   correct -> consumes the approval (2 effects)
        #   buggy   -> does NOT consume it (1 effect) -> replayable
        po_c = dict((a.name, a) for a in ir_c.actions)["place_order"]
        po_b = dict((a.name, a) for a in ir_b.actions)["place_order"]
        self.assertEqual(len(po_c.effects), 2)
        self.assertEqual(len(po_b.effects), 1)
        self.assertNotEqual(po_c.effects, po_b.effects)

    # ------------------------------------------------------------------
    # APW-4: distinct-event count cap
    # ------------------------------------------------------------------

    def test_distinct_count_matches_oracle(self):
        """The distinct-count shape must reproduce the hand-written oracle.

        The two fixtures differ only in the counted event's kind
        (``request`` vs. ``response``) -- the SAFE / UNSAFE distinction.
        """
        import rot.shapes as shapes
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "distinct-count-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "distinct-count-buggy.dw")
        self.assertEqual(
            parse_file(correct).to_ir(),
            shapes.build_distinct_count_ir(buggy=False, cap=3))
        self.assertEqual(
            parse_file(buggy).to_ir(),
            shapes.build_distinct_count_ir(buggy=True, cap=3))

    def test_distinct_count_protocol_and_buggy_flag(self):
        """The distinct-count IR must be tagged and the buggy flag correct."""
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "distinct-count-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "distinct-count-buggy.dw")
        ir_c = parse_file(correct).to_ir()
        ir_b = parse_file(buggy).to_ir()
        self.assertEqual(ir_c.metadata.get("protocol"), "DISTINCT_COUNT")
        self.assertEqual(ir_c.metadata.get("buggy"), False)
        self.assertEqual(ir_c.metadata.get("dw_event_kind"), "request")
        self.assertEqual(ir_b.metadata.get("protocol"), "DISTINCT_COUNT")
        self.assertEqual(ir_b.metadata.get("buggy"), True)
        self.assertEqual(ir_b.metadata.get("dw_event_kind"), "response")
        # the only structural difference is the new_value *effects*:
        #   correct -> advances the dedup counter (2 effects)
        #   buggy   -> counter never advances (1 effect) -> cap not enforced
        nv_c = dict((a.name, a) for a in ir_c.actions)["new_value"]
        nv_b = dict((a.name, a) for a in ir_b.actions)["new_value"]
        self.assertEqual(len(nv_c.effects), 2)
        self.assertEqual(len(nv_b.effects), 1)
        self.assertNotEqual(nv_c.effects, nv_b.effects)

    # ------------------------------------------------------------------
    # APW-5: event ordering (A must precede B)
    # ------------------------------------------------------------------

    def test_event_ordering_matches_oracle(self):
        """The event-ordering shape must reproduce the hand-written oracle.

        The two fixtures differ only in the events' kind (``request`` vs.
        ``response``) -- the SAFE / UNSAFE distinction.
        """
        import rot.shapes as shapes
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "event-ordering-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "event-ordering-buggy.dw")
        self.assertEqual(
            parse_file(correct).to_ir(),
            shapes.build_event_ordering_ir(buggy=False))
        self.assertEqual(
            parse_file(buggy).to_ir(),
            shapes.build_event_ordering_ir(buggy=True))

    def test_event_ordering_protocol_and_buggy_flag(self):
        """The event-ordering IR must be tagged and the buggy flag correct."""
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "event-ordering-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "event-ordering-buggy.dw")
        ir_c = parse_file(correct).to_ir()
        ir_b = parse_file(buggy).to_ir()
        self.assertEqual(ir_c.metadata.get("protocol"), "EVENT_ORDERING")
        self.assertEqual(ir_c.metadata.get("buggy"), False)
        self.assertEqual(ir_c.metadata.get("dw_event_kind"), "request")
        self.assertEqual(ir_b.metadata.get("protocol"), "EVENT_ORDERING")
        self.assertEqual(ir_b.metadata.get("buggy"), True)
        self.assertEqual(ir_b.metadata.get("dw_event_kind"), "response")
        # the only structural difference is the do_b guard:
        #   correct -> a_done (B only after A) ; buggy -> True (unguarded)
        b_c = dict((a.name, a) for a in ir_c.actions)["do_b"]
        b_b = dict((a.name, a) for a in ir_b.actions)["do_b"]
        self.assertNotEqual(b_c.guard.to_dict(), b_b.guard.to_dict())
        self.assertEqual(b_c.guard.to_dict(), ir.V("a_done").to_dict())
        self.assertEqual(b_b.guard.to_dict(), ir.T().to_dict())

    # ------------------------------------------------------------------
    # APW-6: net open-count window cap
    # ------------------------------------------------------------------

    def test_count_window_pair_matches_oracle(self):
        """The count-window pair must reproduce the hand-written oracle.

        The two fixtures differ only in the counted events' kind (``request``
        vs. ``response``); the net-open-count model is the same.
        """
        import rot.shapes as shapes
        correct = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                   "count-window-correct.dw")
        buggy = ("tests/fixtures/aws_dogwood/spendcap/policies/"
                 "count-window-buggy.dw")
        self.assertEqual(parse_file(correct).to_ir(),
                         shapes.build_count_window_ir(3))
        self.assertEqual(parse_file(buggy).to_ir(),
                         shapes.build_count_window_ir(3))
        # and the buggy flag is threaded through the event kind.
        self.assertEqual(parse_file(correct).to_ir().metadata.get("buggy"),
                         False)
        self.assertEqual(parse_file(buggy).to_ir().metadata.get("buggy"),
                         True)


if __name__ == "__main__":
    unittest.main()