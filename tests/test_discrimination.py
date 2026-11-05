# Copyright (c) KAMANU. All rights reserved.
"""Phase 2 -- discrimination cases: where a keyword/pattern scan ("grep")
is blind to what actually decides safety, and ROTN is not.

A per-request monitor or a policy keyword scan can only see *local* structure:
"this sum is over responses => in-flight invisible => UNSAFE", or "this action
is gated on an approval => SAFE".  The first heuristic is a flag without an
explanation; the second is *sometimes* right and *sometimes* wrong, because
the true verdict depends on context the scan cannot model -- the concurrency
bound (K), and whether the approval is single-use.

These two fixtures pin the discrimination, so the "elaborate grep" critique
has a concrete, reproducible answer:

  * **Case 1 -- response-sum + bounded in-flight  =>  UNSAFE at every K.**
    ``tests/fixtures/discrimination/response-sum-bounded.dw`` is a
    *response*-sum spend-cap policy.  The scan flags it as UNSAFE -- and is
    right: the current event is a request, never a response, so it is
    excluded from that sum by event kind.  ROTN agrees (UNSAFE at every K)
    and adds what the scan cannot: a concrete witness whose shape tracks the
    bound K (K = 1 -- the sequential off-by-one,
    ``{completed: 200, inflight: 1}``; K = 3 -- the parallel fire,
    ``{completed: 0, inflight: 3}``) and a sound proof that no other failure
    exists.

  * **Case 2 -- approval-gated but replayable  =>  UNSAFE.**
    The approval-replay shape (APW-2) is *gated on an approval* (a scan calls
    it safe).  When the approval is not consumed on use, one cart-check
    replays into an unbounded number of orders; ROTN refutes it (witness
    ``{approved: True, orders: 2}``).  When the approval is single-use the
    same policy is SAFE.  The verdict turns on *consumption*, not gating.

Both cases are checked against the same sound core (``ModelFinder`` over
the lowered IR / the hand-written oracle), so the discrimination is not a
per-fixture tuning.  See ``docs/discrimination.md``.
"""

import os
import unittest

import rot.frontends.policy as policy_fe
import rot.shapes as shapes
from rot.modelfind import ModelFinder

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DISC = os.path.join(_REPO_ROOT, "tests", "fixtures", "discrimination")
_RESPONSE_SUM = os.path.join(_DISC, "response-sum-bounded.dw")


def _verdict(ir):
    """Decide the pinned property over reachable states.

    Returns ``(safe, witness)`` where ``safe`` is ``True`` (PROVEN),
    ``False`` (VIOLATED), or ``None`` (UNKNOWN), and ``witness`` is the
    counterexample state for a violation (else ``None``).
    """
    mf = ModelFinder.from_ir(ir)
    result, witness = mf.forall_reachable(
        lambda s: ir.pinned_property.eval(s))
    return result, witness


class Case1ResponseSumBoundedTests(unittest.TestCase):
    """Case 1: a response-sum policy is UNSAFE at every K -- the SAME policy
    text -- and the witness shape tracks the bound K (which the scan cannot
    see)."""

    def test_fixture_parses_to_response_sum(self):
        ir = policy_fe.build_ir(_RESPONSE_SUM, max_inflight=3)
        self.assertEqual(ir.metadata.get("dw_event_kind"), "response",
                         "the fixture must be a response-sum policy")
        self.assertEqual(ir.metadata.get("property_kind"), "safety")

    def test_unsafe_at_k1_with_sequential_witness(self):
        """K = 1: the parallel-fire race is impossible, but the policy is
        UNSAFE -- the sequential off-by-one (a fire admitted with the settled
        amount at the cap settles past it) -> witness
        ``{completed: 200, inflight: 1}``.  The scan says UNSAFE too; here
        ROTN agrees and adds the witness + a sound proof."""
        ir = policy_fe.build_ir(_RESPONSE_SUM, max_inflight=1)
        safe, witness = _verdict(ir)
        self.assertIs(safe, False, "response-sum at K=1 must be UNSAFE")
        self.assertEqual(witness, {"completed": 200, "inflight": 1},
                         "K=1 witness must be the sequential off-by-one")

    def test_unsafe_at_k3_with_witness(self):
        """K = 3: a parallel burst overshoots the cap -> UNSAFE + witness."""
        ir = policy_fe.build_ir(_RESPONSE_SUM, max_inflight=3)
        safe, witness = _verdict(ir)
        self.assertIs(safe, False, "response-sum at K=3 must be UNSAFE")
        self.assertIsNotNone(witness)
        # The witness is the parallel-fire race: settled still 0, 3 in flight.
        self.assertEqual(witness.get("inflight"), 3)
        self.assertGreater(
            witness.get("inflight", 0) * 100, 200,
            "the in-flight amount must exceed the cap in the witness")

    def test_witness_shape_tracks_the_bound_not_the_keyword(self):
        """The discrimination: identical policy text and keyword at every K,
        UNSAFE at every K -- but the witness *shape* tracks the bound K
        (K=1 sequential off-by-one vs K>=2 parallel fire), which the scan
        cannot see."""
        safe_k1, w_k1 = _verdict(policy_fe.build_ir(_RESPONSE_SUM, max_inflight=1))
        safe_k3, w_k3 = _verdict(policy_fe.build_ir(_RESPONSE_SUM, max_inflight=3))
        self.assertIs(safe_k1, False, "response-sum at K=1 must be UNSAFE")
        self.assertIs(safe_k3, False, "response-sum at K=3 must be UNSAFE")
        self.assertNotEqual(w_k1, w_k3, "the bound K must change the witness")
        self.assertEqual(w_k1, {"completed": 200, "inflight": 1})
        self.assertEqual(w_k3, {"completed": 0, "inflight": 3})


class Case2ApprovalReplayTests(unittest.TestCase):
    """Case 2: an approval-gated policy is UNSAFE when the approval is
    replayable (not consumed), SAFE when it is single-use."""

    def test_replayable_approval_is_unsafe_with_witness(self):
        ir = shapes.build_approval_replay_ir(buggy=True)
        safe, witness = _verdict(ir)
        self.assertIs(safe, False, "replayable approval must be UNSAFE")
        self.assertIsNotNone(witness)
        # The witness is the replay: approval still present, >= 2 orders.
        self.assertTrue(witness.get("approved"),
                        "the approval must still be present in the witness")
        self.assertGreaterEqual(witness.get("orders", 0), 2,
                                "a second order must be reachable in the witness")

    def test_single_use_approval_is_safe(self):
        ir = shapes.build_approval_replay_ir(buggy=False)
        safe, witness = _verdict(ir)
        self.assertIs(safe, True, "single-use approval must be SAFE")
        self.assertIsNone(witness)

    def test_verdict_turns_on_consumption_not_gating(self):
        """Both variants are gated on an approval (a scan calls both safe);
        only the consumption of the approval separates them."""
        buggy = shapes.build_approval_replay_ir(buggy=True)
        correct = shapes.build_approval_replay_ir(buggy=False)
        # Both gate the order on the approval being present.
        order_buggy = dict((a.name, a) for a in buggy.actions)["place_order"]
        order_correct = dict((a.name, a) for a in correct.actions)["place_order"]
        from rot.expr_render import render_expr
        self.assertEqual(render_expr(order_buggy.guard),
                         render_expr(order_correct.guard),
                         "both variants gate on the same approval")
        safe_buggy, _ = _verdict(buggy)
        safe_correct, _ = _verdict(correct)
        self.assertIs(safe_buggy, False)
        self.assertIs(safe_correct, True)


class DiscriminationPageTests(unittest.TestCase):
    """The one-pager renders both directions and names both witnesses."""

    _PAGE = os.path.join(_REPO_ROOT, "docs", "discrimination.md")

    def test_page_exists(self):
        self.assertTrue(os.path.exists(self._PAGE),
                        "docs/discrimination.md must exist")

    def test_page_covers_both_directions(self):
        with open(self._PAGE, "r", encoding="utf-8") as f:
            text = f.read().lower()
        # Both directions of the grep error must be named.
        for needle in ("response", "in-flight", "k = 1", "approval",
                       "replay", "witness"):
            self.assertIn(needle, text,
                          "discrimination.md must mention %r" % needle)

    def test_fixture_present(self):
        self.assertTrue(os.path.exists(_RESPONSE_SUM),
                        "the response-sum discrimination fixture must exist")


if __name__ == "__main__":
    unittest.main()

