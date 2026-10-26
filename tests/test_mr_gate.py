# -*- coding: utf-8 -*-
"""Tests for rot.mr_gate (Step 3.6: MR-gate verdict).

Runs under ``python -m unittest tests.test_mr_gate`` from the ROTN directory
(Python 3.6), using the same import bootstrap as tests/test_specdiff.py.

The Phase 3 blocking-permission rule (``apply_verdict``) is:

    BLOCK  -- a blocking-eligible invariant (label in {inductive_at_bound,
              bounded_depth}) that is pinned=True is violated on the candidate.
    WARN   -- a non-blocking invariant (or a blocking-eligible invariant that
              is not pinned) is violated on the candidate.
    PASS   -- no checked invariant is violated on the candidate.

Two layers are tested: (1) the pure rule via synthetic InvariantResult
objects (deterministic, engine-independent), and (2) ``evaluate_mr`` on the
real 2PC ``correct`` / ``buggy`` targets (correct -> buggy breaks the pinned,
blocking ``agreement`` invariant => BLOCK with a deterministic failing test;
an unchanged pair PASSES).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

# --- import bootstrap (mirror tests/test_specdiff.py) ------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import rot.targets as targets
import rot.invariants as invariants
import rot.env as env
from rot.invariants import (
    LABEL_BOUNDED,
    Invariant,
    PERM_ALERT, PERM_WARN, PERM_BLOCK,
    RUNG_LOCAL, RUNG_PROTOCOL, RUNG_E2E, RUNG_ENV,
)
from rot.mr_gate import (
    PASS, WARN, BLOCK,
    InvariantResult,
    apply_verdict,
    evaluate_mr,
)


def _result(name, violated_after, blocking, pinned, label):
    """Build a synthetic :class:`InvariantResult` for the pure-rule tests."""
    return InvariantResult(
        name=name,
        violated_before=False,
        violated_after=violated_after,
        witness_path=["vote_1_yes", "decide", "apply_1"] if violated_after else [],
        witness_state={"applied_1": "commit", "applied_2": "abort"}
                      if violated_after else {},
        blocking=blocking,
        pinned=pinned,
        label=label,
        description="synthetic invariant %s" % name,
    )


class TestApplyVerdict(unittest.TestCase):

    def test_no_violation_passes(self):
        results = [_result("agreement", False, True, True, LABEL_BOUNDED),
                   _result("validity", False, True, True, LABEL_BOUNDED)]
        verdict, justification = apply_verdict(results)
        self.assertEqual(verdict, PASS)
        self.assertIn("verified", justification)

    def test_blocking_pinned_violation_blocks(self):
        results = [_result("agreement", True, True, True, LABEL_BOUNDED)]
        verdict, justification = apply_verdict(results)
        self.assertEqual(verdict, BLOCK)
        self.assertIn("agreement", justification)

    def test_nonblocking_violation_warns_not_blocks(self):
        results = [_result("no_spurious_abort", True, False, False, LABEL_BOUNDED)]
        verdict, _ = apply_verdict(results)
        self.assertEqual(verdict, WARN)

    def test_likely_label_never_blocks(self):
        results = [_result("perf_hint", True, False, True, "likely_on_traces")]
        verdict, _ = apply_verdict(results)
        self.assertEqual(verdict, WARN)

    def test_blocking_wins_over_warn(self):
        results = [
            _result("nonblocking", True, False, False, LABEL_BOUNDED),
            _result("agreement", True, True, True, LABEL_BOUNDED),
        ]
        verdict, _ = apply_verdict(results)
        self.assertEqual(verdict, BLOCK)

    def test_violation_only_before_does_not_block(self):
        r = _result("agreement", False, True, True, LABEL_BOUNDED)
        r.violated_before = True
        verdict, _ = apply_verdict([r])
        self.assertEqual(verdict, PASS)

class TestEvaluateMr(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rot_mr_gate_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_regression_blocks_with_deterministic_test(self):
        # correct -> buggy breaks the pinned, blocking 'agreement' invariant
        v = evaluate_mr("correct", "buggy", properties=["agreement"], n=2,
                        out_dir=self.tmp)
        self.assertEqual(v.verdict, BLOCK)
        self.assertEqual(v.before_label, "correct")
        self.assertEqual(v.after_label, "buggy")
        agr = [r for r in v.invariants if r.name == "agreement"]
        self.assertEqual(len(agr), 1)
        self.assertTrue(agr[0].violated_after)
        self.assertTrue(agr[0].blocking)
        # a deterministic failing test must be present
        self.assertIsNotNone(v.deterministic)
        self.assertEqual(v.deterministic.invariant_name, "agreement")
        self.assertTrue(v.deterministic.path)

    def test_no_change_passes(self):
        v = evaluate_mr("correct", "correct", properties=["agreement"], n=2)
        self.assertEqual(v.verdict, PASS)
        self.assertIsNone(v.deterministic)
        for r in v.invariants:
            self.assertFalse(r.violated_after)

    def test_scoped_to_nonblocking_invariant_never_blocks(self):
        # the same real change, scoped to a non-blocking invariant:
        # it must never produce a BLOCK verdict
        v = evaluate_mr("correct", "buggy", properties=["no_spurious_abort"],
                        n=2)
        self.assertIn(v.verdict, (PASS, WARN))
        self.assertNotEqual(v.verdict, BLOCK)

    def test_verdict_json_roundtrip(self):
        v = evaluate_mr("correct", "buggy", properties=["agreement"], n=2,
                        out_dir=self.tmp)
        path = os.path.join(self.tmp, "mr-verdict.json")
        self.assertTrue(os.path.exists(path))
        with open(path, "r") as f:
            data = json.load(f)
        self.assertEqual(data["verdict"], BLOCK)
        self.assertIn("justification", data)
        self.assertIn("invariants", data)
        self.assertIn("agreement", data["properties"])
        self.assertEqual(data["before"], "correct")
        self.assertEqual(data["after"], "buggy")
        self.assertIsNotNone(data.get("deterministic_failing_test"))

    def test_accepts_protocol_ir_objects(self):
        before = targets.build("correct", n=2)
        after = targets.build("buggy", n=2)
        v = evaluate_mr(before, after, properties=["agreement"], n=2)
        self.assertEqual(v.verdict, BLOCK)

    def test_rejects_unknown_target_name(self):
        with self.assertRaises(ValueError):
            evaluate_mr("no_such_target", "correct", properties=["agreement"])


# ---------------------------------------------------------------------------
# 5. Assurance ladder verdict rules
# ---------------------------------------------------------------------------

def _ladder_result(name, violated_after, permission):
    """Synthetic InvariantResult at a given gate permission."""
    return InvariantResult(
        name=name,
        violated_before=False,
        violated_after=violated_after,
        witness_path=["vote_1_yes", "decide"] if violated_after else [],
        witness_state={"applied_1": "commit"} if violated_after else {},
        blocking=(permission >= PERM_BLOCK),
        pinned=(permission >= PERM_BLOCK),
        label=LABEL_BOUNDED,
        description="ladder invariant %s" % name,
        permission=permission,
    )


class AssuranceLadderVerdictTests(unittest.TestCase):

    def test_alert_violation_passes_with_note(self):
        v, j = apply_verdict([_ladder_result("local_hint", True, PERM_ALERT)])
        self.assertEqual(v, PASS)
        self.assertIn("local_hint", j)
        self.assertIn("noted", j)

    def test_alert_violation_does_not_block_or_warn(self):
        v, _ = apply_verdict([_ladder_result("local_hint", True, PERM_ALERT),
                              _ladder_result("ok", False, PERM_BLOCK)])
        self.assertEqual(v, PASS)

    def test_warn_plus_alert_violations_warn_with_note(self):
        v, j = apply_verdict([
            _ladder_result("warny", True, PERM_WARN),
            _ladder_result("noted_one", True, PERM_ALERT),
        ])
        self.assertEqual(v, WARN)
        self.assertIn("warny", j)
        self.assertIn("noted_one", j)


    def test_block_beats_warn_and_alert(self):
        v, j = apply_verdict([
            _ladder_result("noted_one", True, PERM_ALERT),
            _ladder_result("warny", True, PERM_WARN),
            _ladder_result("agreement", True, PERM_BLOCK),
        ])
        self.assertEqual(v, BLOCK)
        self.assertIn("agreement", j)

    def test_permission_defaults_from_blocking(self):
        r = InvariantResult(name="x", violated_before=False,
                            violated_after=True, blocking=True, pinned=True,
                            label=LABEL_BOUNDED)
        self.assertEqual(r.permission, PERM_BLOCK)
        r = InvariantResult(name="x", violated_before=False,
                            violated_after=True, blocking=False, pinned=False,
                            label=LABEL_BOUNDED)
        self.assertEqual(r.permission, PERM_WARN)

    def test_to_dict_includes_permission(self):
        r = InvariantResult(name="x", violated_before=False,
                            violated_after=True, blocking=True, pinned=True,
                            label=LABEL_BOUNDED)
        d = r.to_dict()
        self.assertEqual(d["permission"], "block")
        self.assertTrue(d["blocking"])


    def test_local_rung_invariant_violation_warns_not_blocks(self):
        # Same label/pinned as 'agreement' (would BLOCK at RUNG_PROTOCOL),
        # but scoped to RUNG_LOCAL: the rung caps the gate at WARN.
        agr = invariants.get("agreement", n=2)
        local_inv = Invariant(
            name="agreement_local",
            description="agreement scoped to a local rung",
            expression=agr.expression,
            kind=agr.kind,
            label=agr.label,
            pinned=True,
            bound=agr.bound,
            rung=RUNG_LOCAL,
        )
        v = evaluate_mr("correct", "buggy", properties=[local_inv], n=2)
        self.assertEqual(v.verdict, WARN)
        r = [r for r in v.invariants if r.name == "agreement_local"][0]
        self.assertTrue(r.violated_after)
        self.assertFalse(r.blocking)
        self.assertEqual(r.permission, PERM_WARN)

    def test_e2e_rung_invariant_violation_blocks(self):
        agr = invariants.get("agreement", n=2)
        e2e_inv = Invariant(
            name="agreement_e2e",
            description="agreement at the end-to-end rung",
            expression=agr.expression,
            kind=agr.kind,
            label=agr.label,
            pinned=True,
            bound=agr.bound,
            rung=RUNG_E2E,
        )
        v = evaluate_mr("correct", "buggy", properties=[e2e_inv], n=2)
        self.assertEqual(v.verdict, BLOCK)
        r = [r for r in v.invariants if r.name == "agreement_e2e"][0]
        self.assertTrue(r.blocking)
        self.assertEqual(r.permission, PERM_BLOCK)


# ---------------------------------------------------------------------------
# 6. Environment-rung demotion: the witness action's rung caps the gate
# ---------------------------------------------------------------------------

def _env_no_loss_inv():
    """A blocking-eligible (pinned, ``bounded_depth``) no-loss invariant."""
    return Invariant(
        name="queue_no_loss",
        description="a queued message is delivered at least once (never lost)",
        expression=env.at_least_once_queue().pinned_property,
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
        bound=4,
        rung=RUNG_PROTOCOL,
    )


class EnvRungDemotionTests(unittest.TestCase):
    """A violation whose witness path ends at an *environment* action
    (rung ``RUNG_ENV``) can never drive a BLOCK: that action's rung caps the
    effective permission at ``RUNG_CEILING[RUNG_ENV]`` (WARN)."""

    def test_env_actions_are_annotated(self):
        # the env fragments mark every environment (env_free) action with the
        # RUNG_ENV rung, so the gate can cap a violation's permission
        for buggy in (False, True):
            for frag in (env.at_least_once_queue(buggy),
                         env.tcp_channel(buggy),
                         env.crash_recover_disk(buggy)):
                self.assertTrue(any(a.env_free for a in frag.actions))
                for a in frag.actions:
                    if a.env_free:
                        self.assertTrue(a.is_env, a.name)
                        self.assertEqual(a.rung, RUNG_ENV, a.name)

    def test_env_witness_violation_warns_not_blocks(self):
        # blocking-eligible (PERM_BLOCK) violation, but the witness ends at
        # the environment action 'queue_drop' -> demoted to WARN
        r = _ladder_result("queue_no_loss", True, PERM_BLOCK)
        r.witness_path = ["queue_init", "queue_enq", "queue_drop"]
        cand = env.at_least_once_queue(buggy=True)
        v, j = apply_verdict([r], cand)
        self.assertEqual(v, WARN)
        self.assertIn("queue_no_loss", j)
        self.assertIn("rung-demoted", j)

    def test_non_env_witness_still_blocks(self):
        # same blocking-eligible violation, but the witness ends at an
        # action that is not annotated as environment: no cap, BLOCK holds
        r = _ladder_result("queue_no_loss", True, PERM_BLOCK)
        r.witness_path = ["queue_init", "queue_enq", "app_apply"]
        cand = env.at_least_once_queue(buggy=True)
        v, j = apply_verdict([r], cand)
        self.assertEqual(v, BLOCK)
        self.assertNotIn("rung-demoted", j)

    def test_no_candidate_keeps_legacy_behaviour(self):
        # without a candidate IR the rung cap cannot apply: BLOCK is kept
        r = _ladder_result("queue_no_loss", True, PERM_BLOCK)
        r.witness_path = ["queue_init", "queue_enq", "queue_drop"]
        v, _ = apply_verdict([r])
        self.assertEqual(v, BLOCK)

    def test_evaluate_mr_env_candidate_warns_not_blocks(self):
        # end-to-end: a buggy environment fragment as the MR candidate.  The
        # pinned, blocking-eligible no-loss invariant is violated (the buggy
        # 'queue_drop' is reachable), but the witness ends at an env action,
        # so the gate demotes BLOCK -> WARN instead of false-blocking.
        inv = _env_no_loss_inv()
        before = env.at_least_once_queue()
        after = env.at_least_once_queue(buggy=True)
        v = evaluate_mr(before, after, properties=[inv], n=2)
        self.assertEqual(v.verdict, WARN)
        r = [x for x in v.invariants if x.name == "queue_no_loss"][0]
        self.assertTrue(r.violated_after)
        self.assertEqual(r.permission, PERM_BLOCK)  # declared permission
        self.assertTrue(r.witness_path)
        last = after.action(r.witness_path[-1])
        self.assertIsNotNone(last)
        self.assertEqual(last.rung, RUNG_ENV)


if __name__ == "__main__":
    unittest.main()
