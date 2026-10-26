# -*- coding: utf-8 -*-
"""Tests for rot.refine (Phase 4: propose -> check -> repair refinement loop).

Runs under ``python -m unittest tests.test_refine`` from the ROTN directory
(Python 3.6), using the same import bootstrap as tests/test_zk_bug_replay.py.

Coverage:

  * ``propose_mapping`` -- cosmetic renames captured in the mapping (a
    variable rename with unchanged action names; action renames with an
    unchanged variable name); semantic changes are NOT aliased (reported as
    uncovered). Note: specdiff's rename model is single-dimension per pass,
    so the fixtures rename variables *or* actions, not both at once.
  * ``_rename_expr`` -- helper rewrites nested expressions, identity on no-op.
  * ``check`` -- PASS (identity pair), FAIL (seeded 2PC bug, witness present),
    UNKNOWN (truncated search budget).
  * ``repair`` -- attributable regression restored (re-check PASS);
    unattributable failure -> empty plan + explanatory note.
  * ``run_refinement`` -- full loop: refined (2 rounds), unrepairable (1 round),
    exhausted (UNKNOWN), and the identity no-op (1 round, no steps).
  * CLI ``main`` -- exit 0 on refined, 2 on bad target/invariant, SystemExit.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

# --- import bootstrap (mirror tests/test_zk_bug_replay.py) -------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import rot.ir as ir  # noqa: E402
import rot.invariants as invmod  # noqa: E402
import rot.targets as targets  # noqa: E402
from rot.refine import (  # noqa: E402
    PASS, FAIL, UNKNOWN,
    REFINED, UNREPAIRABLE, EXHAUSTED,
    propose_mapping, _rename_expr,
    check, repair, run_refinement,
    main as cli_main,
)

N = 2  # small enough to prove invariants over all reachable states


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
class _Cfg(object):
    """Minimal engine config: only ``max_states`` is used by refine.check."""
    def __init__(self, max_states=100000):
        self.max_states = max_states


def _bank_before():
    """A one-variable 'bank' protocol: balance in [0,10], add raises by 1."""
    return ir.ProtocolIR(
        name="bank_before",
        variables=[ir.StateVar(name="balance", domain=ir.IntRange(0, 10),
                               owner="bank", desc="current balance")],
        actions=[
            ir.Action(name="init", owner="bank",
                      guard=ir.T(), effects=[ir.Assignment("balance", ir.C(0))],
                      is_initial=True),
            ir.Action(name="add", owner="bank",
                      guard=ir.BinOp("<", ir.V("balance"), ir.C(10)),
                      effects=[ir.Assignment("balance",
                                             ir.BinOp("+", ir.V("balance"), ir.C(1)))]),
        ],
    )


def _bank_after_varrename():
    """Same protocol with the variable renamed balance->bal (action names
    unchanged): a pure variable rename, must be captured as a var rename."""
    return ir.ProtocolIR(
        name="bank_after",
        variables=[ir.StateVar(name="bal", domain=ir.IntRange(0, 10),
                               owner="bank", desc="current balance")],
        actions=[
            ir.Action(name="init", owner="bank",
                      guard=ir.T(), effects=[ir.Assignment("bal", ir.C(0))],
                      is_initial=True),
            ir.Action(name="add", owner="bank",
                      guard=ir.BinOp("<", ir.V("bal"), ir.C(10)),
                      effects=[ir.Assignment("bal",
                                             ir.BinOp("+", ir.V("bal"), ir.C(1)))]),
        ],
    )


def _bank_after_actionrename():
    """Same protocol with the actions renamed init->start, add->inc (variable
    name unchanged): a pure action rename, must be captured as action renames."""
    return ir.ProtocolIR(
        name="bank_after",
        variables=[ir.StateVar(name="balance", domain=ir.IntRange(0, 10),
                               owner="bank", desc="current balance")],
        actions=[
            ir.Action(name="start", owner="bank",
                      guard=ir.T(), effects=[ir.Assignment("balance", ir.C(0))],
                      is_initial=True),
            ir.Action(name="inc", owner="bank",
                      guard=ir.BinOp("<", ir.V("balance"), ir.C(10)),
                      effects=[ir.Assignment("balance",
                                             ir.BinOp("+", ir.V("balance"), ir.C(1)))]),
        ],
    )


def _bank_after_semantic():
    """Same action names, but the guard changed: balance < 5 (semantic)."""
    return ir.ProtocolIR(
        name="bank_after",
        variables=[ir.StateVar(name="balance", domain=ir.IntRange(0, 10),
                               owner="bank", desc="current balance")],
        actions=[
            ir.Action(name="init", owner="bank",
                      guard=ir.T(), effects=[ir.Assignment("balance", ir.C(0))],
                      is_initial=True),
            ir.Action(name="add", owner="bank",
                      guard=ir.BinOp("<", ir.V("balance"), ir.C(5)),
                      effects=[ir.Assignment("balance",
                                             ir.BinOp("+", ir.V("balance"), ir.C(1)))]),
        ],
    )


def _two_pc_pair():
    """(before=correct, after=buggy) 2PC targets with the agreement invariant."""
    before = targets.build("correct", N)
    after = targets.build("buggy", N)
    inv = invmod.get("agreement", N)
    return before, after, inv


# ---------------------------------------------------------------------------
# propose_mapping
# ---------------------------------------------------------------------------
class TestPropose(unittest.TestCase):
    def test_var_rename_captured(self):
        p = propose_mapping(_bank_before(), _bank_after_varrename())
        self.assertEqual(p.var_map, {"balance": "bal"})
        self.assertEqual(p.action_map, {})

    def test_action_rename_captured(self):
        p = propose_mapping(_bank_before(), _bank_after_actionrename())
        self.assertEqual(p.action_map, {"init": "start", "add": "inc"})
        self.assertEqual(p.var_map, {})
        self.assertTrue(all("(renamed)" in r for r in p.reasons))

    def test_semantic_change_not_aliased(self):
        before = _bank_before()
        after = _bank_after_semantic()
        p = propose_mapping(before, after)
        self.assertNotIn("add", p.action_map)
        res = check(before, after, p, [], _Cfg())
        self.assertEqual(res.status, PASS)  # no invariants: vacuously passes
        self.assertIn("add", [u["name"] for u in res.uncovered_semantic])
        self.assertTrue(res.notes)

    def test_identity_no_mapping(self):
        p = propose_mapping(_bank_before(), _bank_before())
        self.assertEqual(p.var_map, {})
        self.assertEqual(p.action_map, {})

    def test_to_dict_keys(self):
        p = propose_mapping(_bank_before(), _bank_after_varrename())
        d = p.to_dict()
        self.assertEqual(set(d), {"var_map", "action_map", "reasons"})
        self.assertEqual(d["var_map"], {"balance": "bal"})


class TestRenameExpr(unittest.TestCase):
    def test_nested_rewrite(self):
        e = ir.BinOp("+", ir.V("balance"), ir.C(1))
        out = _rename_expr(e, {"balance": "bal"})
        self.assertEqual(out.to_dict()["left"]["name"], "bal")
        self.assertEqual(out.to_dict()["right"]["value"], 1)

    def test_identity_when_empty_map(self):
        e = ir.BinOp("+", ir.V("balance"), ir.C(1))
        self.assertIs(_rename_expr(e, {}), e)

    def test_none_passthrough(self):
        self.assertIsNone(_rename_expr(None, {"a": "b"}))


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------
class TestCheck(unittest.TestCase):
    def test_pass_identity(self):
        before, after, inv = _two_pc_pair()
        res = check(before, before, None, [inv], _Cfg())
        self.assertEqual(res.status, PASS)
        r = res.invariant_results[0]
        self.assertEqual(r["status"], PASS)
        self.assertIsNone(r["witness"])

    def test_fail_seeded_bug(self):
        before, after, inv = _two_pc_pair()
        res = check(before, after, None, [inv], _Cfg())
        self.assertEqual(res.status, FAIL)
        r = res.invariant_results[0]
        self.assertEqual(r["status"], FAIL)
        self.assertIsNotNone(r["witness"])

    def test_unknown_truncated_budget(self):
        before, after, inv = _two_pc_pair()
        res = check(before, before, None, [inv], _Cfg(max_states=2))
        self.assertEqual(res.status, UNKNOWN)

    def test_empty_invariant_list_vacuous_pass(self):
        before, after, inv = _two_pc_pair()
        res = check(before, after, None, [], _Cfg())
        self.assertEqual(res.status, PASS)
        self.assertEqual(res.invariant_results, [])


# ---------------------------------------------------------------------------
# repair
# ---------------------------------------------------------------------------
class TestRepair(unittest.TestCase):
    def test_attributable_repaired_and_passes(self):
        before, after, inv = _two_pc_pair()
        res = check(before, after, None, [inv], _Cfg())
        self.assertEqual(res.status, FAIL)
        repaired, plan = repair(before, after, res, [inv])
        self.assertTrue(plan.steps)
        for s in plan.steps:
            self.assertTrue(s.field == "guard"
                            or s.field.startswith("effect:"))
            self.assertIsNotNone(s.before_expr)
        res2 = check(before, repaired, None, [inv], _Cfg())
        self.assertEqual(res2.status, PASS)

    def test_unattributable_empty_plan(self):
        before = targets.build("buggy", N)
        after = targets.build("buggy", N)
        inv = invmod.get("agreement", N)
        res = check(before, after, None, [inv], _Cfg())
        self.assertEqual(res.status, FAIL)
        repaired, plan = repair(before, after, res, [inv])
        self.assertEqual(plan.steps, [])
        self.assertIn("no attributable repair", plan.reason)
        self.assertIs(repaired, after)

    def test_passed_check_yields_no_steps(self):
        before, after, inv = _two_pc_pair()
        res = check(before, before, None, [inv], _Cfg())
        self.assertEqual(res.status, PASS)
        repaired, plan = repair(before, before, res, [inv])
        self.assertEqual(plan.steps, [])
        self.assertIs(repaired, before)


# ---------------------------------------------------------------------------
# run_refinement (the full loop)
# ---------------------------------------------------------------------------
class TestRunRefinement(unittest.TestCase):
    def test_refined_two_rounds(self):
        before, after, inv = _two_pc_pair()
        rep = run_refinement(before, after, [inv], _Cfg(), max_rounds=3)
        self.assertEqual(rep.status, REFINED)
        self.assertEqual(len(rep.rounds), 2)
        self.assertEqual(rep.rounds[0].check.status, FAIL)
        self.assertTrue(rep.rounds[0].applied)
        self.assertEqual(rep.rounds[1].check.status, PASS)
        self.assertEqual(rep.rounds[1].applied, [])

    def test_unrepairable_one_round(self):
        before = targets.build("buggy", N)
        after = targets.build("buggy", N)
        inv = invmod.get("agreement", N)
        rep = run_refinement(before, after, [inv], _Cfg(), max_rounds=3)
        self.assertEqual(rep.status, UNREPAIRABLE)
        self.assertEqual(len(rep.rounds), 1)
        self.assertEqual(rep.rounds[0].plan.steps, [])

    def test_exhausted_on_unknown(self):
        before = targets.build("correct", N)
        after = targets.build("correct", N)
        inv = invmod.get("agreement", N)
        rep = run_refinement(before, after, [inv],
                             _Cfg(max_states=2), max_rounds=3)
        self.assertEqual(rep.status, EXHAUSTED)
        self.assertEqual(len(rep.rounds), 1)
        self.assertIn("undecidable", rep.rounds[0].plan.reason)

    def test_identity_one_round_no_steps(self):
        before = targets.build("correct", N)
        after = targets.build("correct", N)
        inv = invmod.get("agreement", N)
        rep = run_refinement(before, after, [inv], _Cfg(), max_rounds=3)
        self.assertEqual(rep.status, REFINED)
        self.assertEqual(len(rep.rounds), 1)
        self.assertEqual(rep.rounds[0].plan.steps, [])

    def test_report_serialisable(self):
        before, after, inv = _two_pc_pair()
        rep = run_refinement(before, after, [inv], _Cfg(), max_rounds=3)
        d = rep.to_dict()
        json.dumps(d)  # must round-trip through JSON
        self.assertEqual(d["status"], REFINED)
        self.assertEqual(len(d["rounds"]), 2)
        self.assertIn("final_ir", d)
        self.assertEqual(d["invariants"][0]["name"], "agreement")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCLI(unittest.TestCase):
    def test_refined_exit_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["correct", "buggy", "--n", str(N),
                           "--max-states", "100000"])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["status"], REFINED)

    def test_default_invariant_exit_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["correct", "buggy", "--n", str(N),
                           "--max-states", "100000",
                           "--invariant", "agreement"])
        self.assertEqual(rc, 0)

    def test_unknown_target_exit_two(self):
        with redirect_stdout(io.StringIO()):
            try:
                cli_main(["correct", "no_such_target"])
            except SystemExit as exc:
                self.assertEqual(exc.code, 2)
            else:
                self.fail("expected SystemExit(2)")

    def test_unknown_invariant_exit_two(self):
        try:
            cli_main(["correct", "buggy", "--invariant", "no_such_invariant"])
        except SystemExit as exc:
            self.assertEqual(exc.code, 2)
        else:
            self.fail("expected SystemExit(2)")

    def test_missing_positionals_exit_two(self):
        try:
            cli_main([])
        except SystemExit as exc:
            self.assertEqual(exc.code, 2)
        else:
            self.fail("expected SystemExit(2)")


if __name__ == "__main__":
    unittest.main()
