# -*- coding: utf-8 -*-
"""Tests for rot.design_view (human-facing views of a ProtocolIR).

Runs under ``python -m unittest tests.test_design_view`` from the ROTN
directory (Python 3.6), using the same import bootstrap as
tests/test_refine.py.

Coverage:

  * ``expr_to_str`` -- atoms/literals, precedence and parenthesisation
    (``a - (b - c)`` vs ``a - b - c``), identity stripping for ``And``/``Or``
    helpers, ``If``/``AllOf``/``AnyOf``, ``None``/non-Expr inputs.
  * ``free_vars`` -- flat collection, de-dup, sorted output, and binder
    binding for quantified expressions.
  * ``domain_to_str`` -- IntRange / Bool / Enum / None / fallback.
  * ``to_markdown`` -- every section present, overview counts, action
    blocks, unconditional guards, unrestricted init, pinned property,
    assumptions, metadata, custom title, TypeError on non-IR input.
  * ``json_view`` / ``to_json`` -- JSON-safe even when ``assumptions`` hold
    raw ``Expr`` objects, deterministic output, ``ProtocolIR.from_dict``
    round-trip, TypeError on non-IR input.
  * diff views -- ``compute_diff`` on the correct/buggy 2PC pair (SEMANTIC),
    variable rename (COSMETIC), action rename (COSMETIC), added action
    (STRUCTURAL), identical pair (NONE); ``diff_markdown`` bullets and
    severity sections; ``diff_json``/``to_json_diff`` structure.
"""

import json
import os
import sys
import unittest

# --- import bootstrap (mirror tests/test_refine.py) --------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import rot.ir as ir  # noqa: E402
import rot.targets as targets  # noqa: E402
import rot.design_view as dv  # noqa: E402

N = 2  # small enough for the 2PC fixtures to stay tractable


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
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
                                             ir.BinOp("+", ir.V("balance"),
                                                      ir.C(1)))]),
        ],
    )


def _bank_after_varrename():
    """Same protocol with the variable renamed balance->bal (action names
    unchanged): a pure variable rename, must be COSMETIC."""
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
    """Same protocol with the actions renamed init->start, add->inc
    (variable name unchanged): a pure action rename, must be COSMETIC."""
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
                                             ir.BinOp("+", ir.V("balance"),
                                                      ir.C(1)))]),
        ],
    )


def _bank3():
    """bank_after plus an extra ``drain`` action: a structural addition."""
    base = _bank_after_varrename()
    drain = ir.Action(name="drain", owner="bank",
                      guard=ir.T(), effects=[ir.Assignment("bal", ir.C(0))])
    return ir.ProtocolIR(
        name="bank3",
        variables=list(base.variables),
        actions=list(base.actions) + [drain],
    )


def _twopc_pair():
    """(before=correct, after=buggy) 2PC targets: a semantic change."""
    return targets.build("correct", N), targets.build("buggy", N)


def _ir_with_expr_assumption():
    """A tiny IR whose ``assumptions`` hold raw ``Expr`` objects -- the case
    that makes raw ``ProtocolIR.to_dict()`` non-JSON-serialisable."""
    return ir.ProtocolIR(
        name="assumed",
        variables=[ir.StateVar(name="a", domain=ir.Bool(), owner="env"),
                   ir.StateVar(name="b", domain=ir.Bool(), owner="env")],
        assumptions=[ir.And(ir.V("a"), ir.V("b"))],
        metadata={"note": "raw Expr in assumptions"},
    )

# ---------------------------------------------------------------------------
# expr_to_str
# ---------------------------------------------------------------------------
class TestExprToStr(unittest.TestCase):

    def test_atoms(self):
        self.assertEqual(dv.expr_to_str(ir.C(42)), "42")
        self.assertEqual(dv.expr_to_str(ir.C(True)), "True")
        self.assertEqual(dv.expr_to_str(ir.C(False)), "False")
        self.assertEqual(dv.expr_to_str(ir.C(None)), "UNDEF")
        self.assertEqual(dv.expr_to_str(ir.V("phase")), "phase")

    def test_enum_and_non_identifier_strings(self):
        self.assertEqual(dv.expr_to_str(ir.C("IDLE")), "IDLE")
        self.assertEqual(dv.expr_to_str(ir.C("a b")), '"a b"')

    def test_eq_and_cmp(self):
        self.assertEqual(dv.expr_to_str(ir.eq(ir.V("phase"), ir.C("IDLE"))),
                         "phase = IDLE")
        self.assertEqual(dv.expr_to_str(ir.BinOp("<", ir.V("n"), ir.C(0))),
                         "n < 0")

    def test_and_or_identity_stripping(self):
        # The And()/Or() helpers seed the fold with their identity
        # (True/False); the view drops that seed so the expression reads
        # naturally.
        self.assertEqual(dv.expr_to_str(ir.And(ir.V("x"))), "x")
        self.assertEqual(dv.expr_to_str(ir.Or(ir.V("x"))), "x")
        self.assertEqual(dv.expr_to_str(ir.And(ir.V("x"), ir.V("y"))),
                         "x and y")
        self.assertEqual(dv.expr_to_str(ir.Or(ir.V("x"), ir.V("y"))),
                         "x or y")
        # ...but an identity operand passed explicitly is still shown.
        self.assertEqual(dv.expr_to_str(ir.And(ir.T(), ir.V("x"))),
                         "True and x")
        self.assertEqual(dv.expr_to_str(ir.Or(ir.F(), ir.V("x"))),
                         "False or x")

    def test_precedence_add_vs_mul(self):
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("+", ir.BinOp("*", ir.V("a"), ir.V("b")),
                                ir.V("c"))),
            "a * b + c")
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("+", ir.V("a"),
                                    ir.BinOp("*", ir.V("b"), ir.V("c")))),
            "a + b * c")

    def test_subtraction_right_associativity(self):
        # a - (b - c) must keep its parentheses: (a - b) - c would differ.
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("-", ir.V("a"),
                                    ir.BinOp("-", ir.V("b"), ir.V("c")))),
            "a - (b - c)")
        # A left-nested subtraction of the same precedence is flat.
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("-", ir.BinOp("-", ir.V("a"), ir.V("b")),
                                ir.V("c"))),
            "a - b - c")

    def test_logical_precedence(self):
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("and", ir.Or(ir.V("a"), ir.V("b")),
                                ir.V("c"))),
            "(a or b) and c")
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("and", ir.V("a"),
                                    ir.Or(ir.V("b"), ir.V("c")))),
            "a and (b or c)")
        self.assertEqual(
            dv.expr_to_str(ir.BinOp("<", ir.V("n"),
                                    ir.BinOp("+", ir.V("a"), ir.C(1)))),
            "n < a + 1")

    def test_unary(self):
        self.assertEqual(
            dv.expr_to_str(ir.UnOp("not", ir.BinOp("and", ir.V("a"),
                                                   ir.V("b")))),
            "not (a and b)")
        self.assertEqual(
            dv.expr_to_str(ir.UnOp("not", ir.UnOp("not", ir.V("a")))),
            "not not a")
        self.assertEqual(dv.expr_to_str(ir.UnOp("neg", ir.V("x"))), "-x")

    def test_if(self):
        self.assertEqual(
            dv.expr_to_str(ir.If(ir.C(True), ir.V("a"), ir.V("b"))),
            "if True then a else b")

    def test_quantifiers(self):
        # The quantified collection is a concrete IR value, rendered inline.
        e = ir.AllOf("p", [1, 2], ir.eq(ir.V("p"), ir.C(1)))
        self.assertEqual(dv.expr_to_str(e), "all(p in [1, 2]: p = 1)")
        e = ir.AnyOf("q", ["x", "y"], ir.V("q"))
        self.assertEqual(dv.expr_to_str(e), "some(q in ['x', 'y']: q)")

    def test_none_and_non_expr_inputs(self):
        self.assertEqual(dv.expr_to_str(None), "UNDEF")
        self.assertEqual(dv.expr_to_str("plain"), "plain")
        self.assertEqual(dv.expr_to_str(3.5), "3.5")

    def test_deterministic(self):
        before, _ = _twopc_pair()
        for action in before.actions:
            self.assertEqual(dv.expr_to_str(action.guard),
                             dv.expr_to_str(action.guard))


# ---------------------------------------------------------------------------
# free_vars
# ---------------------------------------------------------------------------
class TestFreeVars(unittest.TestCase):

    def test_flat(self):
        e = ir.And(ir.V("a"), ir.eq(ir.V("b"), ir.C(1)))
        self.assertEqual(dv.free_vars(e), ["a", "b"])

    def test_dedup_and_sorted(self):
        e = ir.BinOp("+", ir.V("z"), ir.BinOp("*", ir.V("a"), ir.V("z")))
        self.assertEqual(dv.free_vars(e), ["a", "z"])

    def test_quantifier_binds(self):
        e = ir.AllOf("p", ir.C(1), ir.And(ir.V("p"), ir.V("q")))
        self.assertEqual(dv.free_vars(e), ["q"])
        # The collection itself can reference free vars.
        e = ir.AllOf("p", ir.V("n"), ir.V("p"))
        self.assertEqual(dv.free_vars(e), ["n"])

    def test_none(self):
        self.assertEqual(dv.free_vars(None), [])


# ---------------------------------------------------------------------------
# domain_to_str
# ---------------------------------------------------------------------------
class TestDomainToStr(unittest.TestCase):

    def test_int_range(self):
        self.assertEqual(dv.domain_to_str(ir.IntRange(0, 10)), "[0 .. 10]")

    def test_bool(self):
        self.assertEqual(dv.domain_to_str(ir.Bool()), "Bool")

    def test_enum(self):
        self.assertEqual(dv.domain_to_str(ir.Enum(["YES", "NO"])),
                         "{YES, NO}")

    def test_none_is_any(self):
        self.assertEqual(dv.domain_to_str(None), "Any")


# ---------------------------------------------------------------------------
# to_markdown
# ---------------------------------------------------------------------------
class TestToMarkdown(unittest.TestCase):

    def test_sections_and_counts(self):
        md = dv.to_markdown(targets.build("correct", N))
        for section in ("# Protocol: twopc_correct",
                        "## Overview",
                        "## State variables",
                        "## Channels",
                        "## Actions",
                        "## Initial state",
                        "## Pinned property",
                        "## Assumptions",
                        "## Metadata"):
            self.assertIn(section, md)
        # The 2PC target has 9 actions and 6 state variables, no channels.
        self.assertIn("- **actions:** 9", md)
        self.assertIn("- **state variables:** 6", md)
        self.assertIn("- **channels:** 0", md)
        self.assertIn("_generated by `rot.design_view`_", md)

    def test_action_block(self):
        md = dv.to_markdown(targets.build("correct", N))
        self.assertIn("### `apply_1`", md)
        self.assertIn("**owner:**", md)
        self.assertIn("**guard:**", md)
        self.assertIn("**effects:**", md)

    def test_unrestricted_init_and_pinned_property(self):
        md = dv.to_markdown(targets.build("correct", N))
        self.assertIn("_(unrestricted -- every state is allowed)_", md)
        self.assertIn(
            "`applied_1 = none or applied_2 = none or applied_1 = applied_2`",
            md)

    def test_metadata_section(self):
        md = dv.to_markdown(targets.build("correct", N))
        self.assertIn("- **`n`:** 2", md)
        self.assertIn("- **`buggy`:** False", md)

    def test_no_assumptions_placeholder(self):
        md = dv.to_markdown(_bank_before())
        self.assertIn("## Assumptions", md)
        self.assertIn("_(none)_", md)

    def test_channel_table(self):
        ch = ir.Channel(name="net", sender="a", receiver="b", desc="wires")
        ir1 = ir.ProtocolIR(name="ch", channels=[ch])
        md = dv.to_markdown(ir1)
        self.assertIn("| `net` | `a` | `b` | wires |", md)

    def test_custom_title(self):
        md = dv.to_markdown(_bank_before(), title="My design")
        self.assertTrue(md.startswith("# My design"))

    def test_rejects_non_ir(self):
        with self.assertRaises(TypeError):
            dv.to_markdown("not an ir")


# ---------------------------------------------------------------------------
# json_view / to_json
# ---------------------------------------------------------------------------
class TestJsonView(unittest.TestCase):

    def test_json_safe_with_raw_expr_assumptions(self):
        ir1 = _ir_with_expr_assumption()
        # Raw to_dict() is NOT json-serialisable (Expr in assumptions)...
        with self.assertRaises(TypeError):
            json.dumps(ir1.to_dict())
        # ...but json_view normalises it, so to_json works.
        out = json.loads(dv.to_json(ir1))
        self.assertEqual(out["name"], "assumed")
        self.assertIsInstance(out["assumptions"], list)
        self.assertEqual(len(out["assumptions"]), 1)

    def test_shape_and_actions(self):
        ir1 = _bank_before()
        out = dv.json_view(ir1)
        self.assertEqual(out["name"], "bank_before")
        self.assertEqual(len(out["actions"]), 2)
        for a in out["actions"]:
            self.assertIn("name", a)
            self.assertIn("guard", a)
            self.assertIn("effects", a)

    def test_deterministic(self):
        ir1 = targets.build("correct", N)
        self.assertEqual(dv.to_json(ir1), dv.to_json(ir1))
        self.assertEqual(dv.to_json(ir1, indent=2),
                         dv.to_json(ir1, indent=2))

    def test_compact_indent_none(self):
        ir1 = _bank_before()
        compact = dv.to_json(ir1, indent=None)
        self.assertNotIn("\n", compact)
        json.loads(compact)

    def test_round_trip_through_from_dict(self):
        ir1 = targets.build("correct", N)
        restored = ir.ProtocolIR.from_dict(json.loads(dv.to_json(ir1)))
        self.assertEqual(restored.to_dict(), ir1.to_dict())

    def test_rejects_non_ir(self):
        with self.assertRaises(TypeError):
            dv.json_view([1, 2, 3])
        with self.assertRaises(TypeError):
            dv.to_json({"name": "x"})


# ---------------------------------------------------------------------------
# diff views
# ---------------------------------------------------------------------------
class TestDiffMarkdown(unittest.TestCase):

    def test_semantic_2pc(self):
        before, after = _twopc_pair()
        diff = dv.compute_diff(before, after)
        self.assertEqual(diff.severity, "semantic")
        self.assertGreaterEqual(diff.summary_counts()["semantic"], 1)
        self.assertEqual(diff.before_name, "twopc_correct")
        self.assertEqual(diff.after_name, "twopc_buggy")

        md = dv.diff_markdown(diff)
        self.assertIn("# Protocol change report", md)
        self.assertIn("- **before:** `twopc_correct`", md)
        self.assertIn("- **after:** `twopc_buggy`", md)
        self.assertIn("- **overall severity:** **SEMANTIC**", md)
        self.assertIn("## SEMANTIC", md)
        self.assertIn("_predicates changed -- verification results do not "
                      "carry over_", md)
        self.assertIn("**modified** action `apply_1`", md)
        self.assertIn("_generated by `rot.design_view` from `rot.specdiff`_",
                      md)

    def test_variable_rename_is_cosmetic(self):
        diff = dv.compute_diff(_bank_before(), _bank_after_varrename())
        self.assertEqual(diff.severity, "cosmetic")
        md = dv.diff_markdown(diff)
        self.assertIn("- **overall severity:** **COSMETIC**", md)
        self.assertIn("## COSMETIC", md)
        self.assertIn("**renamed** variable `balance` -> `bal`", md)

    def test_action_rename_is_cosmetic(self):
        diff = dv.compute_diff(_bank_before(), _bank_after_actionrename())
        self.assertEqual(diff.severity, "cosmetic")
        md = dv.diff_markdown(diff)
        self.assertIn("**renamed** action `init` -> `start`", md)
        self.assertIn("**renamed** action `add` -> `inc`", md)

    def test_added_action_is_structural(self):
        diff = dv.compute_diff(_bank_after_varrename(), _bank3())
        self.assertEqual(diff.severity, "structural")
        md = dv.diff_markdown(diff)
        self.assertIn("- **overall severity:** **STRUCTURAL**", md)
        self.assertIn("## STRUCTURAL", md)
        self.assertIn("**added** action `drain` (owner `bank`)", md)
        self.assertIn("bal := 0", md)

    def test_identical_pair_is_none(self):
        ir1 = _bank_before()
        diff = dv.compute_diff(ir1, ir1)
        self.assertEqual(diff.severity, "none")
        self.assertEqual(diff.summary_counts(),
                         {"none": 0, "cosmetic": 0, "structural": 0,
                          "semantic": 0})
        md = dv.diff_markdown(diff)
        self.assertIn("_(no differences -- the two designs are identical)_",
                      md)
        self.assertNotIn("## COSMETIC", md)

    def test_custom_names_override(self):
        diff = dv.compute_diff(_bank_before(), _bank_after_varrename())
        md = dv.diff_markdown(diff, before_name="v1", after_name="v2")
        self.assertIn("- **before:** `v1`", md)
        self.assertIn("- **after:** `v2`", md)


class TestDiffJson(unittest.TestCase):

    def test_structure_semantic(self):
        before, after = _twopc_pair()
        diff = dv.compute_diff(before, after)
        out = dv.diff_json(diff)
        self.assertEqual(out["severity"], "semantic")
        self.assertEqual(out["before"], "twopc_correct")
        self.assertEqual(out["after"], "twopc_buggy")
        self.assertIsInstance(out["elements"], list)
        self.assertGreaterEqual(len(out["elements"]), 1)
        self.assertEqual(out["counts"]["semantic"],
                         diff.summary_counts()["semantic"])
        for el in out["elements"]:
            self.assertIn("kind", el)
            self.assertIn("severity", el)
        # Every element dict is plain JSON.
        json.dumps(out)

    def test_action_elements_carry_versions(self):
        before, after = _twopc_pair()
        diff = dv.compute_diff(before, after)
        out = dv.diff_json(diff)
        # specdiff's ActionDiff.to_dict drops the full before/after Actions;
        # the design view restores them so the JSON carries the concrete
        # effect versions of each change.
        mod = [el for el in out["elements"]
               if el.get("action", {}).get("kind") == "modified"]
        self.assertEqual(len(mod), N)
        for el in mod:
            b = el["action"]["before"]
            a = el["action"]["after"]
            self.assertIsNotNone(b)
            self.assertIsNotNone(a)
            self.assertIn("effects", b)
            self.assertNotEqual(b, a)  # the effect versions differ

    def test_to_json_diff_string(self):
        before, after = _twopc_pair()
        diff = dv.compute_diff(before, after)
        s = dv.to_json_diff(diff)
        data = json.loads(s)
        self.assertEqual(data["severity"], "semantic")
        self.assertEqual(data["counts"]["semantic"],
                         diff.summary_counts()["semantic"])

    def test_identical_pair(self):
        ir1 = _bank_before()
        diff = dv.compute_diff(ir1, ir1)
        out = dv.diff_json(diff)
        self.assertEqual(out["severity"], "none")
        self.assertEqual(out["elements"], [])
        json.dumps(out)


if __name__ == "__main__":
    unittest.main()

