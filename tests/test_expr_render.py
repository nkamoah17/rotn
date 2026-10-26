# -*- coding: utf-8 -*-
"""Unit tests for ``rot.expr_render.render_expr`` -- the IR-expression
pretty-printer behind the guard strings on ``Verdict.trace`` steps.

Expected strings are pinned against the renderer's documented rules:
  * operator vocabulary straight from the IR (``+ - * = != < <= > >= and or not``);
  * parentheses by operator precedence (a looser op nested under a tighter
    one is parenthesised; a tighter op nested under a looser one is not);
  * the right operand of ``-`` at equal precedence is parenthesised;
  * identity elements of an ``and``/``or`` chain (``true`` / ``false``) are
    dropped, so ``ir.And(a, b)`` reads ``a and b``, not ``true and a and b``;
  * ``if`` / ``all`` / ``any`` render with explicit parentheses.

Run: python tests/test_expr_render.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rot.ir as ir
from rot.expr_render import render_expr
from rot.spendcap import (AMOUNT, CAP, MAX_INFLIGHT,
                          spend_ok_guard_buggy, spend_ok_guard_correct)


class ConstRenderTest(unittest.TestCase):
    def test_true_and_false(self):
        self.assertEqual(render_expr(ir.C(True)), "true")
        self.assertEqual(render_expr(ir.C(False)), "false")

    def test_numeric(self):
        self.assertEqual(render_expr(ir.C(200)), "200")
        self.assertEqual(render_expr(ir.C(0)), "0")
        self.assertEqual(render_expr(ir.C(1.5)), "1.5")

    def test_string_uses_repr(self):
        self.assertEqual(render_expr(ir.C("x")), "'x'")


class VarRenderTest(unittest.TestCase):
    def test_variable_name(self):
        self.assertEqual(render_expr(ir.V("completed")), "completed")


class BinOpRenderTest(unittest.TestCase):
    def test_multiplication_binds_tighter_than_addition(self):
        e = ir.BinOp("+", ir.V("completed"),
                     ir.BinOp("*", ir.V("inflight"), ir.C(100)))
        self.assertEqual(render_expr(e), "completed + inflight * 100")

    def test_comparison_looser_than_arithmetic(self):
        e = ir.BinOp("<=",
                     ir.BinOp("+", ir.V("completed"),
                              ir.BinOp("*", ir.V("inflight"), ir.C(100))),
                     ir.C(200))
        self.assertEqual(render_expr(e), "completed + inflight * 100 <= 200")

    def test_looser_child_under_tighter_op_is_parenthesised(self):
        e = ir.BinOp("*", ir.BinOp("+", ir.V("a"), ir.V("b")), ir.C(2))
        self.assertEqual(render_expr(e), "(a + b) * 2")

    def test_left_of_subtraction_equal_precedence_unparenthesised(self):
        # Only the RIGHT operand of `-` at equal precedence is parenthesised.
        e = ir.BinOp("-", ir.BinOp("+", ir.V("a"), ir.C(2)), ir.V("b"))
        self.assertEqual(render_expr(e), "a + 2 - b")

    def test_right_of_subtraction_equal_precedence_parenthesised(self):
        e = ir.BinOp("-", ir.C(1), ir.BinOp("+", ir.C(2), ir.C(3)))
        self.assertEqual(render_expr(e), "1 - (2 + 3)")

    def test_and_or_precedence(self):
        e = ir.BinOp("or", ir.BinOp("and", ir.V("a"), ir.V("b")), ir.V("c"))
        self.assertEqual(render_expr(e), "a and b or c")

    def test_comparison_inside_and_needs_no_parens(self):
        e = ir.BinOp("and",
                     ir.BinOp("<", ir.V("a"), ir.C(1)),
                     ir.BinOp(">", ir.V("b"), ir.C(2)))
        self.assertEqual(render_expr(e), "a < 1 and b > 2")


class UnOpRenderTest(unittest.TestCase):
    def test_not_variable(self):
        self.assertEqual(render_expr(ir.Not(ir.V("a"))), "not a")

    def test_not_of_binary_is_parenthesised(self):
        e = ir.Not(ir.BinOp("<", ir.V("a"), ir.C(1)))
        self.assertEqual(render_expr(e), "not (a < 1)")

    def test_not_of_and_chain_is_parenthesised(self):
        self.assertEqual(render_expr(ir.Not(ir.And(ir.V("a"), ir.V("b")))),
                         "not (a and b)")

    def test_nested_not_is_parenthesised(self):
        self.assertEqual(render_expr(ir.Not(ir.Not(ir.V("a")))),
                         "not (not a)")

    def test_negation_of_variable(self):
        self.assertEqual(render_expr(ir.UnOp("neg", ir.V("a"))), "-a")

    def test_negation_of_binary_is_parenthesised(self):
        e = ir.UnOp("neg", ir.BinOp("*", ir.V("a"), ir.C(2)))
        self.assertEqual(render_expr(e), "-(a * 2)")


class IfRenderTest(unittest.TestCase):
    def test_if_then_else(self):
        e = ir.If(ir.V("c"), ir.C(1), ir.C(0))
        self.assertEqual(render_expr(e), "if (c) then (1) else (0)")


class QuantifierRenderTest(unittest.TestCase):
    def test_all_of(self):
        e = ir.AllOf("p", ["a", "b"], ir.BinOp("=", ir.V("vote"), ir.C(1)))
        self.assertEqual(render_expr(e),
                         "all p in (['a', 'b']): vote = 1")

    def test_any_of(self):
        e = ir.AnyOf("p", ["a", "b"], ir.BinOp("=", ir.V("vote"), ir.C(1)))
        self.assertEqual(render_expr(e),
                         "any p in (['a', 'b']): vote = 1")


class AndOrIdentityTest(unittest.TestCase):
    def test_and_drops_leading_true(self):
        self.assertEqual(render_expr(ir.And(ir.V("a"), ir.V("b"))), "a and b")

    def test_and_with_explicit_true_drops_it(self):
        self.assertEqual(render_expr(ir.And(ir.T(), ir.V("a"), ir.V("b"))),
                         "a and b")

    def test_or_drops_leading_false(self):
        self.assertEqual(render_expr(ir.Or(ir.V("a"), ir.V("b"))), "a or b")

    def test_and_of_only_true_renders_true(self):
        self.assertEqual(render_expr(ir.And(ir.T())), "true")

    def test_or_of_nothing_renders_false(self):
        self.assertEqual(render_expr(ir.Or()), "false")


class SpendcapGuardRenderTest(unittest.TestCase):
    """The exact guard strings that appear on ``Verdict.trace`` steps."""

    def test_buggy_decision(self):
        self.assertEqual(render_expr(spend_ok_guard_buggy()),
                         "completed + 100 <= 200")

    def test_correct_decision(self):
        self.assertEqual(render_expr(spend_ok_guard_correct()),
                         "completed + inflight * 100 + 100 <= 200")

    def test_full_buggy_guard(self):
        e = ir.And(spend_ok_guard_buggy(),
                   ir.BinOp("<", ir.V("inflight"), ir.C(MAX_INFLIGHT)))
        self.assertEqual(render_expr(e),
                         "completed + 100 <= 200 and inflight < 4")

    def test_full_correct_guard(self):
        e = ir.And(spend_ok_guard_correct(),
                   ir.BinOp("<", ir.V("inflight"), ir.C(MAX_INFLIGHT)))
        self.assertEqual(render_expr(e),
                         "completed + inflight * 100 + 100 <= 200 "
                         "and inflight < 4")

    def test_property(self):
        e = ir.BinOp("<=",
                     ir.BinOp("+", ir.V("completed"),
                              ir.BinOp("*", ir.V("inflight"), ir.C(AMOUNT))),
                     ir.C(CAP))
        self.assertEqual(render_expr(e), "completed + inflight * 100 <= 200")


class EdgeCaseRenderTest(unittest.TestCase):
    def test_none_renders_empty_string(self):
        self.assertEqual(render_expr(None), "")

    def test_unknown_node_raises(self):
        self.assertRaises(TypeError, render_expr, object())


if __name__ == "__main__":
    unittest.main()

