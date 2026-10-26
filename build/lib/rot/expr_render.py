# -*- coding: utf-8 -*-
"""expr_render.py -- render :mod:`rot.ir` expression ASTs to readable strings.

The IR expression classes (:class:`~rot.ir.Const`, :class:`~rot.ir.Var`,
:class:`~rot.ir.BinOp`, ...) are semantic value objects with no ``__str__``.
This module provides :func:`render_expr`, a small recursive pretty-printer
that turns an ``Expr`` into a human-readable string using the IR's own
operator vocabulary (``+ - * = != < <= > >= and or not``), inserting
parentheses by operator precedence and dropping ``and``/``or`` identity
elements (a leading ``true and ...`` / ``... or false``) so guards read like
the policy text.

Used by :mod:`rot.smtz3` to render action *guards* on counterexample trace
steps (the ``guard`` field of each ``(state, action, guard, policy_clause,
delta)`` 5-tuple).

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir

__all__ = ["render_expr"]


# Operator precedence (higher binds tighter).  Mirrors ``rot.ir.BinOp.OPS``.
_PREC = {
    "or": 10,
    "and": 20,
    "=": 30, "!=": 30, "<": 30, "<=": 30, ">": 30, ">=": 30,
    "+": 40, "-": 40,
    "*": 50,
}
_UNARY_PREC = 60
_ATOM_PREC = 70


def _prec_of(e):
    if isinstance(e, ir.BinOp):
        return _PREC.get(e.op, 0)
    if isinstance(e, ir.UnOp):
        return _UNARY_PREC
    return _ATOM_PREC  # Const / Var bind tightest


def _child(c, parent_p, is_left, parent_op):
    # Compound expressions always parenthesise.
    if isinstance(c, (ir.If, ir.AllOf, ir.AnyOf)):
        return "(%s)" % render_expr(c)
    cp = _prec_of(c)
    if cp < parent_p:
        return "(%s)" % render_expr(c)
    # Right operand of subtraction at equal precedence needs parentheses.
    if (not is_left) and parent_op == "-" and isinstance(c, ir.BinOp) \
            and cp == parent_p:
        return "(%s)" % render_expr(c)
    return render_expr(c)


def _render_bin(e):
    p = _PREC.get(e.op, 0)
    return "%s %s %s" % (_child(e.left, p, True, e.op),
                         e.op,
                         _child(e.right, p, False, e.op))


def _flatten(e, op):
    """Flatten a nested chain of binary ``op`` nodes into a flat operand list."""
    out = []
    if isinstance(e, ir.BinOp) and e.op == op:
        out.extend(_flatten(e.left, op))
        out.extend(_flatten(e.right, op))
    else:
        out.append(e)
    return out


def _render_and_or(e, op):
    identity_val = True if op == "and" else False
    parts = []
    for part in _flatten(e, op):
        # Drop the chain's identity element (``true`` for and, ``false`` for
        # or) so guards do not read like ``true and X and Y``.
        if isinstance(part, ir.Const) and part.value is identity_val:
            continue
        parts.append(_child(part, _PREC[op], True, op))
    if not parts:
        return "true" if op == "and" else "false"
    return (" %s " % op).join(parts)


def render_expr(expr):
    """Render an IR ``Expr`` to a readable string.

    >>> render_expr(ir.BinOp("<=", ir.BinOp("+", ir.V("completed"),
    ...                        ir.BinOp("*", ir.V("inflight"), ir.C(100))),
    ...              ir.C(200)))
    'completed + inflight * 100 <= 200'
    """
    if expr is None:
        return ""
    if isinstance(expr, ir.Const):
        v = expr.value
        if v is True:
            return "true"
        if v is False:
            return "false"
        return repr(v)
    if isinstance(expr, ir.Var):
        return expr.name
    if isinstance(expr, ir.UnOp):
        if expr.op == "not":
            inner = render_expr(expr.child)
            if isinstance(expr.child, (ir.BinOp, ir.UnOp)):
                inner = "(%s)" % inner
            return "not %s" % inner
        inner = render_expr(expr.child)
        if isinstance(expr.child, ir.BinOp):
            inner = "(%s)" % inner
        return "-%s" % inner
    if isinstance(expr, ir.If):
        return "if (%s) then (%s) else (%s)" % (
            render_expr(expr.cond), render_expr(expr.then), render_expr(expr.els))
    if isinstance(expr, ir.AllOf):
        return "all %s in (%s): %s" % (
            expr.var, render_expr(expr.coll), render_expr(expr.body))
    if isinstance(expr, ir.AnyOf):
        return "any %s in (%s): %s" % (
            expr.var, render_expr(expr.coll), render_expr(expr.body))
    if isinstance(expr, ir.BinOp):
        if expr.op in ("and", "or"):
            return _render_and_or(expr, expr.op)
        return _render_bin(expr)
    raise TypeError("cannot render expr %r" % (type(expr).__name__,))
