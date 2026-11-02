# -*- coding: utf-8 -*-
"""to_proceed.py -- the computed ``to_proceed`` list (G7: generalize the coach).

The thesis's claim::

    the ``to_proceed`` list is computed mathematically: the condition under
    which the blocked action would become enabled, read straight from the spec.

This module implements that claim **generically over the IR** -- there is no
hardcoded fix and no per-shape string.  Given a :class:`rot.ir.ProtocolIR`,
the name of a blocked (decision) action, and a state (typically the violation
witness), it:

  1. reads the action's **guard** from the IR (the spec -- not a hand-written
     rationale);
  2. decomposes the guard into its top-level **conjuncts** (a guard that is a
     possibly-nested conjunction is split; any other expression is its own
     singleton);
  3. evaluates each conjunct in the state and keeps the ones that are
     **false** -- the "false guard", the conditions that are currently
     blocking the action;
  4. emits those false conjuncts as the **enabling conditions** -- the
     condition(s) under which the blocked action would become enabled -- and
     their **negation** (the condition(s) currently true that are blocking it).

The same function therefore coaches the **spend-cap** shape (the ``spend_ok``
guard: settled + in-flight + this request must fit the cap) and the
**exfiltration** shape (the ``send_unapproved`` guard: the agent must not be
holding private data) -- and any other shape whose decision is an IR guard.
The output is a **pure function** of the IR + the state, so it is
deterministic, JSON-serialisable, and hashable, exactly like the rest of the
coaching artifact.

Soundness note: a conjunct that evaluates to ``Expr.UNDEF`` (a value that
depends on an unmodelled atom) is **never** read as blocking -- it is dropped
from the false-conjunct list, consistent with the IR's UNKNOWN handling.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import rot.ir as ir
from rot.design_view import expr_to_str

__all__ = [
    "conjuncts",
    "negate",
    "false_conjuncts",
    "compute_to_proceed",
]


def conjuncts(expr):
    """The top-level conjuncts of a guard expression.

    A guard that is a (possibly nested) conjunction is split into its
    conjuncts, in order; any other expression is its own singleton list.  This
    is the "read straight from the spec" step: the enabling condition of a
    blocked action is the conjunction of the guard's conjuncts, so the
    conditions that are currently blocking it are exactly the top-level
    conjuncts that evaluate to ``False``.
    """
    if isinstance(expr, ir.BinOp) and expr.op == "and":
        return conjuncts(expr.left) + conjuncts(expr.right)
    return [expr]


def negate(expr):
    """The negation of ``expr``, with double-negation eliminated.

    ``not (not x)`` is returned as ``x`` so the "blocking condition" reads
    cleanly -- e.g. the exfiltration guard ``not holding_private`` negates to
    ``holding_private`` rather than ``not not holding_private``.  Any other
    expression is wrapped in a single ``not``.
    """
    if isinstance(expr, ir.UnOp) and expr.op == "not":
        return expr.child
    return ir.Not(expr)


def false_conjuncts(expr, state):
    """The top-level conjuncts of ``expr`` that evaluate to ``False`` in
    ``state`` (the "false guard" -- the conditions currently blocking the
    action), in order.

    Conjuncts that already hold (``True``) are not part of the enabling
    condition and are omitted.  Conjuncts that evaluate to ``Expr.UNDEF`` are
    conservatively omitted too -- an unknown value is never read as blocking
    (the IR's UNKNOWN discipline).
    """
    out = []
    for c in conjuncts(expr):
        if c.eval(state) is False:
            out.append(c)
    return out


def compute_to_proceed(ir, action_name, state):
    """Compute the ``to_proceed`` record for a blocked action.

    This is the thesis's "computed mathematically" claim made concrete: the
    enabling condition of the blocked action is read from its IR guard (the
    spec) and the currently-false conjuncts are emitted as the conditions
    under which the action would become enabled -- together with their
    negation (the conditions currently true that block it).

    Parameters
    ----------
    ir : rot.ir.ProtocolIR
        The (corrected) policy IR whose guard defines the enabling condition.
    action_name : str
        The name of the blocked (decision) action in ``ir`` (e.g.
        ``"spend_ok"`` for the spend-cap shape, ``"agent_take_send_unapproved"``
        for the exfiltration shape).
    state : dict, optional
        The state (typically the violation witness) in which the action is
        blocked.  ``None`` is treated as the empty state.

    Returns
    -------
    dict
        A deterministic, JSON-serialisable record::

            {
              "action":      the blocked action name,
              "state":       the state it was evaluated in,
              "guard":       the action's guard, rendered (the spec),
              "blocked":     whether the guard is false in the state,
              "conditions":  the false conjuncts (the condition(s) under which
                             the action would become enabled), rendered,
              "blockers":    their negation (the condition(s) currently true
                             that block the action), rendered,
              "explanation": a plain-English framing (deterministic),
            }
    """
    state = state or {}
    action = ir.action(action_name)
    guard = action.guard
    blocked = (guard.eval(state) is False)
    false_cs = false_conjuncts(guard, state)
    conditions = [expr_to_str(c) for c in false_cs]
    blockers = [expr_to_str(negate(c)) for c in false_cs]
    if conditions:
        explanation = (
            "to proceed with '%s' from state %s, the guard's currently-false "
            "condition(s) must hold: %s"
            % (action_name, state, "; ".join(conditions))
        )
    else:
        explanation = (
            "the action '%s' is not blocked in state %s (its guard holds or "
            "is unknown); there is no condition to satisfy to proceed"
            % (action_name, state)
        )
    return {
        "action": action_name,
        "state": state,
        "guard": expr_to_str(guard),
        "blocked": blocked,
        "conditions": conditions,
        "blockers": blockers,
        "explanation": explanation,
    }
