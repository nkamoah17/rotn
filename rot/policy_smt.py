# -*- coding: utf-8 -*-
"""policy_smt.py -- a direct Z3 encoding of the spendcap policy obligation.

This is a *different model family* from the IR state-machine model used by
``rot.smt`` / ``rot.smtz3``.  Instead of encoding the transition system
(state variables + transitions), it encodes the policy obligation directly
over a bounded event sequence:

  * ``completed[i]`` and ``inflight[i]`` are **free bounded integers** (Z3
    ``IntSort`` with explicit bounds), not state variables of a transition
    system.  They are *constrained* by the event sequence, not *determined*
    by it -- a different model family.
  * The decision rule (the ``spend_ok`` guard) is applied directly as a
    constraint on the admission of each request.
  * The obligation ``completed + inflight * amount <= cap`` is asserted at
    every step of the sequence.

The counterexample (if any) is a bounded event sequence that violates the
obligation -- a *witness* in the direct model, not a state-machine trace.

This is the "model independence" axis of the crosscheck: the same engine
(Z3) checks a *different model* (direct policy vs IR state-machine), so a
soundness leak in one model family cannot hide a bug in the other.

Pure stdlib + Z3, Python 3.6 compatible.
"""

try:
    import z3
except ImportError:  # z3 is an optional dependency
    z3 = None

from .symbolic import EngineResult, PROVEN, VIOLATED, UNKNOWN

__all__ = ["policy_direct_check"]


def _guard(amount, cap, buggy, completed, inflight):
    """The decision rule (guard) as a Z3 expression.

    Args:
        amount: the per-request settlement amount.
        cap: the spend cap.
        buggy: which decision rule to use (buggy vs correct).
        completed: the settled amount (Z3 Int).
        inflight: the in-flight request count (Z3 Int).

    Returns:
        A Z3 BoolRef: the guard (True if the request is admitted).
    """
    if buggy:
        # buggy: completed + amount <= cap (settled-only accounting)
        return completed + amount <= cap
    else:
        # correct: completed + inflight * amount + amount <= cap
        # (in-flight accounting: the current request + in-flight set must
        # all fit within the cap)
        return completed + inflight * amount + amount <= cap


def _extract_witness(model, completed, inflight, steps, amount, cap):
    """Extract a witness from the Z3 model.

    Finds the first step where the obligation is violated and returns the
    violated state as a dict (the same format as the IR state-machine
    witness, so ``witness_match`` can compare them).

    Args:
        model: the Z3 model.
        completed: the list of completed Z3 variables.
        inflight: the list of inflight Z3 variables.
        steps: the number of steps.
        amount: the per-request settlement amount.
        cap: the spend cap.

    Returns:
        A dict with the witness (the violated state), or an empty dict.
    """
    for i in range(steps + 1):
        c = model.eval(completed[i])
        f = model.eval(inflight[i])
        c_val = c.as_long() if c.is_int() else 0
        f_val = f.as_long() if f.is_int() else 0
        if c_val + f_val * amount > cap:
            return {
                "completed": c_val,
                "inflight": f_val,
            }
    return {}


def policy_direct_check(amount, cap, max_inflight, buggy, steps=None):
    """Direct Z3 encoding of the spendcap policy obligation.

    A bounded event sequence of length ``steps``.  At each step, the client
    either fires a request (``spend_ok``) or a response settles (``respond``).
    The state is tracked as free bounded integers:

      * ``completed[i]``: settled amount (bounded by ``cap + amount``).
      * ``inflight[i]``: in-flight request count (bounded by ``max_inflight``).

    The decision rule (guard) determines whether a ``spend_ok`` is admitted:
      * buggy: ``completed + amount <= cap``
      * correct: ``completed + inflight * amount + amount <= cap``

    The obligation: ``completed + inflight * amount <= cap`` at every step.

    Args:
        amount: the per-request settlement amount (AMOUNT).
        cap: the spend cap (CAP).
        max_inflight: K, the bound on in-flight requests.
        buggy: which decision rule to use (buggy vs correct).
        steps: the length of the bounded event sequence
               (default: ``max_inflight + 1``).

    Returns:
        EngineResult: PROVEN (obligation holds), VIOLATED (counterexample),
        or UNKNOWN (Z3 unavailable / error).
    """
    if z3 is None:
        return EngineResult(
            status=UNKNOWN,
            note="policy_direct: Z3 not installed")

    if steps is None:
        steps = max_inflight + 1

    solver = z3.Solver()

    # Free bounded integers for each step.
    completed = [z3.Int("completed_%d" % i) for i in range(steps + 1)]
    inflight = [z3.Int("inflight_%d" % i) for i in range(steps + 1)]

    # Bounds.
    for i in range(steps + 1):
        solver.add(completed[i] >= 0)
        solver.add(completed[i] <= cap + amount)
        solver.add(inflight[i] >= 0)
        solver.add(inflight[i] <= max_inflight)

    # Init.
    solver.add(completed[0] == 0)
    solver.add(inflight[0] == 0)

    # Transitions.
    for i in range(steps):
        admit = z3.Bool("admit_%d" % i)
        settle = z3.Bool("settle_%d" % i)

        # State update.
        solver.add(inflight[i + 1] == inflight[i]
                   + z3.If(admit, 1, 0) - z3.If(settle, 1, 0))
        solver.add(completed[i + 1] == completed[i]
                   + z3.If(settle, amount, 0))

        # Guard (decision rule).
        solver.add(z3.Implies(
            admit,
            _guard(amount, cap, buggy, completed[i], inflight[i])))

        # Settle precondition.
        solver.add(z3.Implies(settle, inflight[i] >= 1))

    # Obligation (negation: find a counterexample).
    violated = z3.Or([
        completed[i] + inflight[i] * amount > cap
        for i in range(steps + 1)
    ])
    solver.add(violated)

    # Check satisfiability.
    try:
        result = solver.check()
    except Exception as e:
        return EngineResult(
            status=UNKNOWN,
            note="policy_direct: Z3 error: %s" % e)

    if result == z3.sat:
        # Counterexample found.
        model = solver.model()
        witness = _extract_witness(
            model, completed, inflight, steps, amount, cap)
        return EngineResult(
            status=VIOLATED,
            witness=witness,
            note="policy_direct: counterexample found (steps=%d)" % steps)
    elif result == z3.unsat:
        return EngineResult(
            status=PROVEN,
            note="policy_direct: obligation holds (steps=%d)" % steps)
    else:
        return EngineResult(
            status=UNKNOWN,
            note="policy_direct: Z3 returned unknown")

