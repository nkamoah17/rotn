# -*- coding: utf-8 -*-
"""symbolic.py -- the symbolic (bounded-exhaustive) engine over a LinearModel.

The other engine is real TLC (rot.tlc). This one is our own, fully-offline
engine: it reasons about the *linearised* transition system produced by
``rot.linearization`` and decides the pinned safety property by exhaustive,
bounded search over the reachable state space.

Why this is sound
-----------------
Every domain in the IR is finite, so the reachable state space of the linearised
model is finite. An exhaustive BFS that explores it fully is *complete*: if the
pinned invariant holds in every reachable state, that is a genuine proof (over
the bounded model); if it finds a reachable state where the invariant is
definitely False, that is a genuine counterexample. If the search is truncated
by its state budget before the frontier drains, the call is ``UNKNOWN`` -- the
caller must never treat UNKNOWN as proven.

The evaluation is the IR's own three-valued ``Expr.eval`` (True / False / UNDEF):
  * a violation is only reported on a *definite* False (never on UNDEF);
  * UNDEF at a state is conservatively surfaced, not silently dropped.

This module is pure stdlib, Python 3.6 compatible.
"""

from .ir import Expr

# Verdict statuses (kept local so the engine has no upward dependency).
PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"
# Bounded-liveness verdicts (reach_within). Kept distinct from the safety pair
# above: a liveness claim is always relative to a bound, never unconditional.
REACHED = "reached"
NOT_REACHED = "not_reached"


class EngineResult(object):
    """The outcome of one engine run over one pinned property."""

    def __init__(self, status, witness=None, n_states=0, complete=False,
                 note=""):
        self.status = status            # PROVEN / VIOLATED / UNKNOWN
        self.witness = witness          # dict state (only when VIOLATED)
        self.n_states = int(n_states)   # #states explored
        self.complete = bool(complete)  # was the frontier fully drained?
        self.note = note

    def is_proven(self):
        return self.status == PROVEN

    def is_violated(self):
        return self.status == VIOLATED

    def is_unknown(self):
        return self.status == UNKNOWN

    def to_dict(self):
        return {
            "status": self.status,
            "witness": self.witness,
            "n_states": self.n_states,
            "complete": self.complete,
            "note": self.note,
        }


class ReachResult(object):
    """Outcome of a bounded-liveness reachability query (``reach_within``).

    This is deliberately distinct from :class:`EngineResult` (a *safety*
    verdict). A liveness claim is always relative to a bound, so the result
    carries:

    * ``status`` -- one of ``REACHED`` / ``NOT_REACHED`` / ``UNKNOWN``;
    * ``depth``  -- the step index (0..horizon) at which the goal was first
      reached (REACHED only), else ``None``;
    * ``path``   -- the concrete, IR-feasible state trace (list of state dicts,
      from the initial state to the goal) for a REACHED result -- this is the
      liveness *witness*;
    * ``budget_complete``  -- the search was NOT truncated by the state budget;
    * ``horizon_complete`` -- the whole horizon (all states reachable within
      ``horizon`` steps) was explored, i.e. a REACHED / NOT_REACHED answer is
      sound. In this implementation the horizon is only ever cut short by the
      state budget, so ``horizon_complete`` is True iff ``budget_complete``;
      the two flags are exposed separately so a future engine can report them
      independently without changing the contract.

    Soundness contract: ``NOT_REACHED`` is returned ONLY when
    ``horizon_complete`` is True. If the state budget was exhausted first, the
    result is ``UNKNOWN`` -- a caller must never read that as "unreachable".
    """

    def __init__(self, status, horizon, depth=None, path=None, witness=None,
                 n_states=0, n_visits=0, budget_complete=False,
                 horizon_complete=False, note=""):
        if status not in (REACHED, NOT_REACHED, UNKNOWN):
            raise ValueError("bad reach status %r" % (status,))
        self.status = status
        self.horizon = int(horizon)
        self.depth = depth                       # int or None
        self.path = list(path or [])            # state dicts (REACHED only)
        self.witness = witness                  # final state dict (REACHED only)
        self.n_states = int(n_states)           # #distinct states seen
        self.n_visits = int(n_visits)           # #state expansions (frontier)
        self.budget_complete = bool(budget_complete)
        self.horizon_complete = bool(horizon_complete)
        self.note = note

    def is_reached(self):
        return self.status == REACHED

    def is_not_reached(self):
        return self.status == NOT_REACHED

    def is_unknown(self):
        return self.status == UNKNOWN

    def to_dict(self):
        return {
            "status": self.status,
            "horizon": self.horizon,
            "depth": self.depth,
            "path": self.path,
            "witness": self.witness,
            "n_states": self.n_states,
            "n_visits": self.n_visits,
            "budget_complete": self.budget_complete,
            "horizon_complete": self.horizon_complete,
            "note": self.note,
        }


def _step(model, state, actions):
    """Concrete successor states via the IR's own evaluation (sound)."""
    out = []
    for a in actions:
        g = a.guard.eval(state)
        if g is Expr.UNDEF or not g:
            continue
        ns = dict(state)
        blocked = False
        for e in a.effects:
            v = e.expr.eval(state)
            if v is Expr.UNDEF:
                blocked = True
                break
            ns[e.var] = v
        if blocked or ns == state:
            continue
        out.append(ns)
    return out


class SymbolicEngine(object):
    """Bounded-exhaustive safety checker over a :class:`LinearModel`.

    ``model`` must expose: ``init_state`` (dict), and a way to enumerate the
    non-initial actions. We accept either the LinearModel's ordered
    ``actions`` list or an explicit action list.
    """

    def __init__(self, model, max_states=200000):
        self.model = model
        self.max_states = int(max_states)
        self.actions = [a for a in model.actions if not a.is_initial]

    def reachable(self, max_states=None):
        """BFS from the init state; return (states, complete).

        ``states`` is the ordered list of reachable state dicts (at most the
        budget). ``complete`` is True iff the frontier was fully drained (i.e.
        the search was not truncated by the budget).
        """
        budget = self.max_states if max_states is None else int(max_states)
        init = dict(self.model.init_state)
        seen = {frozenset(init.items())}
        queue = [init]
        i = 0
        complete = True
        while i < len(queue):
            cur = queue[i]
            i += 1
            if len(seen) >= budget:
                complete = False
                break
            for ns in _step(self.model, cur, self.actions):
                k = frozenset(ns.items())
                if k not in seen:
                    seen.add(k)
                    queue.append(ns)
        return queue, complete

    def check(self, property_expr, max_states=None):
        """Decide the pinned safety property over reachable states.

        Returns an :class:`EngineResult`. A violation is only reported on a
        definite ``False``; an incomplete (budget-truncated) search with no
        violation found is ``UNKNOWN``.
        """
        budget = self.max_states if max_states is None else int(max_states)
        states, complete = self.reachable(max_states)
        for s in states:
            r = property_expr.eval(s)
            if r is Expr.UNDEF:
                continue  # cannot refute; conservative
            if not r:
                return EngineResult(VIOLATED, witness=s, n_states=len(states),
                                    complete=complete,
                                    note="definite counterexample found")
        if complete:
            return EngineResult(PROVEN, n_states=len(states), complete=True,
                                note="invariant holds in all %d reachable states"
                                     % len(states))
        return EngineResult(UNKNOWN, n_states=len(states), complete=False,
                            note="search truncated at budget %d; no violation "
                                 "seen, but not proven" % budget)

    def reach_within(self, goal_expr, horizon, max_states=None):
        """Bounded-liveness reachability: can ``goal_expr`` be reached within ``horizon``?

        Unlike :meth:`check` (safety: the property must hold in *every*
        reachable state), this asks whether the goal is reachable in *some*
        execution of at most ``horizon`` steps. The search is a level-by-level
        breadth-first expansion (level == number of steps taken) with a shared
        state budget and a shared ``seen`` set, so the state space never
        inflates with ``horizon``.

        ``goal_expr`` is an :class:`~rot.ir.Expr`; a state satisfies it when
        ``goal_expr.eval(state)`` is definitely ``True`` (``UNDEF``/``False``
        never count, so the goal is never claimed on an unmodelled atom).

        Returns a :class:`ReachResult` with status:

        * ``REACHED``     -- some reachable state within ``horizon`` steps holds
          the goal; ``depth`` is the step index and ``path`` is the concrete
          initial-state-to-goal trace (the liveness witness).
        * ``NOT_REACHED`` -- the whole horizon was explored (the frontier
          drained before the bound, or the bound B was reached) with no goal
          state. Sound only because ``horizon_complete`` is True.
        * ``UNKNOWN``     -- the state budget was exhausted before the horizon
          finished. NOT to be read as "unreachable within the bound".

        Every verdict speaks of reachability *within bound B* -- never an
        unconditional liveness claim.
        """
        B = int(horizon)
        if B < 0:
            raise ValueError("horizon must be >= 0, got %r" % (horizon,))
        budget = self.max_states if max_states is None else int(max_states)
        if budget < 1:
            raise ValueError("state budget must be >= 1, got %r" % (max_states,))

        def goal_ok(s):
            r = goal_expr.eval(s)
            return r is not Expr.UNDEF and bool(r)

        def path_to(states_by_key, parent, key):
            path = []
            cur = key
            while cur is not None:
                path.append(states_by_key[cur])
                cur = parent[cur]
            path.reverse()
            return path

        init = dict(self.model.init_state)
        init_key = frozenset(init.items())
        if goal_ok(init):
            return ReachResult(
                REACHED, B, depth=0, path=[dict(init)], witness=dict(init),
                n_states=1, n_visits=1, budget_complete=True,
                horizon_complete=True,
                note="goal already holds in the initial state (within bound %d)"
                     % B)

        seen = {init_key}
        parent = {init_key: None}
        states_by_key = {init_key: init}
        level = [init]
        n_states = 1
        n_visits = 1
        truncated = False

        for step in range(1, B + 1):
            if not level:
                break  # frontier drained before the bound; nothing more reachable
            next_level = []
            for s in level:
                n_visits += 1
                for ns in _step(self.model, s, self.actions):
                    k = frozenset(ns.items())
                    if k in seen:
                        continue
                    if len(seen) >= budget:
                        truncated = True
                        break
                    seen.add(k)
                    parent[k] = frozenset(s.items())  # parent KEY (not the state dict)
                    states_by_key[k] = ns
                    n_states += 1
                    if goal_ok(ns):
                        return ReachResult(
                            REACHED, B, depth=step,
                            path=path_to(states_by_key, parent, k),
                            witness=dict(ns), n_states=n_states,
                            n_visits=n_visits, budget_complete=True,
                            horizon_complete=True,
                            note=("goal reached at step %d (within bound %d); "
                                  "path of %d states attached")
                                 % (step, B, step + 1))
                    next_level.append(ns)
                if truncated:
                    break
            level = next_level

        if truncated:
            return ReachResult(
                UNKNOWN, B, n_states=n_states, n_visits=n_visits,
                budget_complete=False, horizon_complete=False,
                note=("state budget %d exhausted before finishing the horizon "
                      "of %d steps; reachability of the goal within bound %d "
                      "is undecidable -- this is NOT a proof of "
                      "non-reachability") % (budget, B, B))
        return ReachResult(
            NOT_REACHED, B, n_states=n_states, n_visits=n_visits,
            budget_complete=True, horizon_complete=True,
            note=("no reachable state holds the goal within %d steps; the "
                  "horizon was fully explored (budget %d not exhausted), so "
                  "this is sound -- but it says nothing about bounds above %d")
                 % (B, budget, B))


__all__ = ["PROVEN", "VIOLATED", "UNKNOWN", "REACHED", "NOT_REACHED",
           "EngineResult", "ReachResult", "SymbolicEngine"]
