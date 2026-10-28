# -*- coding: utf-8 -*-
"""modelfind.py -- bounded enumeration over the IR's finite domains.

sat.py reasons over *propositional* atoms. But the IR carries typed domains
(integers, enums, booleans) and invariants such as ``votes[0]=1 & votes[1]=1``
need to be checked over the *values* those domains enumerate. This module is
that bounded enumerator: it walks the finite product of a chosen set of
variable domains and applies a predicate (built from ``rot.ir`` expressions)
to each concrete state.

Soundness contract (same as the IR's UNDEF handling and sat.eval3):
  * ``exists`` -> SAT only on a *definite* witness (predicate True); a predicate
    that evaluates to ``Expr.UNDEF`` is not a witness.
  * ``forall`` -> False only on a *definite* counterexample (predicate False);
    UNDEF is not a counterexample (kept conservatively, surfaced as a
    refinement/assumption elsewhere).
  * If the product space exceeds the budget, the call returns ``UNKNOWN`` --
    callers must never treat UNKNOWN as True.

Pure stdlib, Python 3.6 compatible.
"""

import itertools

from .ir import Expr, IntRange, Bool, Enum

SAT = "SAT"
UNSAT = "UNSAT"
UNKNOWN = "UNKNOWN"


class ProductTooLarge(Exception):
    """Raised when an enumeration exceeds its budget (count only)."""


class BoundedVar(object):
    """A named finite domain (name, list-of-values)."""

    __slots__ = ("name", "values")

    def __init__(self, name, values):
        vals = list(values)
        if not vals:
            raise ValueError("BoundedVar %s has no values" % name)
        self.name = name
        self.values = vals

    def __repr__(self):
        return "BoundedVar(%s:%s)" % (self.name, self.values)


def domain_values(domain):
    """Expand an IR domain object into a concrete list of values."""
    if isinstance(domain, (list, tuple)):
        return list(domain)
    if isinstance(domain, IntRange):
        return list(range(domain.lo, domain.hi + 1))
    if isinstance(domain, Bool):
        return [True, False]
    if isinstance(domain, Enum):
        return list(domain.values)
    return list(domain)


class ModelFinder(object):
    """Enumerates the finite product of a set of bounded variables."""

    def __init__(self, variables, max_states=200000, ir=None):
        self.variables = list(variables)
        self.max_states = int(max_states)
        self.names = [v.name for v in self.variables]
        self._size = 1
        for v in self.variables:
            self._size *= len(v.values)
        self.ir = ir

    @classmethod
    def from_ir(cls, ir, var_names=None, max_states=200000):
        if var_names is None:
            var_names = [v.name for v in ir.variables]
        out = []
        for name in var_names:
            sv = ir.var(name)
            if sv is None:
                raise KeyError("no such IR variable: %s" % name)
            out.append(BoundedVar(name, domain_values(sv.domain)))
        return cls(out, max_states=max_states, ir=ir)

    def size(self):
        return self._size

    def within_bound(self):
        return self._size <= self.max_states

    def _iter_states(self):
        if not self.variables:
            yield {}
            return
        names = self.names
        value_lists = [v.values for v in self.variables]
        for combo in itertools.product(*value_lists):
            yield dict(zip(names, combo))

    def exists(self, predicate, max_iter=None):
        """Return (SAT, state) | (UNSAT, None) | (UNKNOWN, None)."""
        budget = self.max_states if max_iter is None else int(max_iter)
        seen = 0
        for state in self._iter_states():
            seen += 1
            if seen > budget:
                return (UNKNOWN, None)
            r = predicate(state)
            if r is not Expr.UNDEF and r:
                return (SAT, state)
        return (UNSAT, None)

    def forall(self, predicate, max_iter=None):
        """Return (True, None) | (False, counter_state) | (UNKNOWN, None)."""
        budget = self.max_states if max_iter is None else int(max_iter)
        seen = 0
        for state in self._iter_states():
            seen += 1
            if seen > budget:
                return (UNKNOWN, None)
            r = predicate(state)
            if r is Expr.UNDEF:
                continue
            if not r:
                return (False, state)
        return (True, None)

    def count(self, predicate, max_iter=None):
        """Count states where predicate is definitely True (raises if over budget)."""
        budget = self.max_states if max_iter is None else int(max_iter)
        n = 0
        seen = 0
        for state in self._iter_states():
            seen += 1
            if seen > budget:
                raise ProductTooLarge("count exceeded budget %d" % budget)
            r = predicate(state)
            if r is not Expr.UNDEF and r:
                n += 1
        return n

    def _apply_effects(self, state, effects):
        """Return the post-state after applying ``effects`` (evaluated over the
        pre-``state``), or ``None`` if any effect is not concretely evaluable
        (``Expr.UNDEF``) -- a transition we cannot track is conservatively
        skipped rather than mis-modelled."""
        out = dict(state)
        for e in effects:
            r = e.expr.eval(out)
            if r is Expr.UNDEF:
                return None
            out[e.var] = r
        return out

    def reachable_states(self, max_states=None):
        """BFS from the initial state; return a list of reachable state dicts.

        This mirrors what TLC explores (states reachable from Init), unlike
        ``_iter_states`` which enumerates the full Cartesian product.
        """
        budget = self.max_states if max_states is None else int(max_states)
        init_actions = [a for a in self.ir.actions if getattr(a, "is_initial", False)]
        if not init_actions:
            return []
        start = self._apply_effects({}, init_actions[0].effects)
        if start is None:
            return []
        seen = {tuple(sorted(start.items()))}
        frontier = [start]
        out = [start]
        idx = 0
        while idx < len(frontier):
            cur = frontier[idx]
            idx += 1
            if len(frontier) > budget:
                raise ProductTooLarge("reachable_states exceeded budget %d" % budget)
            for a in self.ir.actions:
                if getattr(a, "is_initial", False):
                    continue
                g = a.guard.eval(cur)
                if g is Expr.UNDEF or not g:
                    continue
                ns = self._apply_effects(cur, a.effects)
                if ns is None:
                    continue
                key = tuple(sorted(ns.items()))
                if key not in seen:
                    seen.add(key)
                    frontier.append(ns)
                    out.append(ns)
        return out

    def exists_reachable(self, predicate, max_states=None):
        """Return (SAT, witness) | (UNSAT, None) over reachable states only."""
        budget = self.max_states if max_states is None else int(max_states)
        seen = 0
        for state in self.reachable_states():
            seen += 1
            if seen > budget:
                return (UNKNOWN, None)
            r = predicate(state)
            if r is not Expr.UNDEF and r:
                return (SAT, state)
        return (UNSAT, None)

    def forall_reachable(self, predicate, max_states=None):
        """Return (True, None) | (False, counter) over reachable states only."""
        budget = self.max_states if max_states is None else int(max_states)
        seen = 0
        for state in self.reachable_states():
            seen += 1
            if seen > budget:
                return (UNKNOWN, None)
            r = predicate(state)
            if r is not Expr.UNDEF:
                if not r:
                    return (False, state)
            # UNDEF: cannot refute; skip (conservative)
        return (True, None)

    def path_to(self, target, max_states=None):
        """Return the BFS path from the initial state to ``target``.

        Returns a list of ``(state_before, action, delta)`` steps -- the exact
        step sequence the BFS first discovers on the way to ``target`` (the
        same traversal order as :meth:`reachable_states`, so the path is
        deterministic and consistent with :meth:`forall_reachable`):

        - ``state_before``: the state dict the step is applied to;
        - ``action``: the :class:`rot.ir.Action` whose guard is enabled in
          ``state_before``;
        - ``delta``: mapping ``{var: new_value}`` of the state variables the
          action's effects assign in the resulting state.

        Returns ``[]`` when ``target`` is the initial state or unreachable.
        Raises :class:`ProductTooLarge` if the budget is exhausted before
        ``target`` is found.
        """
        budget = self.max_states if max_states is None else int(max_states)
        init_actions = [a for a in self.ir.actions
                        if getattr(a, "is_initial", False)]
        if not init_actions:
            return []
        start = self._apply_effects({}, init_actions[0].effects)
        if start is None:
            return []
        start_key = tuple(sorted(start.items()))
        target_key = tuple(sorted(target.items()))
        if target_key == start_key:
            return []
        # key -> (prev_key, action, post_state)
        parent = {start_key: (None, None, None)}
        order = [start_key]
        idx = 0
        found = False
        while idx < len(order):
            if len(order) > budget:
                raise ProductTooLarge(
                    "path_to exceeded budget of %d states" % budget)
            cur_key = order[idx]
            idx += 1
            if cur_key == target_key:
                found = True
                break
            cur = dict(cur_key)
            for a in self.ir.actions:
                if getattr(a, "is_initial", False):
                    continue
                g = a.guard.eval(cur)
                if g is Expr.UNDEF or not g:
                    continue
                ns = self._apply_effects(cur, a.effects)
                if ns is None:
                    continue
                key = tuple(sorted(ns.items()))
                if key not in parent:
                    parent[key] = (cur_key, a, ns)
                    order.append(key)
        if not found:
            return []
        steps = []
        node = target_key
        while True:
            prev_key, action, post = parent[node]
            if action is None:
                break
            delta = {}
            for e in action.effects:
                delta[e.var] = post[e.var]
            steps.append((dict(prev_key), action, delta))
            node = prev_key
        steps.reverse()
        return steps


def find_deadlock_state(ir, terminal=None, max_states=100000):
    """A reusable "reachable stuck state" check (the deadlock discriminator).

    A **stuck state** (a *deadlock*) is a reachable state in which the system
    makes no further progress: **no non-initial action is enabled** (every
    guard is False or UNDEF) in that state, and the state is not a legitimate
    terminal/finished condition.

    This is the precise boundary between a *deadlock* (stuck: no action is
    enabled here, so the system cannot move, and the task is not done) and a
    *livelock* (not stuck: some action *is* enabled and taken, but the task
    never completes).  It is a pure, engine-agnostic helper: it builds a
    :class:`ModelFinder` over ``ir`` and returns a witness, so it can be
    driven by any caller (the MR gate, the CLI, or a test) without
    re-implementing the BFS.

    Parameters
    ----------
    ir : rot.ir.ProtocolIR
        The transition system to explore (the general agent-harness / approval
        model).
    terminal : rot.ir.Expr or None
        An optional predicate that marks *legitimate terminal* states (e.g.
        ``done OR escalated``).  A stuck state that satisfies ``terminal`` is a
        normal end-of-run, not a deadlock, and is skipped.  When ``None``,
        every stuck state counts as a deadlock witness.
    max_states : int
        The reachable-state budget (default 100000).

    Returns
    -------
    (bool, dict or None, list)
        A 3-tuple:

        * ``stuck`` -- True if a reachable *deadlock* (stuck, non-terminal)
          state exists;
        * ``witness`` -- the deadlock state dict, or ``None``;
        * ``reachable`` -- the list of reachable states (for the caller to
          reason about, e.g. to check whether any enabled action ever fires).

    The test is *conservative*: a state is a deadlock witness only if **no**
    non-initial action's guard is definitely True in it AND (if ``terminal``
    is given) ``terminal`` is not definitely True in it.  A state with at
    least one enabled action is *not* stuck (the system can still move), even
    if it never completes -- that is the livelock case, which this helper
    deliberately does **not** report.  It reports only the stuck/deadlock
    half; the caller combines this with the ``TaskEndsOrEscalates`` liveness
    verdict to distinguish deadlock (stuck) from livelock (progress without
    completion).
    """
    finder = ModelFinder.from_ir(ir, max_states=max_states)
    reachable = finder.reachable_states()
    if not reachable:
        return (False, None, [])
    non_initial = [a for a in ir.actions if not getattr(a, "is_initial", False)]
    for state in reachable:
        any_enabled = False
        for a in non_initial:
            g = a.guard.eval(state)
            if g is Expr.UNDEF:
                continue
            if g:
                any_enabled = True
                break
        if any_enabled:
            continue
        # A reachable state where no non-initial action is enabled: the system
        # is stuck here.  But a *terminal* state (task done / escalated) is a
        # legitimate end-of-run, not a deadlock -- skip it.
        if terminal is not None:
            t = terminal.eval(state)
            if t is Expr.UNDEF or t:
                continue
        # A non-terminal stuck state: a deadlock witness.  The caller can
        # inspect the witness to confirm the task is still pending.
        return (True, dict(state), reachable)
    return (False, None, reachable)