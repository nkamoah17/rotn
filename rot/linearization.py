# -*- coding: utf-8 -*-
"""linearization.py -- turn the concurrent IR into a deterministic LinearModel.

A concurrent protocol is a *set* of interleaved actions over shared state. Both
downstream engines (the SAT symbolic engine and the TLA+ emitter) want the same
thing: a *total, deterministic* ordering of those actions plus a concrete initial
state. This module produces exactly that -- the shared "linearization" -- so the
two engines cannot drift apart.

    ProtocolIR  --(linearize)-->  LinearModel

The LinearModel records: the state variables (domains); the ordered transition
actions; the control points (``pc`` values = action names, in order); a concrete
``init_state`` (init action's effects evaluated on empty state); and provenance
(functions / call edges / message edges from the CPG).

It exposes the two operations every engine needs: ``enabled_in(state)`` and
``next_states(state)``. Determinism: actions keep their declared order (stable),
and every iteration is over an explicitly ordered list.

Pure stdlib, Python 3.6 compatible.
"""

from .ir import (T, F, Expr, Bool, Enum, IntRange)
from .impact import _action_written_vars
UNDEF = Expr.UNDEF
class LinearModel(object):
    """A deterministic, ordered transition system derived from a ProtocolIR."""

    def __init__(self, name, variables, init_action, actions, pc_values,
                 init_state, provenance, assumes=None,
                 stuttering_assumption=None):
        self.name = name
        self.variables = list(variables)      # StateVar list (ordered)
        self.init_action = init_action        # Action (the is_initial action)
        self.actions = list(actions)          # ordered non-initial Action list
        self.pc_values = list(pc_values)      # ordered control points (str)
        self.init_state = dict(init_state)    # var -> value
        self.provenance = provenance or {}    # dict (functions/calls/messages)
        # Phase 6.2: state constraints (TLA+ ASSUME clauses) carried over from
        # the IR; the concrete engines prune states that do not definitely
        # satisfy them (sound pruning).  Empty by default.
        self.assumes = list(assumes or [])
        # Phase 6.1: the stated stuttering assumption (stated, never silent).
        from .ir import STUTTERING_ASSUMPTION
        self.stuttering_assumption = (
            STUTTERING_ASSUMPTION if stuttering_assumption is None
            else stuttering_assumption)
        # Constant-node reduction (GSSM §2.6, the general state space): a state
        # variable that no transition action ever writes is a *constant node* --
        # it can only ever hold its initial value, so it contributes a single
        # state rather than its full domain.  Marking them shrinks the state
        # space the naive linearized chain would otherwise carry.  This is a
        # pure *view* over the actions -- it changes nothing the engines do.
        self.constant_nodes = self._constant_node_names()

    # -- lookups -------------------------------------------------------------
    @property
    def var_names(self):
        return [v.name for v in self.variables]

    def var(self, name):
        for v in self.variables:
            if v.name == name:
                return v
        raise KeyError(name)

    def actions_by_name(self):
        return {a.name: a for a in self.actions}

    def init(self):
        """Return the Init effect dict (var -> value), for the Init predicate."""
        return {e.var: e.expr for e in self.init_action.effects}

    # -- constant-node reduction (GSSM §2.6, the general state space) --------
    def _constant_node_names(self):
        """Variable names never written by any transition action.

        These are the *constant nodes* (GSSM constant-awareness, §IV-3c): a
        variable only the ``init`` action writes can only ever hold its initial
        value, so it is a constant of the state space, not time-varying state.
        Reuses ``rot.impact._action_written_vars`` for the write-set.
        """
        written = set()
        for a in self.actions:
            written |= _action_written_vars(a)
        return [v.name for v in self.variables if v.name not in written]

    def varying_var_names(self):
        """Variable names written by at least one transition action."""
        written = set()
        for a in self.actions:
            written |= _action_written_vars(a)
        return [v.name for v in self.variables if v.name in written]

    def domain_size(self, name):
        """The finite cardinality of the named variable's domain (None if unknown)."""
        sv = self.var(name)
        d = sv.domain
        if isinstance(d, Bool):
            return 2
        if isinstance(d, Enum):
            return len(d.values)
        if isinstance(d, IntRange):
            return max(0, d.hi - d.lo + 1)
        return None

    def state_space(self):
        """The state-space dimension, with and without constant-node reduction.

        Returns a dict:

        * ``chain``   -- the naive linearized-chain state space: the product of
          the domain sizes of *all* state variables (the full Cartesian product;
          an upper bound on the reachable states).
        * ``reduced`` -- the constant-node-reduced state space: the product over
          only the *varying* variables (a constant node contributes a factor of
          1, since it can only ever hold its initial value).
        * ``constant_nodes`` -- the variable names that are constant (init-only).
        * ``n_variables`` / ``n_varying`` -- the counts.

        ``reduced <= chain`` always; ``reduced < chain`` iff there is a constant
        node with a domain of size > 1 (the 2PC fixture's Phase 2 gate).  This is
        a pure measurement over the model -- it does not change what is verified.
        """
        def _product(names):
            p = 1
            for n in names:
                s = self.domain_size(n)
                if s is None:
                    return None
                p *= s
            return p

        all_names = [v.name for v in self.variables]
        varying = self.varying_var_names()
        return {
            "chain": _product(all_names),
            "reduced": _product(varying),
            "constant_nodes": list(self.constant_nodes),
            "n_variables": len(all_names),
            "n_varying": len(varying),
        }

    # -- concrete stepping ---------------------------------------------------
    def _apply_effects(self, state, effects):
        ns = dict(state)
        for e in effects:
            v = e.expr.eval(state)
            if v is not UNDEF:
                ns[e.var] = v
        return ns

    def enabled_in(self, state):
        """Ordered list of actions whose guard holds at ``state`` (concrete)."""
        out = []
        for a in self.actions:
            try:
                if a.guard.eval(state) is True:
                    out.append(a)
            except Exception:
                pass
        return out

    def next_states(self, state):
        """Ordered list of concrete successor states from ``state``."""
        out = []
        for a in self.enabled_in(state):
            ns = self._apply_effects(state, a.effects)
            if ns != state:
                out.append(ns)
        return out

    def reachable(self, max_states=100000):
        """Breadth-first reachable-state closure from init (concrete engine)."""
        init = dict(self.init_state)
        seen = {frozenset(init.items())}
        queue = [init]
        order = [init]
        i = 0
        while i < len(queue) and len(seen) < max_states:
            for ns in self.next_states(queue[i]):
                k = frozenset(ns.items())
                if k not in seen:
                    seen.add(k)
                    order.append(ns)
                    queue.append(ns)
            i += 1
        return order

    def to_dict(self):
        return {
            "name": self.name,
            "variables": [v.name for v in self.variables],
            "pc_values": self.pc_values,
            "init": {k: (v.to_dict() if hasattr(v, "to_dict") else v)
                     for k, v in self.init_state.items()},
            "n_actions": len(self.actions),
            "action_names": [a.name for a in self.actions],
            "provenance": {k: self.provenance.get(k)
                           for k in ("language", "functions", "call_edges",
                                     "message_edges")},
        }


def linearize(ir):
    """Build a LinearModel from a ProtocolIR.

    * split the init action from the transition actions (preserving order),
    * compute a concrete init_state by evaluating init effects on empty state,
    * collect provenance from ir.metadata.
    """
    init_action = None
    transitions = []
    for a in ir.actions:
        if a.is_initial and init_action is None:
            init_action = a
        else:
            transitions.append(a)

    if init_action is None:
        from .ir import Action
        init_action = Action(name="Init", owner="global", guard=T(),
                             effects=[], is_initial=True)

    # Concrete initial state: evaluate init effects against an empty state.
    init_state = {}
    for e in init_action.effects:
        v = e.expr.eval({})
        if v is not UNDEF:
            init_state[e.var] = v

    # Provenance: pull the CPG-derived metadata, if present.
    meta = ir.metadata or {}
    provenance = {
        "language": meta.get("language", ""),
        "functions": meta.get("functions", []),
        "call_edges": meta.get("call_edges", []),
        "message_edges": meta.get("message_edges", []),
        "source_path": ir.source_path or "",
    }

    return LinearModel(
        name=ir.name,
        variables=ir.variables,
        init_action=init_action,
        actions=transitions,
        pc_values=[a.name for a in transitions],
        init_state=init_state,
        provenance=provenance,
        assumes=getattr(ir, "assumes", None),
        stuttering_assumption=getattr(ir, "stuttering_assumption", None),
    )


__all__ = ["LinearModel", "linearize"]