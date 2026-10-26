# -*- coding: utf-8 -*-
"""impact.py -- impact-set computation for incremental verification.

Given a set of changed action names (e.g. extracted from a code diff),
compute the "cone of influence": which actions and invariants are affected
by the change.

This is the *forward* mirror of the property-directed abstraction in
``rot.abstraction``: abstraction computes "which variables does this property
depend on?" (backward closure), while impact computes "which actions and
invariants does this change affect?" (forward / shared-state overlap).

The algorithm (shared-state overlap, the same free-variable closure concept
that ``rot.abstraction`` uses for properties):

  1. **Direct** -- the changed actions themselves.
  2. **Indirect** -- any *transition* action whose free variables (guard +
     effect expressions) overlap with the free variables of the changed
     actions.
  3. **Invariants** -- any invariant whose expression references any variable
     in the impact scope.

Output: :class:`ImpactSet` with ``changed_actions``, ``impacted_actions``,
``affected_invariants``, ``impacted_variables``, and a human-readable
``scope_reason``.

Pure stdlib, Python 3.6 compatible.
"""

from .ir import Var, BinOp, UnOp, If, AllOf, AnyOf


# ---------------------------------------------------------------------------
# free-variable helpers (same walking logic as rot.abstraction._free_vars)
# ---------------------------------------------------------------------------
def _free_vars(expr):
    """Collect free variable names from an IR expression tree.

    Same walking logic as ``rot.abstraction._free_vars`` (returns a set here
    for convenient set-overlap use in impact computation).
    """
    out = set()

    def walk(e):
        if e is None:
            return
        if isinstance(e, Var):
            out.add(e.name)
        elif isinstance(e, BinOp):
            walk(e.left)
            walk(e.right)
        elif isinstance(e, UnOp):
            walk(e.child)
        elif isinstance(e, If):
            walk(e.cond)
            walk(e.then)
            walk(e.els)
        elif isinstance(e, (AllOf, AnyOf)):
            walk(e.coll)
            walk(e.body)

    walk(expr)
    return out


def _action_free_vars(action):
    """All free variable names in an action's guard and effect expressions.

    Includes both the variables read (guard + effect source expressions) and
    the variables written (effect target names), excluding the control
    variable ``pc``.
    """
    vars_ = set()
    for v in _free_vars(action.guard):
        if v != "pc":
            vars_.add(v)
    for e in action.effects:
        for v in _free_vars(e.expr):
            if v != "pc":
                vars_.add(v)
        if e.var != "pc":
            vars_.add(e.var)
    return vars_


def _action_written_vars(action):
    """Variable names that an action writes (its effect targets)."""
    return set(e.var for e in action.effects if e.var != "pc")
# ---------------------------------------------------------------------------
# ImpactSet
# ---------------------------------------------------------------------------
class ImpactSet(object):
    """The cone of influence for a set of changed actions.

    Attributes
    ----------
    changed_actions : list of str
        The action names that changed (from a diff or code review).
    impacted_actions : list of str
        All *transition* actions whose free variables overlap with the
        changed actions' free variables (includes the changed actions
        themselves; the init action is never included).
    affected_invariants : list of str
        Names of invariants whose expression references any variable in
        the impact scope.
    impacted_variables : list of str
        All state variables that are read or written by any impacted action.
    scope_reason : str
        A human-readable explanation of the impact scope.
    """

    def __init__(self, changed_actions, impacted_actions,
                 affected_invariants, scope_reason,
                 impacted_variables=None):
        self.changed_actions = sorted(set(changed_actions))
        self.impacted_actions = sorted(set(impacted_actions))
        self.affected_invariants = sorted(set(affected_invariants))
        self.scope_reason = scope_reason
        self.impacted_variables = sorted(set(impacted_variables or []))

    @property
    def indirect_actions(self):
        """Actions impacted but not directly changed."""
        changed = set(self.changed_actions)
        return [a for a in self.impacted_actions if a not in changed]

    @property
    def is_isolated(self):
        """True if the change only affects the changed actions themselves."""
        return not self.indirect_actions

    def to_dict(self):
        return {
            "changed_actions": self.changed_actions,
            "impacted_actions": self.impacted_actions,
            "indirect_actions": self.indirect_actions,
            "affected_invariants": self.affected_invariants,
            "impacted_variables": self.impacted_variables,
            "scope_reason": self.scope_reason,
            "is_isolated": self.is_isolated,
        }

    def __repr__(self):
        return ("ImpactSet(changed=%r, impacted=%d actions, "
                "affected_invariants=%r, isolated=%r)"
                % (self.changed_actions, len(self.impacted_actions),
                   self.affected_invariants, self.is_isolated))

# ---------------------------------------------------------------------------
# compute_impact
# ---------------------------------------------------------------------------
def compute_impact(ir, changed_action_names, invariants=None):
    """Compute the impact set for a set of changed action names.

    Parameters
    ----------
    ir : rot.ir.ProtocolIR
        The full protocol IR.
    changed_action_names : iterable of str
        The names of actions that changed (from a code diff).
    invariants : iterable of rot.invariants.Invariant or None
        The invariants to check for impact.  If ``None``, all registered
        invariants from ``rot.invariants`` are used.

    Returns
    -------
    ImpactSet
        The computed impact set.

    Raises
    ------
    ValueError
        If any changed action name is not found in the IR.
    """
    changed = list(changed_action_names)
    if not changed:
        return ImpactSet(
            changed_actions=[],
            impacted_actions=[],
            affected_invariants=[],
            scope_reason="no changed actions; empty impact set",
        )

    # Only transition actions participate in the impact set (the init action
    # is the fixed initial state and is never "changed").
    transitions = [a for a in ir.actions if not a.is_initial]
    actions_by_name = {a.name: a for a in transitions}

    # Validate that all changed action names exist among transition actions.
    missing = [n for n in changed if n not in actions_by_name]
    if missing:
        raise ValueError(
            "changed action(s) not found in IR: %r; have %r"
            % (sorted(missing), sorted(actions_by_name.keys())))

    # Compute free variables for every transition action.
    action_vars = {}
    for a in transitions:
        action_vars[a.name] = _action_free_vars(a)

    # Step 1: union of free vars of the changed actions.
    changed_vars = set()
    for name in changed:
        changed_vars |= action_vars[name]

    # Step 2: find all transition actions that share at least one variable
    # with the changed actions (the "cone of influence").
    impacted_actions = set()
    for a in transitions:
        if action_vars[a.name] & changed_vars:
            impacted_actions.add(a.name)

    # Ensure all changed actions are in the impacted set.
    impacted_actions |= set(changed)

    # Step 3: the full impact scope (union of free vars of impacted actions).
    impacted_vars = set()
    for name in impacted_actions:
        impacted_vars |= action_vars[name]

    # Step 4: find affected invariants.
    affected_invariants = []
    if invariants is None:
        from .invariants import names as _inv_names, get as _inv_get
        invariants = [_inv_get(n) for n in _inv_names()]

    for inv in invariants:
        if inv.expression is None:
            continue
        inv_vars = _free_vars(inv.expression)
        if inv_vars & impacted_vars:
            affected_invariants.append(inv.name)

    # Step 5: build the scope reason.
    n_changed = len(changed)
    n_impacted = len(impacted_actions)
    n_inv = len(affected_invariants)
    if n_changed == n_impacted:
        reason = ("%d action(s) changed with no indirect impact "
                  "(isolated change); %d invariant(s) affected."
                  % (n_changed, n_inv))
    else:
        reason = ("%d action(s) changed; %d action(s) impacted via shared "
                  "state (%d variable(s) in the impact scope); "
                  "%d invariant(s) affected."
                  % (n_changed, n_impacted, len(impacted_vars), n_inv))

    return ImpactSet(
        changed_actions=changed,
        impacted_actions=impacted_actions,
        affected_invariants=affected_invariants,
        scope_reason=reason,
        impacted_variables=sorted(impacted_vars),
    )


__all__ = ["ImpactSet", "compute_impact",
           "_free_vars", "_action_free_vars", "_action_written_vars"]