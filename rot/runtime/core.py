# -*- coding: utf-8 -*-
"""rot.runtime.core -- the ``RuntimeGuard`` (B1): the deterministic core decides.

The motto, made live: *"the deterministic core decides -- the LLM proposes."*
At runtime an agent *proposes* a tool call (a request).  The :class:`RuntimeGuard`
*decides* it: it evaluates the rule's ``ProtocolIR`` **guard predicate** -- the
same predicate the offline engine discharged -- against the current state, and
returns the exact refusal shape::

    {"blocked", "rule", "why", "to_proceed", "allowed_now"}

There is **no new proof engine** here.  The decision is a single ``Expr.eval``
of the guard (the spec) in the state -- the identical predicate the offline
soundness core proved safe.  The ``to_proceed`` enabling condition is computed
by :func:`rot.to_proceed.compute_to_proceed` (the thesis's "computed
mathematically" claim), so the refusal says *what must hold* to proceed, read
straight from the guard -- not a hand-written rationale.

The guard is **shape-agnostic**: it decides any ``ProtocolIR`` decision action.
What makes it *reusable* is that the concrete rule (the spend-cap rule, the
exfiltration rule, ...) supplies (a) the ``ProtocolIR`` + decision action and
(b) the canonical, human-readable ``why`` / ``to_proceed`` strings for that
shape.  The core supplies the *mechanism*; the rule supplies the *meaning*.

Design contract
---------------

  * **Deterministic.**  :meth:`RuntimeGuard.decide` is a pure function of
    (rule, action, state, request): no timestamps, no randomness.  Two calls
    with the same inputs produce byte-identical refusals (same hash).
  * **Fail-closed on unknown.**  If the guard evaluates to the IR's ``UNDEF``
    (a value depending on an unmodelled atom), the guard is read as *not
    proven safe* -- the call is **blocked** (UNKNOWN never read as allowed),
    consistent with the IR's sound fallback.
  * **Auditable.**  Every :class:`~rot.runtime.refusal.Refusal` records the
    guard (rendered), the state, and the computed ``to_proceed`` conditions,
    so a reader can re-run the guard on the recorded state and confirm the
    decision byte-for-byte (via the refusal hash) -- no proof engine needed.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

import rot.ir as ir
from rot.to_proceed import compute_to_proceed
from .refusal import Refusal, SCHEMA

__all__ = [
    "ALLOWED",
    "BLOCKED",
    "Decision",
    "RuntimeGuard",
    "Rule",
]

#: The two possible decisions (stable tokens).
ALLOWED = "allowed"
BLOCKED = "blocked"


class Decision(object):
    """The outcome of one :meth:`RuntimeGuard.decide` call.

    A :class:`Decision` wraps the :class:`~rot.runtime.refusal.Refusal` (the
    exact five-field shape plus provenance) and the decision in one word.
    The refusal is present for **both** decisions: an *allowed* refusal is the
    same shape with ``blocked=False`` / ``allowed_now=True`` and a ``why`` of
    ``""`` (nothing to explain) -- so the refusal shape is uniform whether the
    call is permitted or denied.
    """

    def __init__(self, decision, refusal):
        if decision not in (ALLOWED, BLOCKED):
            raise ValueError("bad decision %r" % (decision,))
        self.decision = decision
        self.refusal = refusal

    @property
    def blocked(self):
        """``True`` when the call was denied."""
        return self.decision == BLOCKED

    @property
    def allowed(self):
        """``True`` when the call was permitted."""
        return self.decision == ALLOWED

    def to_dict(self):
        """The refusal body (the exact five-field shape + provenance + hash)."""
        return self.refusal.to_dict()

    def to_json(self, indent=2):
        """The refusal as deterministic JSON."""
        return self.refusal.to_json(indent=indent)

    def __repr__(self):
        return "Decision(%s, rule=%r)" % (self.decision, self.refusal.rule)


class Rule(object):
    """A concrete runtime rule: a ``ProtocolIR`` decision action + its shape.

    A rule is the *meaning* the :class:`RuntimeGuard` applies the *mechanism*
    to.  It carries:

      * ``ir``           -- the :class:`rot.ir.ProtocolIR` (the spec);
      * ``action``       -- the decision action name in the IR (e.g.
                            ``"spend_ok"``);
      * ``rule_id``      -- the stable rule id (e.g. ``"spendcap_within_cap"``);
      * ``why``          -- the canonical, human-readable reason a call of this
                            shape is blocked (a string, or a callable of the
                            state -- for rules whose reason names a
                            state-dependent quantity, like the in-flight count);
      * ``to_proceed``   -- the canonical remediation string (what to do to
                            proceed); when ``None`` the core computes it from
                            the guard's false conjuncts.

    The guard predicate itself is *not* stored here -- it is read from the
    ``ProtocolIR`` action (the spec is the single source of truth), so a rule
    can never drift from the predicate it is meant to enforce.
    """

    def __init__(self, ir, action, rule_id, why=None, to_proceed=None,
                 description=""):
        self.ir = ir
        self.action = action
        self.rule_id = rule_id
        self.why = why
        self.to_proceed = to_proceed
        self.description = description

    def guard(self):
        """The decision action's guard (an ``ir.Expr``), read from the spec."""
        return self.ir.action(self.action).guard

    def why_for(self, state):
        """Resolve the rule's ``why`` for ``state`` (string or callable)."""
        if self.why is None:
            return ""
        if callable(self.why):
            return self.why(state)
        return self.why

    def to_dict(self):
        """A stable description of the rule (for the ledger / reports)."""
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "description": self.description,
        }

    def __repr__(self):
        return "Rule(rule_id=%r, action=%r)" % (self.rule_id, self.action)



class RuntimeGuard(object):
    """The deterministic allow/deny core (B1).

    Given a :class:`Rule` (a ``ProtocolIR`` decision action + its canonical
    strings), the guard decides a request by evaluating the guard predicate
    (the spec) against the current state.  It returns a :class:`Decision`
    wrapping a :class:`~rot.runtime.refusal.Refusal` -- the exact refusal
    shape ``{blocked, rule, why, to_proceed, allowed_now}``.

    Parameters
    ----------
    rule : rot.runtime.core.Rule
        The rule to enforce (the ``ProtocolIR`` + decision action + strings).
    action : str, optional
        Override the rule's decision action name (defaults to ``rule.action``).
    """

    def __init__(self, rule, action=None):
        if not isinstance(rule, Rule):
            raise TypeError("RuntimeGuard expects a Rule (got %r)"
                            % type(rule).__name__)
        self.rule = rule
        self.action = action or rule.action
        if self.ir().action(self.action) is None:
            raise ValueError(
                "action %r not found in rule IR %r" % (self.action,
                                                       self.ir().name))

    # -- accessors -----------------------------------------------------------
    def ir(self):
        """The rule's ``ProtocolIR`` (the spec)."""
        return self.rule.ir

    def guard_expr(self):
        """The decision action's guard (an ``ir.Expr``)."""
        return self.rule.guard()

    def _state(self, state, request):
        """Merge an explicit ``state`` with any state carried by ``request``.

        ``state`` wins on key collisions (it is the authoritative state); the
        request's ``state`` (if any) fills in the rest.  ``None`` yields ``{}``.
        """
        out = {}
        if isinstance(request, dict):
            req_state = request.get("state") or {}
            if isinstance(req_state, dict):
                out.update(req_state)
        if state:
            out.update(state)
        return out

    def _action_from(self, request):
        """The action name for a request (defaults to the rule's action)."""
        if isinstance(request, dict):
            for key in ("action", "tool", "name", "tool_name"):
                v = request.get(key)
                if isinstance(v, str) and v and self.ir().action(v) is not None:
                    return v
        return self.action

    def _render(self, expr):
        """Render an ``ir.Expr`` to its TLA-flavoured ASCII form (stable)."""
        from rot.design_view import expr_to_str
        try:
            return expr_to_str(expr)
        except Exception:
            return repr(expr)

    # -- decision ------------------------------------------------------------
    def decide(self, state=None, request=None):
        """Decide a request against the guard (the deterministic core).

        Parameters
        ----------
        state : dict, optional
            The current state (e.g. ``{"completed": 0, "inflight": 3}``).  For
            the spend-cap shape this is computed from the request history
            (settled vs in-flight transfers).  ``None`` / empty is the initial
            state (all variables unset -> the guard may read ``UNDEF``).
        request : dict, optional
            The proposed tool call.  May carry ``"tool"`` / ``"name"`` (the
            action), ``"state"`` (merged under ``state``), and free-form
            ``"args"`` (recorded for the ledger / audit).  It is *not* needed
            for the decision itself -- the guard is the decision -- but it is
            recorded in the refusal so the refusal names the call it decided.

        Returns
        -------
        Decision
            ``Decision(ALLOWED, ...)`` or ``Decision(BLOCKED, ...)`` wrapping
            a deterministic, hashable :class:`~rot.runtime.refusal.Refusal`.
        """
        state = self._state(state, request)
        action = self._action_from(request)
        guard = self.ir().action(action).guard

        # The decision: evaluate the guard predicate (the spec) in the state.
        # UNDEF (a value depending on an unmodelled atom) is read as *not
        # proven safe* -- fail-closed -- never as allowed.
        value = guard.eval(state)
        if value is ir.Expr.UNDEF:
            blocked = True
            allowed_now = False
        else:
            blocked = (value is not True)
            allowed_now = (value is True)

        # The computed to_proceed (the enabling condition, read from the spec).
        # For an allowed call there is nothing to satisfy (conditions == []).
        tp = compute_to_proceed(self.ir(), action, state)
        conditions = tp.get("conditions", []) if blocked else []
        blockers = tp.get("blockers", []) if blocked else []

        if blocked:
            why = self.rule.why_for(state) or (
                "the guard for '%s' does not hold in state %s"
                % (action, state))
            to_proceed = (self.rule.to_proceed
                          or ("; ".join(conditions) if conditions
                              else tp.get("explanation", "see guard")))
        else:
            why = ""
            to_proceed = ""

        refusal = Refusal(
            blocked=blocked,
            rule=self.rule.rule_id,
            why=why,
            to_proceed=to_proceed,
            allowed_now=allowed_now,
            schema=SCHEMA,
            action=action,
            guard=self._render(guard),
            state=state,
            conditions=conditions,
            blockers=blockers,
        )
        decision = BLOCKED if blocked else ALLOWED
        return Decision(decision, refusal)

