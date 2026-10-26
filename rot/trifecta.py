# -*- coding: utf-8 -*-
"""trifecta.py -- the three-facet policy audit: safety, liveness, conformance.

This module audits an :class:`rot.ir.AdversarialPolicy` against the
:class:`rot.agent_step` model (the narrow waist for adversarial agent
verification) across three distinct facets:

* **Safety** (``forall_reachable``) -- the policy conformance property holds
  in *every* reachable state: the agent never takes a denied action. This is
  the core safety invariant, checked with the bounded exhaustive model finder.

* **Liveness** (``reach_within``) -- the agent can commit to an allowed action
  *within a bounded number of steps* (the horizon). This is bounded liveness:
  the agent is not stuck. Checked with the symbolic engine's
  :meth:`rot.symbolic.SymbolicEngine.reach_within`.

* **Conformance** (``exists_reachable``) -- there exists *some* reachable state
  where the agent has taken an allowed action. This is the non-vacuity /
  realizability check: the policy permits at least one concrete action.
  Checked with the bounded exhaustive model finder.

Soundness contract (inherited from the engines):

* A facet is **proven** only on a *definite* engine result (``True`` /
  ``REACHED`` / ``SAT``); an ``UNKNOWN`` / budget-truncated search is never
  read as proven.
* A facet is **violated** only on a *definite* counterexample (``False`` /
  ``NOT_REACHED`` / ``UNSAT``); an ``UNKNOWN`` is never read as violated.
* The **liveness** facet is always *bounded*: a ``NOT_REACHED`` verdict is
  sound only because the whole horizon was explored (``horizon_complete``).

The module is deterministic: the same policy, horizon, and state budget always
produce the same facet verdicts (the engines are deterministic over the
bounded state space). The policy hash (SHA-256 of the policy's canonical
JSON) is stable across runs.

Pure stdlib, Python 3.6 compatible.
"""

import hashlib
import json

import rot.ir as ir
from rot import agent_step
from rot.modelfind import ModelFinder, ProductTooLarge
from rot.symbolic import SymbolicEngine, REACHED, NOT_REACHED
from rot.linearization import linearize

__all__ = [
    "FacetVerdict",
    "TrifectaResult",
    "audit",
    "allowed_action_property",
    "policy_hash",
]


# Facet status constants (stable, engine-agnostic).
PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"


def _json_default(obj):
    """Fallback serializer for :func:`to_json`.

    Witnesses are normally plain state dicts (JSON-serialisable). For any
    other object we prefer a stable ``to_dict()`` when present, then fall back
    to ``repr`` so serialisation never raises and stays deterministic.
    """
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return repr(obj)


class FacetVerdict(object):
    """The verdict for one audit facet.

    Attributes
    ----------
    facet : str
        The facet name: ``"safety"``, ``"liveness"``, or ``"conformance"``.
    status : str
        One of :data:`PROVEN`, :data:`VIOLATED`, or :data:`UNKNOWN`.
    property_name : str
        The stable property name for reports (e.g. ``"policy_conformance"``).
    witness : object or None
        A concrete witness (state dict or path) for a ``VIOLATED`` (safety /
        conformance) or ``PROVEN`` (liveness) verdict; ``None`` otherwise.
    evidence : dict
        Engine-specific evidence (e.g. ``n_states``, ``complete``, ``depth``).
    n_states : int
        The number of states explored by the engine for this facet.
    note : str
        A human-readable explanation of the verdict.
    """

    def __init__(self, facet, status, property_name="", witness=None,
                 evidence=None, n_states=0, note=""):
        if status not in (PROVEN, VIOLATED, UNKNOWN):
            raise ValueError("bad facet status %r" % (status,))
        self.facet = facet
        self.status = status
        self.property_name = property_name
        self.witness = witness
        self.evidence = evidence or {}
        self.n_states = int(n_states)
        self.note = note

    def is_proven(self):
        return self.status == PROVEN

    def is_violated(self):
        return self.status == VIOLATED

    def is_unknown(self):
        return self.status == UNKNOWN

    def to_dict(self):
        return {
            "facet": self.facet,
            "status": self.status,
            "property_name": self.property_name,
            "witness": self.witness,
            "evidence": self.evidence,
            "n_states": self.n_states,
            "note": self.note,
        }

    def to_json(self):
        """Deterministic JSON (sorted keys, compact separators)."""
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"), default=_json_default)

    def __repr__(self):
        return "FacetVerdict(%s=%s)" % (self.facet, self.status)

class TrifectaResult(object):
    """The aggregated result of the three-facet audit.

    Attributes
    ----------
    safety : FacetVerdict
        The safety facet verdict.
    liveness : FacetVerdict
        The liveness facet verdict.
    conformance : FacetVerdict
        The conformance facet verdict.
    policy_hash : str
        The SHA-256 hex digest of the policy's canonical JSON (stable).
    ir_name : str
        The name of the agent-step IR that was audited.
    n_states : int
        The total number of states explored across all three facets.
    """

    def __init__(self, safety, liveness, conformance, policy_hash="",
                 ir_name="", n_states=0):
        self.safety = safety
        self.liveness = liveness
        self.conformance = conformance
        self.policy_hash = policy_hash
        self.ir_name = ir_name
        self.n_states = int(n_states)

    def all_proven(self):
        """True iff all three facets are proven (the policy is sound)."""
        return (self.safety.is_proven()
                and self.liveness.is_proven()
                and self.conformance.is_proven())

    def any_violated(self):
        """True iff any facet is violated (the policy is unsound)."""
        return (self.safety.is_violated()
                or self.liveness.is_violated()
                or self.conformance.is_violated())

    def to_dict(self):
        return {
            "safety": self.safety.to_dict(),
            "liveness": self.liveness.to_dict(),
            "conformance": self.conformance.to_dict(),
            "policy_hash": self.policy_hash,
            "ir_name": self.ir_name,
            "n_states": self.n_states,
        }

    def to_json(self):
        """Deterministic JSON (sorted keys, compact separators)."""
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":"), default=_json_default)

    def __repr__(self):
        return ("TrifectaResult(safety=%s, liveness=%s, conformance=%s)"
                % (self.safety.status, self.liveness.status,
                   self.conformance.status))


def policy_hash(policy):
    """Compute the SHA-256 hex digest of the policy's canonical JSON.

    The policy's :meth:`rot.ir.AdversarialPolicy.to_dict` method returns a
    sorted, order-independent dict, so the JSON serialization is stable and
    the hash is deterministic across runs.
    """
    policy_dict = policy.to_dict()
    policy_json = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(policy_json.encode("utf-8")).hexdigest()


def allowed_action_property(policy):
    """The liveness/conformance goal: the agent has taken an allowed action.

    Returns an :class:`rot.ir.Expr` over the ``decision`` state variable
    equivalent to ``decision in policy.allowed`` -- i.e.
    ``Or(eq(decision, a)) for a in allowed``. When ``allowed`` is empty the
    predicate is trivially false (``ir.F()``).
    """
    if not policy.allowed:
        return ir.F()
    return ir.Or(*[ir.eq(ir.V("decision"), ir.C(a))
                   for a in sorted(policy.allowed)])


def _reachable_states_bounded(ir_model, max_states):
    """Enumerate the reachable states once, respecting the state budget.

    Returns a tuple ``(states, n_states, truncated)`` where:

    * ``states`` is the list of reachable state dicts, or ``None`` when the
      search was truncated by the budget;
    * ``n_states`` is the number of reachable states enumerated;
    * ``truncated`` is ``True`` iff the search was cut off by the state budget.
      A truncated exploration is *incomplete* and must be read as ``UNKNOWN``
      (never as proven or violated).

    This mirrors :meth:`rot.modelfind.ModelFinder.reachable_states`, which
    raises :class:`rot.modelfind.ProductTooLarge` on budget exhaustion; we
    catch that and report it as a truncated, incomplete exploration. Enumerating
    once and reusing the result for both the safety and conformance facets
    avoids redundant BFS and yields a true ``n_states`` (not the budget).
    """
    mf = ModelFinder.from_ir(ir_model, max_states=max_states)
    try:
        states = mf.reachable_states()
    except ProductTooLarge:
        return None, 0, True
    return states, len(states), False


def _audit_safety(safety_prop, states, n_states, truncated):
    """Facet 1: Safety -- the policy conformance property holds in every
    reachable state.

    This mirrors the bounded exhaustive model finder's ``forall_reachable``
    semantics over the shared reachable-state enumeration: a definite
    counterexample (a reachable state where the property evaluates ``False``)
    is a violation; a fully explored state space with no counterexample is a
    proof; a budget-truncated search is ``UNKNOWN``. Predicate evaluation
    treats an ``UNDEF`` result as "cannot refute" (conservative), exactly as
    ``ModelFinder.forall_reachable`` does.
    """
    if truncated:
        status = UNKNOWN
        witness = None
        note = "the reachable state space was not fully explored (budget)"
    else:
        witness = None
        for s in states:
            r = safety_prop.eval(s)
            if r is not ir.Expr.UNDEF and not r:
                witness = s
                break
        if witness is None:
            status = PROVEN
            note = "policy conformance holds in every reachable state"
        else:
            status = VIOLATED
            note = "a reachable state violates policy conformance"

    return FacetVerdict(
        facet="safety",
        status=status,
        property_name="policy_conformance",
        witness=witness,
        evidence={
            "engine": "ModelFinder",
            "method": "forall_reachable",
            "n_states": n_states,
            "truncated": truncated,
        },
        n_states=n_states,
        note=note,
    )


def _audit_liveness(ir_model, horizon, max_states):
    """Facet 2: Liveness -- the agent can reach an allowed action within the
    horizon.

    Uses the symbolic engine's ``reach_within``: the agent must commit to an
    allowed action within ``horizon`` steps. A ``REACHED`` result is a proof
    (with a concrete path witness); a ``NOT_REACHED`` result (only when the
    whole horizon was explored) is a violation; a budget-truncated search is
    ``UNKNOWN``.
    """
    goal = allowed_action_property(ir_model.policy)
    linear_model = linearize(ir_model)
    eng = SymbolicEngine(linear_model, max_states=max_states)
    reach = eng.reach_within(goal, horizon, max_states=max_states)

    if reach.status == REACHED:
        status = PROVEN
        note = ("an allowed action is reachable within %d step(s) "
                "(reached at depth %s)" % (horizon, reach.depth))
        witness = reach.path
    elif reach.status == NOT_REACHED:
        status = VIOLATED
        note = ("no allowed action is reachable within %d step(s) "
                "(the agent is stuck)" % horizon)
        witness = None
    else:
        status = UNKNOWN
        note = ("the bounded search was truncated by the state budget "
                "before the horizon finished")
        witness = None

    return FacetVerdict(
        facet="liveness",
        status=status,
        property_name="bounded_allowed_action",
        witness=witness,
        evidence={
            "engine": "SymbolicEngine.reach_within",
            "horizon": horizon,
            "depth": reach.depth,
            "budget_complete": reach.budget_complete,
            "horizon_complete": reach.horizon_complete,
        },
        n_states=reach.n_states,
        note=note,
    )


def _audit_conformance(goal, states, n_states, truncated):
    """Facet 3: Conformance -- there exists a reachable state where an
    allowed action was taken.

    This mirrors the bounded exhaustive model finder's ``exists_reachable``
    semantics over the shared reachable-state enumeration: a reachable state
    where the goal holds is a proof (with a concrete witness); a fully
    explored state space with no such state is a violation (the policy is
    vacuous / unrealisable); a budget-truncated search is ``UNKNOWN``.
    """
    if truncated:
        status = UNKNOWN
        witness = None
        note = "the reachable state space was not fully explored (budget)"
    else:
        witness = None
        for s in states:
            r = goal.eval(s)
            if r is not ir.Expr.UNDEF and r:
                witness = s
                break
        if witness is None:
            status = VIOLATED
            note = "no reachable state exists where an allowed action was taken"
        else:
            status = PROVEN
            note = "a reachable state exists where an allowed action was taken"

    return FacetVerdict(
        facet="conformance",
        status=status,
        property_name="allowed_action_reachable",
        witness=witness,
        evidence={
            "engine": "ModelFinder",
            "method": "exists_reachable",
            "n_states": n_states,
            "truncated": truncated,
        },
        n_states=n_states,
        note=note,
    )


def audit(policy, buggy=False, horizon=12, max_states=200000):
    """Run the three-facet audit on the AgentStep model.

    Parameters
    ----------
    policy : rot.ir.AdversarialPolicy
        The agent policy to audit. The policy's ``allowed`` and ``denied``
        sets partition the agent's action space.
    buggy : bool
        If ``False`` (default), the agent is *conforming* -- denied actions
        are policy-enforced (never-enabled) and ``policy_conformance`` holds.
        If ``True``, the agent is *adversarial* -- denied actions are left
        enabled, so a reachable state may violate ``policy_conformance``.
    horizon : int
        The bounded-liveness horizon (max steps) for the liveness facet.
        Default 12 (matching the pipeline's default).
    max_states : int
        The state budget for the model finder and symbolic engine.
        Default 200000 (matching the pipeline's default).

    Returns
    -------
    TrifectaResult
        The aggregated result of the three-facet audit.

    Raises
    ------
    ValueError
        If the policy is invalid (e.g. ``allowed`` and ``denied`` overlap).
    """
    # Build the agent-step model (the narrow waist) and validate it.
    overlap = set(policy.allowed) & set(policy.denied)
    if overlap:
        raise ValueError(
            "policy allowed and denied overlap: %r" % (sorted(overlap),))
    ir_model = agent_step.build_ir(buggy=buggy, policy=policy)
    errors = ir_model.validate()
    if errors:
        raise ValueError("agent-step IR is invalid: %r" % (errors,))

    # Compute the deterministic policy hash.
    p_hash = policy_hash(policy)

    # The two model-finder facets (safety, conformance) share one bounded
    # enumeration of the reachable state space. The safety property is the
    # canonical policy-conformance invariant; the conformance goal is the
    # "an allowed action was taken" predicate.
    safety_prop = agent_step.policy_conformance_property(policy)
    conformance_goal = allowed_action_property(policy)
    states, n_states, truncated = _reachable_states_bounded(ir_model, max_states)

    # Run the three facets (independent, deterministic).
    safety = _audit_safety(safety_prop, states, n_states, truncated)
    liveness = _audit_liveness(ir_model, horizon, max_states)
    conformance = _audit_conformance(conformance_goal, states, n_states,
                                     truncated)

    return TrifectaResult(
        safety=safety,
        liveness=liveness,
        conformance=conformance,
        policy_hash=p_hash,
        ir_name=ir_model.name,
        n_states=safety.n_states + liveness.n_states + conformance.n_states,
    )


