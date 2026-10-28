# -*- coding: utf-8 -*-
"""rot.policy_verify -- safety and non-vacuity checks for Cedar policies.

This module is the *verification* half of the Cedar policy pipeline.  The
front-end (``rot.frontends.cedar``) compiles Cedar policy text into the IR,
exposing the bounded request space (``principal`` x ``action`` x ``resource``
x attribute values) together with two precise signals written by the
``decide`` action:

  * ``decision``  -- the final verdict (True = permitted);
  * ``forbidden`` -- the raw disjunction of the ``forbid`` rules.

Given that IR, this module checks two *complementary* properties over the
whole bounded request space (a sweep, not a single witness):

  * ``policy_denies_forbidden`` -- **safety (universal)**: for *every*
    reachable request, if a ``forbid`` rule matches (``forbidden`` is True)
    then the verdict is Deny (``decision`` is False).  This is the "forbid
    rules hold / permit rules don't over-grant" check -- the direction a
    realizability-only query cannot express.

  * ``policy_permits_request``  -- **non-vacuity (existential)**: there
    *exists* a reachable request whose verdict is Permit (``decision`` is
    True).  The policy is not vacuous.

Together the two make Cedar a real verifier: one checks the *universal*
safety direction, the other the *existential* realizability direction.

This module sits *downstream* of the narrow waist: it imports
``rot.modelfind`` (the bounded enumerator) and ``rot.ir`` -- never the other
way around (the front-end never imports this module).

Pure stdlib + ``rot.modelfind`` + ``rot.ir``, Python 3.6 compatible.
"""

from .modelfind import ModelFinder
from . import ir

__all__ = ["policy_denies_forbidden", "policy_permits_request"]


def _safety_expr():
    """Build the safety predicate as an IR expression.

    The safety property is ``forbidden -> not decision`` (no forbidden
    request is ever permitted), expressed as ``not forbidden or not
    decision``.  It is evaluated over concrete states by the bounded model
    finder, so it must be a closed IR expression over the IR variables.
    """
    return ir.Or(ir.Not(ir.Var("forbidden")), ir.Not(ir.Var("decision")))


def policy_denies_forbidden(ir, max_states=200000):
    """Safety (universal): the policy denies every forbidden request.

    Sweeps the bounded request space and checks that, for *every* reachable
    state, a matching ``forbid`` rule (``forbidden`` is True) implies the
    verdict is Deny (``decision`` is False).  This is the "forbid rules hold
    / permit rules don't over-grant" check -- the safety direction that a
    realizability-only (``exists``) query cannot express.

    Args:
        ir: the ``ProtocolIR`` produced by ``rot.frontends.cedar.parse_cedar``.
        max_states: budget on the number of reachable states to enumerate.

    Returns:
        A ``(status, detail)`` tuple:

        * ``(True, None)`` -- the safety property holds over the bounded space
          (every forbidden request is denied);
        * ``(False, counter)`` -- a counterexample: a reachable request that is
          forbidden (``forbidden`` True) yet permitted (``decision`` True);
        * ``(UNKNOWN, None)`` -- the reachable-state budget was exceeded, so
          the result is inconclusive (callers must not treat it as True).
    """
    safety = _safety_expr()

    def predicate(state):
        return safety.eval(state)

    return ModelFinder.from_ir(ir, max_states=max_states).forall_reachable(
        predicate)


def policy_permits_request(ir, max_states=200000):
    """Non-vacuity (existential): the policy permits at least one request.

    Checks that there *exists* a reachable request whose verdict is Permit
    (``decision`` is True) -- i.e. the policy is not vacuous.  This is the
    realizability twin of :func:`policy_denies_forbidden`.

    Args:
        ir: the ``ProtocolIR`` produced by ``rot.frontends.cedar.parse_cedar``.
        max_states: budget on the number of reachable states to enumerate.

    Returns:
        A ``(status, detail)`` tuple:

        * ``(SAT, witness)`` -- the policy permits at least one request
          (``witness`` is that permitted request);
        * ``(UNSAT, None)`` -- the policy permits no request (vacuous);
        * ``(UNKNOWN, None)`` -- the reachable-state budget was exceeded.
    """
    return ModelFinder.from_ir(ir, max_states=max_states).exists_reachable(
        lambda state: state.get("decision") is True)