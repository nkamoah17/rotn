# -*- coding: utf-8 -*-
"""agent_step.py -- the ``AgentStep`` family: adversarial agent-action verification.

This is the narrow-waist frontend that turns an :class:`rot.ir.AdversarialPolicy`
into a bounded, safety-checkable :class:`rot.ir.ProtocolIR`. It models a single
decision step of an autonomous agent that must pick an action from the policy's
universe (``allowed ∪ denied``).

The design reuses the engine's existing existential-choice machinery (the same
pattern the environment fragments in :mod:`rot.env` use), so **no new engine**
is required -- the IR *is* the narrow waist, and the symbolic model finder
explores the choice exhaustively over the bounded state space.

Discriminator (mirrors ``payment`` correct/buggy):

* **correct** -- every *denied* action is policy-enforced: its transition is
  guarded to be never-enabled (``ir.F()``), so a denied action is unreachable
  and ``policy_conformance`` holds in every reachable state.
* **buggy** (compromised / mis-configured agent) -- the denied action is left
  enabled (guard ``decision == "idle"``), so a reachable state exists in which
  the agent has chosen a denied action and ``policy_conformance`` is violated.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir


#: The default adversarial policy for the AgentStep vertical slice.
#:
#: ``read_log`` and ``update_balance`` are permitted; ``exfiltrate_secret`` is
#: forbidden. The discriminator is whether the model finder can reach a state
#: in which the agent has chosen ``exfiltrate_secret``.
DEFAULT_POLICY = ir.AdversarialPolicy(
    allowed=frozenset(["read_log", "update_balance"]),
    denied=frozenset(["exfiltrate_secret"]),
)


def policy_conformance_property(policy=None):
    """The safety predicate: the agent never chooses a denied action.

    Returns an ``Expr`` over the ``decision`` state variable equivalent to
    ``decision ∉ policy.denied`` -- i.e. ``∧_{d ∈ denied} decision != d``.
    When ``denied`` is empty the predicate is trivially true (``ir.T()``).
    """
    policy = policy if policy is not None else DEFAULT_POLICY
    if not policy.denied:
        return ir.T()
    return ir.And(*[ir.neq(ir.V("decision"), ir.C(d)) for d in policy.denied])


def build_ir(n=1, buggy=False, policy=None):
    """Build the AgentStep protocol IR.

    Parameters
    ----------
    n : int
        Participant count. The AgentStep slice is single-actor, so ``n`` is
        accepted for registry compatibility and does not change the model.
    buggy : bool
        ``False`` (default): the agent is *conforming* -- denied actions are
        policy-enforced (never-enabled) and ``policy_conformance`` holds.
        ``True``: the agent is *adversarial* -- denied actions are left
        enabled, so a reachable state violates ``policy_conformance``.
    policy : rot.ir.AdversarialPolicy or None
        The agent policy (defaults to :data:`DEFAULT_POLICY`).

    Returns
    -------
    rot.ir.ProtocolIR
    """
    policy = policy if policy is not None else DEFAULT_POLICY
    universe = sorted(policy.allowed | policy.denied)

    decision = ir.StateVar(
        "decision",
        ir.Enum(["idle"] + universe),
        mode=ir.MODE_EXISTENTIAL,
        owner="agent",
        desc="the action the agent chose this step (existential choice)")

    acts = [
        ir.Action(
            "agent_init",
            "agent",
            is_initial=True,
            effects=[("decision", ir.C("idle"))],
        )
    ]
    for a in universe:
        if a in policy.denied and not buggy:
            # Conforming agent: the policy enforces the denial -- the
            # transition to the denied action is never-enabled.
            guard = ir.F()
        else:
            # Adversarial agent (buggy variant): the agent is free to attempt
            # the action, so a denied action becomes reachable.
            guard = ir.eq(ir.V("decision"), ir.C("idle"))
        acts.append(
            ir.Action(
                "agent_take_%s" % a,
                "agent",
                guard=guard,
                effects=[("decision", ir.C(a))],
            )
        )

    return ir.ProtocolIR(
        name="agent-step",
        variables=[decision],
        actions=acts,
        init=ir.T(),
        pinned_property=policy_conformance_property(policy),
        policy=policy,
        metadata={
            "family": "AGENT_STEP",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "policy_conformance",
            "denied": sorted(policy.denied),
            "allowed": sorted(policy.allowed),
        },
    )


__all__ = ["DEFAULT_POLICY", "policy_conformance_property", "build_ir"]