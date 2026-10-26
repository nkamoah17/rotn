# -*- coding: utf-8 -*-
"""twopc.py -- the 2PC vertical-slice target as a trusted IR.

Two variants share the same state, the same actions, and the same pinned
(agreement) property; they differ only in how participants apply the decision:

  * CORRECT -- every participant applies the coordinator's decision
    (``applied_i = decision``). Agreement holds by construction; TLC must prove it.

  * BUGGY   -- participants apply their *own* vote instead of the coordinator's
    decision (``applied_i = (vote_i = yes) ? commit : abort``). A single "yes"
    among a mixed set makes one commit while another aborts, violating agreement.
    TLC must find that counterexample.

This is the CEGAR/verdict demo: one variant passes, one fails, and the failure
comes back with a concrete, IR-feasible counterexample.
Pure stdlib, Python 3.6 compatible.
"""

from .ir import (ProtocolIR, StateVar, Enum, Assignment, Action,
                 And, Or, Not, eq, If, V, C, T)

PHASES = ["prepare", "decided", "done"]
VOTE = ["none", "yes", "no"]
DECISION = ["none", "commit", "abort"]

_NONE = "none"
_YES = "yes"
_NO = "no"
_COMMIT = "commit"
_ABORT = "abort"
_PREPARE = "prepare"
_DECIDED = "decided"
_DONE = "done"


def _vote_eq(i, value):
    return eq(V("vote_%d" % i), C(value))


def build_ir(n=3, buggy=False):
    variables = [
        StateVar("phase", Enum(PHASES), owner="global"),
        StateVar("decision", Enum(DECISION), owner="coordinator"),
    ]
    for i in range(1, n + 1):
        variables.append(StateVar("vote_%d" % i, Enum(VOTE),
                                  owner="participant_%d" % i))
        variables.append(StateVar("applied_%d" % i, Enum(DECISION),
                                  owner="participant_%d" % i))

    actions = []

    # ---- init ---------------------------------------------------------------
    init_effects = [Assignment("phase", C(_PREPARE)),
                    Assignment("decision", C(_NONE))]
    for i in range(1, n + 1):
        init_effects.append(Assignment("vote_%d" % i, C(_NONE)))
        init_effects.append(Assignment("applied_%d" % i, C(_NONE)))
    actions.append(Action(name="init", owner="global",
                          guard=T(), effects=init_effects,
                          is_initial=True))

    # ---- prepare: each participant votes (choice actions model the environment)
    for i in range(1, n + 1):
        guard = And(eq(V("phase"), C(_PREPARE)), _vote_eq(i, _NONE))
        actions.append(Action(name="vote_%d_yes" % i, owner="participant_%d" % i,
                              guard=guard,
                              effects=[Assignment("vote_%d" % i, C(_YES))]))
        actions.append(Action(name="vote_%d_no" % i, owner="participant_%d" % i,
                              guard=guard,
                              effects=[Assignment("vote_%d" % i, C(_NO))]))

    # ---- coordinator decides ------------------------------------------------
    all_voted = And(*[Not(_vote_eq(i, _NONE)) for i in range(1, n + 1)])
    all_yes = And(*[_vote_eq(i, _YES) for i in range(1, n + 1)])
    decide_guard = And(eq(V("phase"), C(_PREPARE)), all_voted)
    decision_val = If(all_yes, C(_COMMIT), C(_ABORT))
    actions.append(Action(name="decide", owner="coordinator",
                          guard=decide_guard,
                          effects=[Assignment("decision", decision_val),
                                   Assignment("phase", C(_DECIDED))],
                          linearization="send(decide)"))

    # ---- apply: participants decide ----------------------------------------
    for i in range(1, n + 1):
        guard = eq(V("phase"), C(_DECIDED))
        if buggy:
            # BUG: participant decides from its own vote, ignoring the coordinator
            self_decide = If(_vote_eq(i, _YES), C(_COMMIT), C(_ABORT))
            actions.append(Action(name="apply_%d" % i, owner="participant_%d" % i,
                                  guard=guard,
                                  effects=[Assignment("applied_%d" % i, self_decide)]))
        else:
            actions.append(Action(name="apply_%d" % i, owner="participant_%d" % i,
                                  guard=guard,
                                  effects=[Assignment("applied_%d" % i, V("decision"))]))

    # ---- done ---------------------------------------------------------------
    all_applied = And(*[Not(eq(V("applied_%d" % i), C(_NONE)))
                        for i in range(1, n + 1)])
    actions.append(Action(name="done", owner="coordinator",
                          guard=And(eq(V("phase"), C(_DECIDED)), all_applied),
                          effects=[Assignment("phase", C(_DONE))],
                          linearization="finalize"))

    return ProtocolIR(
        name=("twopc_buggy" if buggy else "twopc_correct"),
        variables=variables,
        actions=actions,
        init=T(),
        pinned_property=agreement_property(n),
        metadata={"n": n,
                  "buggy": buggy,
                  "description": ("Two-phase commit, %d participants, %s" % (
                      n, "BUGGY (participants self-decide)" if buggy
                      else "correct (participants apply coordinator decision)"))},
    )


def agreement_property(n=3):
    """Pinned safety invariant (2PC agreement): decisions, once made, agree.

    For every pair of participants: if both have made a real decision they must
    be the same (a participant that has not decided yet imposes no constraint).
    This is the correct invariant -- it tolerates the transient "some decided,
    some not yet" states that occur while the coordinator's decision is applied.
    """
    conjs = []
    for i in range(1, n + 1):
        for j in range(i + 1, n + 1):
            none_i = eq(V("applied_%d" % i), C("none"))
            none_j = eq(V("applied_%d" % j), C("none"))
            equal = eq(V("applied_%d" % i), V("applied_%d" % j))
            conjs.append(Or(none_i, none_j, equal))
    return And(*conjs) if conjs else T()


def validity_property(n=3):
    """If the coordinator decided commit, every participant voted yes."""
    conjs = [If(eq(V("decision"), C(_COMMIT)),
               _vote_eq(i, _YES), T())
             for i in range(1, n + 1)]
    return And(*conjs)


__all__ = ["PHASES", "VOTE", "DECISION", "build_ir",
           "agreement_property", "validity_property"]