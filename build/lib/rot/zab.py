# -*- coding: utf-8 -*-
"""zab.py -- the bounded ZAB broadcast/commit vertical slice as a trusted IR.

Two variants share the same state and the same actions; they differ only in the
guard under which a follower *applies* a transaction to its state machine:

  * CORRECT -- a follower applies a transaction only after the leader has
    *committed* it (i.e. every follower has persisted it) AND the follower has
    persisted it itself. ``zab_no_premature_apply`` holds; every engine must
    prove it.

  * BUGGY   -- a follower applies a transaction as soon as it has persisted it,
    *before* the leader has committed it. A follower can therefore apply an
    uncommitted transaction, violating ``zab_no_premature_apply`` (the ZAB
    analogue of the 2PC agreement bug). Every engine must find that
    counterexample.

The state is deliberately bounded -- ``M`` in-flight transactions, ``n``
followers -- and every variable is monotone (``none -> done``), each action
idempotency-guarded, so the reachable state space stays exhaustively enumerable
by the bounded model finder (an independent oracle ahead of TLC/Apalache).

Pure stdlib, Python 3.6 compatible.
"""

from .ir import (ProtocolIR, StateVar, Enum, Assignment, Action,
                 And, eq, If, V, C, T)

MARK = ["none", "done"]

_NONE = "none"
_DONE = "done"

# Number of in-flight transactions in the bounded slice. Kept small so the
# reachable state space stays exhaustively enumerable by the model finder.
M = 2


def _persisted(i, j):
    return "persisted_%d_%d" % (i, j)


def _applied(i, j):
    return "applied_%d_%d" % (i, j)


def _committed(i):
    return "committed_%d" % i


def build_ir(n=3, buggy=False):
    variables = []
    for i in range(1, M + 1):
        for j in range(1, n + 1):
            variables.append(StateVar(_persisted(i, j), Enum(MARK),
                                      owner="follower_%d" % j,
                                      desc="follower %d persisted tx %d" % (j, i)))
            variables.append(StateVar(_applied(i, j), Enum(MARK),
                                     owner="follower_%d" % j,
                                     desc="follower %d applied tx %d" % (j, i)))
        variables.append(StateVar(_committed(i), Enum(MARK), owner="leader",
                                  desc="leader committed tx %d" % i))

    actions = []

    # ---- init ---------------------------------------------------------------
    init_effects = []
    for i in range(1, M + 1):
        for j in range(1, n + 1):
            init_effects.append(Assignment(_persisted(i, j), C(_NONE)))
            init_effects.append(Assignment(_applied(i, j), C(_NONE)))
        init_effects.append(Assignment(_committed(i), C(_NONE)))
    actions.append(Action(name="init", owner="global",
                          guard=T(), effects=init_effects, is_initial=True))

    # ---- persist: each follower durably appends the tx (environment choice) --
    for i in range(1, M + 1):
        for j in range(1, n + 1):
            actions.append(Action(
                name="persist_%d_%d" % (i, j), owner="follower_%d" % j,
                guard=eq(V(_persisted(i, j)), C(_NONE)),
                effects=[Assignment(_persisted(i, j), C(_DONE))],
                linearization="persist(tx%d, f%d)" % (i, j)))

    # ---- leader commits once all followers have persisted (quorum = all) ----
    for i in range(1, M + 1):
        all_persisted = And(*[eq(V(_persisted(i, j)), C(_DONE))
                              for j in range(1, n + 1)])
        actions.append(Action(
            name="commit_%d" % i, owner="leader",
            guard=And(all_persisted, eq(V(_committed(i)), C(_NONE))),
            effects=[Assignment(_committed(i), C(_DONE))],
            linearization="commit(tx%d)" % i))

    # ---- apply: each follower applies the tx to its state machine -----------
    for i in range(1, M + 1):
        for j in range(1, n + 1):
            persisted = eq(V(_persisted(i, j)), C(_DONE))
            not_applied = eq(V(_applied(i, j)), C(_NONE))
            if buggy:
                # BUG: the follower applies as soon as it has persisted, even if
                # the leader has not yet committed the transaction.
                guard = And(persisted, not_applied)
            else:
                committed = eq(V(_committed(i)), C(_DONE))
                guard = And(committed, persisted, not_applied)
            actions.append(Action(
                name="apply_%d_%d" % (i, j), owner="follower_%d" % j,
                guard=guard,
                effects=[Assignment(_applied(i, j), C(_DONE))],
                linearization="apply(tx%d, f%d)" % (i, j)))

    return ProtocolIR(
        name=("zab_buggy" if buggy else "zab_correct"),
        variables=variables,
        actions=actions,
        init=T(),
        pinned_property=no_premature_apply_property(n),
        metadata={"protocol": "zab",
                  "n": n,
                  "m": M,
                  "buggy": buggy,
                  "description": ("ZAB broadcast/commit, %d followers, %d tx, %s" % (
                      n, M,
                      "BUGGY (followers apply before the leader commits)" if buggy
                      else "correct (followers apply only after commit)"))},
    )


def no_premature_apply_property(n=3):
    """Pinned safety invariant (ZAB): a follower never applies an uncommitted tx.

    For every follower ``j`` and transaction ``i``: if the follower has applied
    the transaction, the leader must have committed it. This is the discriminator
    between the correct and buggy ZAB variants.
    """
    conjs = []
    for j in range(1, n + 1):
        for i in range(1, M + 1):
            conjs.append(
                If(eq(V(_applied(i, j)), C(_DONE)),
                   eq(V(_committed(i)), C(_DONE)),
                   T()))
    return And(*conjs) if conjs else T()


def apply_persisted_property(n=3):
    """A follower applies a transaction only if it has persisted it.

    For every follower ``j`` and transaction ``i``:
    ``applied(i,j) => persisted(i,j)``. Holds in both variants (the seeded bug is
    *premature* apply -- applying before the leader commits -- not
    applying-before-persisting).
    """
    conjs = []
    for j in range(1, n + 1):
        for i in range(1, M + 1):
            conjs.append(
                If(eq(V(_applied(i, j)), C(_DONE)),
                   eq(V(_persisted(i, j)), C(_DONE)),
                   T()))
    return And(*conjs) if conjs else T()


__all__ = ["MARK", "M", "build_ir",
           "no_premature_apply_property", "apply_persisted_property"]