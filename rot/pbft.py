# -*- coding: utf-8 -*-
"""pbft.py -- bounded PBFT prepare/commit vertical slice as a trusted IR.

Two variants share the same state and the same action set; they differ only
in the guard under which a node *commits* the in-flight sequence:

  * CORRECT -- a node commits the sequence only once it holds a quorum
    certificate for it (the primary certified it after every node prepared).
    ``pbft_quorum`` holds; every engine must prove it.

  * BUGGY   -- a node commits the sequence as soon as it has prepared it
    *itself*, without a quorum certificate. A node can then commit a
    sequence for which no quorum was ever reached, violating
    ``pbft_quorum`` (the PBFT analogue of the ZAB premature-apply bug).

The state is deliberately bounded -- one in-flight sequence, ``n`` nodes
(node 1 = primary, nodes 2..n = replicas) -- and every variable is monotone
(``false -> true``), each action idempotency-guarded, so the reachable state
space stays exhaustively enumerable by the bounded model finder (an
independent oracle ahead of TLC/Apalache).

Pure stdlib, Python 3.6 compatible.
"""

from .ir import (ProtocolIR, StateVar, Bool, Assignment, Action,
                 And, eq, If, V, T, F)

# Number of in-flight sequences in the bounded slice. Kept at 1 so the
# reachable state space stays exhaustively enumerable by the model finder.
SEQ = 1


def _prepared(i):
    return "prepared_%d" % i


def _quorum(i):
    return "quorum_%d" % i


def _committed(i):
    return "committed_%d" % i


def build_ir(n=3, buggy=False):
    variables = []
    for i in range(1, n + 1):
        role = "primary" if i == 1 else "replica"
        variables.append(StateVar(
            _prepared(i), Bool(), owner="node_%d" % i,
            desc="%s %d prepared seq %d" % (role, i, SEQ)))
        variables.append(StateVar(
            _quorum(i), Bool(), owner="node_%d" % i,
            desc="%s %d holds a quorum certificate for seq %d" % (role, i, SEQ)))
        variables.append(StateVar(
            _committed(i), Bool(), owner="node_%d" % i,
            desc="%s %d committed seq %d" % (role, i, SEQ)))

    actions = []

    # ---- init ---------------------------------------------------------------
    init_effects = []
    for i in range(1, n + 1):
        init_effects.append(Assignment(_prepared(i), F()))
        init_effects.append(Assignment(_quorum(i), F()))
        init_effects.append(Assignment(_committed(i), F()))
    actions.append(Action(name="init", owner="global",
                          guard=T(), effects=init_effects, is_initial=True))

    # ---- prepare: each node records its prepare vote (environment choice) ---
    for i in range(1, n + 1):
        actions.append(Action(
            name="prepare_%d" % i, owner="node_%d" % i,
            guard=eq(V(_prepared(i)), F()),
            effects=[Assignment(_prepared(i), T())],
            linearization="prepare(seq=%d, node=%d)" % (SEQ, i)))

    # ---- quorum: primary certifies once every node has prepared (quorum = all)
    all_prepared = And(*[eq(V(_prepared(i)), T()) for i in range(1, n + 1)])
    actions.append(Action(
        name="advance", owner="node_1",
        guard=all_prepared,
        effects=[Assignment(_quorum(i), T()) for i in range(1, n + 1)],
        linearization="quorum_certificate(seq=%d)" % SEQ))

    # ---- commit: each node commits the sequence to its state machine --------
    for i in range(1, n + 1):
        not_committed = eq(V(_committed(i)), F())
        if buggy:
            # BUG: the node commits as soon as it has prepared the sequence
            # itself, without a quorum certificate from the primary.
            guard = And(eq(V(_prepared(i)), T()), not_committed)
            linearization = "commit(seq=%d, node=%d) [premature: own prepare only]" % (SEQ, i)
        else:
            guard = And(eq(V(_quorum(i)), T()), not_committed)
            linearization = "commit(seq=%d, node=%d)" % (SEQ, i)
        actions.append(Action(
            name="commit_%d" % i, owner="node_%d" % i,
            guard=guard,
            effects=[Assignment(_committed(i), T())],
            linearization=linearization))

    return ProtocolIR(
        name=("pbft_buggy" if buggy else "pbft_correct"),
        variables=variables,
        actions=actions,
        init=T(),
        pinned_property=quorum_property(n),
        metadata={"protocol": "pbft",
                  "n": n,
                  "seq": SEQ,
                  "buggy": buggy,
                  "description": ("PBFT prepare/commit, %d nodes, %d seq, %s" % (
                      n, SEQ,
                      "BUGGY (nodes commit on their own prepare vote, no quorum)"
                      if buggy
                      else "correct (nodes commit only on a quorum certificate)"))},
    )


def quorum_property(n=3):
    """Pinned safety invariant (PBFT): a node never commits an unquorumed seq.

    For every node ``i``: if the node has committed the sequence, it must
    hold a quorum certificate for it. This is the discriminator between the
    correct and buggy PBFT variants.
    """
    conjs = [If(eq(V(_committed(i)), T()),
                eq(V(_quorum(i)), T()),
                T())
             for i in range(1, n + 1)]
    return And(*conjs) if conjs else T()


def prepare_before_commit_property(n=3):
    """A node commits a sequence only if it has prepared it.

    For every node ``i``: ``committed(i) => prepared(i)``. Holds in both
    variants (the seeded bug is *premature* commit -- committing without a
    quorum certificate -- not committing-before-preparing).
    """
    conjs = [If(eq(V(_committed(i)), T()),
                eq(V(_prepared(i)), T()),
                T())
             for i in range(1, n + 1)]
    return And(*conjs) if conjs else T()


__all__ = ["SEQ", "build_ir",
           "quorum_property", "prepare_before_commit_property"]
