# -*- coding: utf-8 -*-
"""Research invariant kinds (ZAB / PBFT / payment / approval / liveness).

These are the invariant *kinds* that the research plane pins.  They were
previously defined in ``rot.invariants``; after the product/research split
they live here and are re-registered into the shared ``rot.invariants``
registry via ``register`` so that research targets resolve exactly as before.

The product never imports this module; only the research plane (and its
tests) do.  Importing ``rotn_research`` triggers the registration at the
bottom of this file.
"""
from rot import ir                                    # product (shared IR)
import rot.invariants as _inv                         # product (registry)
from rot.invariants import (                          # product (data model)
    Invariant,
    LABEL_BOUNDED, LABEL_EVENTUALLY,
    KIND_SAFETY, KIND_LIVENESS,
    RUNG_STRUCTURAL, RUNG_LOCAL, RUNG_PROTOCOL, RUNG_E2E,
)
from rot.verdicts import DEADLOCK                     # product (violation code)
import rotn_research.zab as zab                       # research
import rotn_research.payment as payment               # research
import rotn_research.approval as approval             # research (CAP + props)

def zab_no_premature_apply(n=3):
    """ZAB: a follower never applies an uncommitted transaction.

    For every follower ``j`` and transaction ``i``:
    ``applied(i,j) = done => committed(i) = done``.
    This is the discriminator between the correct and buggy ZAB variants.
    """
    conjs = []
    for j in range(1, n + 1):
        for i in range(1, zab.M + 1):
            conjs.append(ir.If(
                ir.eq(ir.V("applied_%d_%d" % (i, j)), ir.C("done")),
                ir.eq(ir.V("committed_%d" % i), ir.C("done")),
                ir.T()))
    return Invariant(
        name="zab_no_premature_apply",
        description="ZAB: followers never apply a tx before the leader commits it",
        expression=ir.And(*conjs) if conjs else ir.T(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
    )


def zab_apply_persisted(n=3):
    """ZAB: a follower applies a transaction only if it has persisted it.

    For every follower ``j`` and transaction ``i``:
    ``applied(i,j) = done => persisted(i,j) = done``.
    Holds in both variants (the seeded bug is *premature* apply, not
    apply-before-persisting).
    """
    conjs = []
    for j in range(1, n + 1):
        for i in range(1, zab.M + 1):
            conjs.append(ir.If(
                ir.eq(ir.V("applied_%d_%d" % (i, j)), ir.C("done")),
                ir.eq(ir.V("persisted_%d_%d" % (i, j)), ir.C("done")),
                ir.T()))
    return Invariant(
        name="zab_apply_persisted",
        description="ZAB: followers apply only what they have persisted",
        expression=ir.And(*conjs) if conjs else ir.T(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=False,  # holds in both variants; informational, not a blocking gate
        rung=RUNG_LOCAL,  # per-follower (actor-local) property: never blocks
    )


def pbft_quorum(n=3):
    """PBFT: a node never commits a sequence for which it holds no quorum.

    For every node ``i``: ``committed(i) => quorum(i)``.
    This is the discriminator between the correct and buggy PBFT variants.
    """
    conjs = []
    for i in range(1, n + 1):
        conjs.append(ir.If(
            ir.eq(ir.V("committed_%d" % i), ir.C(True)),
            ir.eq(ir.V("quorum_%d" % i), ir.C(True)),
            ir.T()))
    return Invariant(
        name="pbft_quorum",
        description="PBFT: nodes commit a sequence only on a quorum certificate",
        expression=ir.And(*conjs) if conjs else ir.T(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
    )


def pbft_prepare_before_commit(n=3):
    """PBFT: a node commits a sequence only if it has prepared it.

    For every node ``i``: ``committed(i) => prepared(i)``.
    Holds in both variants (the seeded bug is *premature* commit --
    committing without a quorum certificate -- not committing-before-preparing).
    """
    conjs = []
    for i in range(1, n + 1):
        conjs.append(ir.If(
            ir.eq(ir.V("committed_%d" % i), ir.C(True)),
            ir.eq(ir.V("prepared_%d" % i), ir.C(True)),
            ir.T()))
    return Invariant(
        name="pbft_prepare_before_commit",
        description="PBFT: nodes commit a sequence only after preparing it",
        expression=ir.And(*conjs) if conjs else ir.T(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=False,  # holds in both variants; informational, not a blocking gate
        rung=RUNG_LOCAL,  # per-node (actor-local) property: never blocks
    )


def no_double_charge(n=1):
    """Payment (client + payment services): an order is never charged twice.

    Cross-service property over the *composed* IR: the client's order state
    and the payment service's charge counter must jointly guarantee
    ``charges <= 1`` (idempotent charging).  This is the discriminator
    between the correct and buggy payment variants, and -- because it spans
    two services -- it lives on the :data:`RUNG_E2E` rung: it may carry a
    blocking label and pinning, and a violation may block the merge request.
    """
    return Invariant(
        name="no_double_charge",
        description="payment: an order is never charged more than once "
                    "(idempotent charging across client + payment services)",
        expression=payment.no_double_charge_property(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_E2E,  # cross-service (composition plane) property
    )


def charge_requires_order(n=1):
    """Payment (client + payment services): the payment service never charges
    an order the client never placed (``charges >= 1 => ordered``).

    Cross-service, but holds in both variants (the seeded bug is a re-issued
    charge on a *placed* order, not a charge with no order) -- a
    discriminator property that must not be a vacuous PASS.
    """
    return Invariant(
        name="charge_requires_order",
        description="payment: the payment service never charges an order the "
                    "client never placed",
        expression=payment.charge_requires_order_property(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=False,  # holds in both variants; informational, not a blocking gate
        rung=RUNG_E2E,  # cross-service (composition plane) property
    )


def settle_requires_charge(n=1):
    """Payment: a payment is settled only after it has been charged
    (``settled => charges >= 1``).

    Involves only the payment service's own state, so it is an actor-local
    (single-service) property on the :data:`RUNG_LOCAL` rung: even when
    pinned, the assurance ladder caps its gate permission at WARN.
    """
    return Invariant(
        name="settle_requires_charge",
        description="payment: a payment is settled only after it has been charged",
        expression=payment.settle_requires_charge_property(),
        kind="safety",
        label=LABEL_BOUNDED,
        pinned=False,  # holds in both variants; informational, not a blocking gate
        rung=RUNG_LOCAL,  # payment-service-local property: never blocks
    )


def no_unapproved_irreversible(n=1):
    """``NoUnapprovedIrreversible`` -- the keystone governance rule (G4).

    An irreversible action is executed only if it was approved
    (``Executed(a) => Approved(a)``).  The correct approval state machine
    (``approval-correct``) proves it; the buggy harness (``approval-buggy``)
    executes without a valid approval and is refuted (witness = the
    executed-without-approval state).

    Single/multi-actor governance property on the :data:`RUNG_E2E` rung (the
    end-to-end system plane): pinned, :data:`LABEL_BOUNDED`, a blocking gate.
    """
    return Invariant(
        name="no_unapproved_irreversible",
        description="approval: an irreversible action is executed only if it "
                    "was approved (Executed(a) => Approved(a))",
        expression=approval.no_unapproved_irreversible_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_E2E,
        policy_clause="approval: an irreversible action may only be executed "
                      "once an approval token is in force",
    )


def no_privilege_escalation(n=1):
    """No privilege escalation through delegation (G4).

    A delegatee never executes an action the delegator was not entitled to
    (``NOT executed OR delegator_perm``).  The correct delegation harness
    (``delegation-correct``) proves it; the buggy harness (``delegation-buggy``)
    delegates regardless of the delegator's own entitlement and is refuted
    (witness = the delegatee executing a permission the delegator never held).

    :data:`RUNG_E2E` rung: pinned, :data:`LABEL_BOUNDED`, a blocking gate.
    """
    return Invariant(
        name="no_privilege_escalation",
        description="delegation: a delegatee never executes an action the "
                    "delegator was not entitled to",
        expression=approval.no_privilege_escalation_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_E2E,
        policy_clause="delegation: a delegate may only be granted what the "
                      "delegator itself is entitled to",
    )


def no_deadlock(n=1):
    """No deadlock in multi-agent orchestration (G4).

    The circular-wait state (every agent blocked on another, task still
    pending) is unreachable
    (``NOT (task_pending AND a_waiting AND b_waiting AND approver_waiting)``).
    The correct orchestration (``orchestration-correct``) has an acyclic
    dependency chain and proves it; the buggy orchestration
    (``orchestration-buggy``) closes the cycle and is refuted (witness = the
    circular-wait state).

    :data:`RUNG_E2E` rung: pinned, :data:`LABEL_BOUNDED`, a blocking gate.
    """
    return Invariant(
        name="no_deadlock",
        description="orchestration: the multi-agent circular-wait state is "
                    "unreachable (no deadlock)",
        expression=approval.no_deadlock_property(),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        rung=RUNG_E2E,
        policy_clause="orchestration: the agent dependency graph must stay "
                      "acyclic (no circular wait)",
        violation_code=DEADLOCK,
    )


def task_ends_or_escalates(n=1):
    """``TaskEndsOrEscalates`` -- the liveness rule (G4, the thesis rule).

    A shared multi-agent task either completes (``done``) or is escalated to a
    human (``escalated``).  This is a *goal* (liveness) invariant: its
    ``expression`` is a goal predicate, not a universal safety predicate, so it
    is evaluated by ``SymbolicEngine.reach_within`` over the linear model
    (REACHED -> PROVEN, NOT_REACHED -> VIOLATED).  The ``escalate`` escape
    hatch makes it hold even in the deadlock-prone orchestration: a task that
    would deadlock can still be escalated, so the task always ends or escalates.

    :data:`RUNG_E2E` rung: pinned, :data:`LABEL_EVENTUALLY` (bounded-eventually).
    """
    return Invariant(
        name="task_ends_or_escalates",
        description="orchestration: a shared multi-agent task either completes "
                    "or is escalated to a human (the liveness escape hatch) -- "
                    "evaluated by SymbolicEngine.reach_within, not a universal "
                    "safety check",
        expression=approval.task_ends_or_escalates_property(),
        kind=KIND_LIVENESS,
        label=LABEL_EVENTUALLY,
        pinned=True,
        rung=RUNG_E2E,
        policy_clause="orchestration: every task must terminate (done) or "
                      "escalate to a human",
    )


def no_runaway_budget(n=1, cap=approval.CAP):
    """No runaway budget across agents (G4).

    The shared total spend of all agents stays within the shared cap
    (``spent_a + spent_b <= cap``).  The correct budget harness
    (``budget-correct``) charges both agents against the shared total and
    proves it; the buggy harness (``budget-buggy``) accounts each agent's local
    spend only and is refuted (witness = the shared total running past the cap).

    :data:`RUNG_E2E` rung: pinned, :data:`LABEL_BOUNDED` (bounded by ``cap``),
    a blocking gate.
    """
    return Invariant(
        name="no_runaway_budget",
        description="budget: the shared total spend of all agents stays within "
                    "the shared cap (no runaway budget)",
        expression=approval.no_runaway_budget_property(cap),
        kind=KIND_SAFETY,
        label=LABEL_BOUNDED,
        pinned=True,
        bound=cap,
        rung=RUNG_E2E,
        policy_clause="budget: the sum of all agents' spend must not exceed "
                      "the shared cap",
    )


# ---------------------------------------------------------------------------
# G6: over-privileged tool bind (rot.agent_harness)
# ---------------------------------------------------------------------------


# --- register into the shared product registry ---------------------
_inv.register("zab_no_premature_apply", zab_no_premature_apply)
_inv.register("zab_apply_persisted", zab_apply_persisted)
_inv.register("pbft_quorum", pbft_quorum)
_inv.register("pbft_prepare_before_commit", pbft_prepare_before_commit)
_inv.register("no_double_charge", no_double_charge)
_inv.register("charge_requires_order", charge_requires_order)
_inv.register("settle_requires_charge", settle_requires_charge)
_inv.register("no_unapproved_irreversible", no_unapproved_irreversible)
_inv.register("no_privilege_escalation", no_privilege_escalation)
_inv.register("no_deadlock", no_deadlock)
_inv.register("task_ends_or_escalates", task_ends_or_escalates)
_inv.register("no_runaway_budget", no_runaway_budget)
__all__ = ['zab_no_premature_apply', 'zab_apply_persisted', 'pbft_quorum', 'pbft_prepare_before_commit', 'no_double_charge', 'charge_requires_order', 'settle_requires_charge', 'no_unapproved_irreversible', 'no_privilege_escalation', 'no_deadlock', 'task_ends_or_escalates', 'no_runaway_budget']
