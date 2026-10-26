# -*- coding: utf-8 -*-
"""env.py -- composable environment (asynchrony) fragments as IR (WP2).

The Oracle (R3) requires the tool to model the *environment* asynchrony a
service actually lives in -- at-least-once queues, lossy/reordering TCP, and
crash-recoverable disks -- not just the happy-path state machine. This module
is that library: each environment is a small, self-contained ``ProtocolIR``
fragment with

* a **correct** variant whose pinned property the bounded model finder
  (``rot.modelfind.ModelFinder``) proves holds over *all reachable* states, and
* a **buggy** variant (the environment's failure mode) for which the property
  is *reachable and violated*.

The four fragments exercise four *different* environment guarantees:

* :func:`at_least_once_queue`  -- no message loss (a message is delivered at
  least once; the ``lost`` state is unreachable in the correct variant).
* :func:`tcp_channel`          -- in-order delivery (B is delivered only after
  A; the out-of-order state is unreachable in the correct variant).
* :func:`crash_recover_disk`   -- durability (a committed write survives a
  crash; the ``lost`` state is unreachable in the correct variant).
* :func:`idempotent_payment`   -- no double charge (a charge is applied at most
  once; the ``double_charged`` state is unreachable in the correct variant).

Fragments are composable via :func:`compose` (union of variables + actions,
conjunction of init and the pinned property) so an application can be verified
*against* the environment it depends on.

Everything here is authored purely in ``rot.ir`` vocabulary (``StateVar`` /
``Action`` / ``Expr``) -- exactly what the frontends emit -- so it flows through
the same emitters / model finder as real targets.

Pure stdlib, Python 3.6 compatible.
"""

from .ir import (
    ProtocolIR, StateVar, Action, Assignment, Enum, Bool, IntRange,
    And, Or, Not, V, C, eq, neq, MODE_PRECISE, RUNG_ENV,
)

__all__ = [
    "at_least_once_queue", "tcp_channel", "crash_recover_disk",
    "idempotent_payment", "compose",
    "QUEUE_NO_LOSS", "TCP_IN_ORDER", "DISK_DURABILITY", "NO_DOUBLE_CHARGE",
]


def _ir(name, variables, actions, init, prop, metadata=None):
    return ProtocolIR(name=name, variables=variables, actions=actions,
                      init=init, pinned_property=prop,
                      metadata=(metadata or {}))


# ---------------------------------------------------------------------------
# at-least-once queue  (no message loss)
# ---------------------------------------------------------------------------
QUEUE_NO_LOSS = "queue_no_loss"


def at_least_once_queue(buggy=False):
    """A single-message at-least-once queue (no message loss).

    Correct: a message that enters the queue is delivered (at least once) and
    is never lost -- the ``lost`` state is unreachable, so the invariant
    ``msg != lost`` holds in every reachable state.

    Buggy: a ``queue_drop`` loses the in-flight message, making ``lost``
    reachable -- the at-least-once (no-loss) invariant is violated.
    """
    msg = StateVar("msg", Enum(["none", "inflight", "delivered", "lost"]),
                   mode=MODE_PRECISE, owner="queue",
                   desc="state of the single tracked message")

    actions = [
        Action("queue_init", "queue", C(True), [
            Assignment("msg", C("none")),
        ], is_initial=True),
        Action("queue_enq", "queue", eq(V("msg"), C("none")), [
            Assignment("msg", C("inflight")),
        ], linearization="enq", env_free=True, is_env=True, rung=RUNG_ENV),
        Action("queue_deliver", "queue", eq(V("msg"), C("inflight")), [
            Assignment("msg", C("delivered")),
        ], linearization="deliver", env_free=True, is_env=True, rung=RUNG_ENV),
    ]
    if buggy:
        actions.append(
            Action("queue_drop", "queue", eq(V("msg"), C("inflight")), [
                Assignment("msg", C("lost")),
            ], linearization="drop", env_free=True, is_env=True, rung=RUNG_ENV))

    invariant = neq(V("msg"), C("lost"))
    return _ir("at_least_once_queue_buggy" if buggy else "at_least_once_queue",
               [msg], actions,
               eq(V("msg"), C("none")),
               invariant,
               metadata={"property_name": QUEUE_NO_LOSS, "buggy": bool(buggy)})
# ---------------------------------------------------------------------------
# TCP channel  (in-order delivery)
# ---------------------------------------------------------------------------
TCP_IN_ORDER = "tcp_in_order"


def tcp_channel(buggy=False):
    """A two-message TCP channel (in-order delivery).

    Messages A and B are both in flight; A was sent first. In-order delivery
    means B is delivered only after A.

    Correct: ``tcp_deliver_b`` is guarded on A being delivered, so the state
    "B delivered while A not" is unreachable and the invariant
    ``b_delivered -> a_delivered`` holds in every reachable state.

    Buggy: ``tcp_reorder_b`` delivers B first, making the out-of-order state
    reachable -- the in-order invariant is violated.
    """
    a = StateVar("a_delivered", Bool(), mode=MODE_PRECISE, owner="channel",
                 desc="has message A been delivered?")
    b = StateVar("b_delivered", Bool(), mode=MODE_PRECISE, owner="channel",
                 desc="has message B been delivered?")

    actions = [
        Action("tcp_init", "channel", C(True), [
            Assignment("a_delivered", C(False)),
            Assignment("b_delivered", C(False)),
        ], is_initial=True),
        Action("tcp_deliver_a", "channel", eq(V("a_delivered"), C(False)), [
            Assignment("a_delivered", C(True)),
        ], linearization="deliver_a", env_free=True, is_env=True, rung=RUNG_ENV),
        Action("tcp_deliver_b", "channel",
               And(eq(V("a_delivered"), C(True)), eq(V("b_delivered"), C(False))), [
                   Assignment("b_delivered", C(True)),
               ], linearization="deliver_b", env_free=True, is_env=True, rung=RUNG_ENV),
    ]
    if buggy:
        actions.append(
            Action("tcp_reorder_b", "channel",
                   eq(V("b_delivered"), C(False)), [
                       Assignment("b_delivered", C(True)),
                   ], linearization="reorder_b", env_free=True, is_env=True, rung=RUNG_ENV))

    # invariant: B delivered implies A was delivered first (in-order)
    invariant = Or(eq(V("a_delivered"), C(True)), eq(V("b_delivered"), C(False)))
    return _ir("tcp_channel_buggy" if buggy else "tcp_channel",
               [a, b], actions,
               And(eq(V("a_delivered"), C(False)), eq(V("b_delivered"), C(False))),
               invariant,
               metadata={"property_name": TCP_IN_ORDER, "buggy": bool(buggy)})


# ---------------------------------------------------------------------------
# crash-recoverable disk  (durability)
# ---------------------------------------------------------------------------
DISK_DURABILITY = "disk_durability"


def crash_recover_disk(buggy=False):
    """A write whose durability depends on a commit before crash.

    Correct: once the write is ``committed`` it is durable, so a crash leaves
    it ``recovered`` -- the ``lost`` state is unreachable and the invariant
    ``disk_state != lost`` holds in every reachable state.

    Buggy: a crash lands before the write is committed/durable, so the
    ``lost`` state is reachable -- the durability invariant is violated.
    """
    st = StateVar("disk_state",
                  Enum(["idle", "writing", "committed", "recovered", "lost"]),
                  mode=MODE_PRECISE, owner="disk", desc="durability phase of the write")

    actions = [
        Action("disk_init", "disk", C(True), [
            Assignment("disk_state", C("idle")),
        ], is_initial=True),
        Action("disk_write", "disk", eq(V("disk_state"), C("idle")), [
            Assignment("disk_state", C("writing")),
        ], linearization="write", env_free=True, is_env=True, rung=RUNG_ENV),
        Action("disk_commit", "disk", eq(V("disk_state"), C("writing")), [
            Assignment("disk_state", C("committed")),
        ], linearization="commit", env_free=True, is_env=True, rung=RUNG_ENV),
        Action("disk_recover", "disk", eq(V("disk_state"), C("committed")), [
            Assignment("disk_state", C("recovered")),
        ], linearization="recover", env_free=True, is_env=True, rung=RUNG_ENV),
    ]
    if buggy:
        actions.append(
            Action("disk_crash_before_commit", "disk",
                   eq(V("disk_state"), C("writing")), [
                       Assignment("disk_state", C("lost")),
                   ], linearization="crash", env_free=True, is_env=True, rung=RUNG_ENV))

    invariant = neq(V("disk_state"), C("lost"))
    return _ir("crash_recover_disk_buggy" if buggy else "crash_recover_disk",
               [st], actions,
               eq(V("disk_state"), C("idle")),
               invariant,
               metadata={"property_name": DISK_DURABILITY, "buggy": bool(buggy)})


# ---------------------------------------------------------------------------
# idempotent payment  (no double charge)
# ---------------------------------------------------------------------------
NO_DOUBLE_CHARGE = "no_double_charge"


def idempotent_payment(buggy=False):
    """A payment gateway that charges an order at most once (idempotent).

    Correct: a ``charge`` request is applied once and a re-issued request for
    the same order is a no-op -- the ``double_charged`` state is unreachable,
    so the invariant ``charges != double_charged`` holds in every reachable
    state.

    Buggy: the gateway re-applies the charge on a re-issued request, making
    ``double_charged`` reachable -- the idempotency (no double charge)
    invariant is violated.

    Note: this is the environment-side fragment.  The application-side
    counterpart of the same property is ``no_double_charge_property()`` in
    :mod:`rot.payment`; it is re-declared here inline (rather than imported)
    so the environment library stays free of any application-layer dependency.
    """
    charges = StateVar("charges",
                       Enum(["unpaid", "charged", "double_charged"]),
                       mode=MODE_PRECISE, owner="payment",
                       desc="charge state of the order")

    actions = [
        Action("payment_init", "payment", C(True), [
            Assignment("charges", C("unpaid")),
        ], is_initial=True),
        Action("payment_charge", "payment", eq(V("charges"), C("unpaid")), [
            Assignment("charges", C("charged")),
        ], linearization="charge", env_free=True, is_env=True, rung=RUNG_ENV),
    ]
    if buggy:
        actions.append(
            Action("payment_recharge", "payment",
                   eq(V("charges"), C("charged")), [
                      Assignment("charges", C("double_charged")),
                   ], linearization="recharge", env_free=True, is_env=True,
                   rung=RUNG_ENV))

    invariant = neq(V("charges"), C("double_charged"))
    return _ir("idempotent_payment_buggy" if buggy else "idempotent_payment",
               [charges], actions,
               eq(V("charges"), C("unpaid")),
               invariant,
               metadata={"property_name": NO_DOUBLE_CHARGE, "buggy": bool(buggy)})



# ---------------------------------------------------------------------------
# composition
# ---------------------------------------------------------------------------
def compose(base, env, keep_env_property=True):
    """Merge an application IR ``base`` with an environment fragment ``env``.

    Variables and actions are unioned (on a name clash the *env* definition
    wins, since the environment owns its state); ``init`` and
    ``pinned_property`` are conjoined (unless ``keep_env_property`` is False).
    This is the "verify the application *against* the environment" composition.
    """
    vars_by_name = {v.name: v for v in base.variables}
    for v in env.variables:
        vars_by_name[v.name] = v            # env owns its state
    actions = list(base.actions) + [a for a in env.actions]
    init = And(base.init, env.init)
    prop = And(base.pinned_property, env.pinned_property) if keep_env_property \
        else base.pinned_property
    return ProtocolIR(name=base.name + "+" + env.name,
                      variables=list(vars_by_name.values()),
                      actions=actions, init=init, pinned_property=prop,
                      metadata=dict(base.metadata))

