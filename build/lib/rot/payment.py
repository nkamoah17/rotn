# -*- coding: utf-8 -*-
"""payment.py -- a two-service payment protocol (client + payment).

The Phase 2 composition demo: two independently modelled services that share
order state and must be verified together.

  client service (owner "client"):
      ordered    -- the client has placed an order
      cancelled  -- the client has cancelled the order
      actions:    order, cancel

  payment service (owner "payment"):
      charges    -- how many times the order has been charged
      settled    -- the payment has been settled
      actions:    charge, settle

The two variants share the same services, the same state, the same actions,
and the same pinned property; they differ only in the decision rule of the
payment service's ``charge`` action:

  * correct -- charge is idempotent (guarded on ``charges == 0``): once
    charged, the order can never be charged again (``no_double_charge``);
  * buggy   -- charge ignores the idempotency guard (``charges`` increments
    on every firing, saturated at 2 so the concrete state space stays finite):
    a re-issued charge request double-charges the order.

:func:`build_ir` merges the two service IRs with
:func:`rot.composition.compose` into one concurrent IR; the cross-service
invariants (registered in :mod:`rot.invariants`: ``no_double_charge``,
``charge_requires_order``, ``settle_requires_charge``) are then pinned
against the composed IR and checked by the usual pipeline.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir
import rot.composition as composition

__all__ = [
    "build_client_ir",
    "build_payment_ir",
    "build_ir",
    "no_double_charge_property",
    "charge_requires_order_property",
    "settle_requires_charge_property",
]


def build_client_ir():
    """The client service: places and cancels an order."""
    variables = [
        ir.StateVar("ordered", ir.Bool(), ir.MODE_PRECISE, "client",
                    "the client has placed an order"),
        ir.StateVar("cancelled", ir.Bool(), ir.MODE_PRECISE, "client",
                    "the client has cancelled the order"),
    ]
    actions = [
        ir.Action(name="init", owner="client", guard=ir.T(),
                  effects=[ir.Assignment("ordered", ir.F()),
                           ir.Assignment("cancelled", ir.F())],
                  is_initial=True),
        ir.Action(name="order", owner="client", guard=ir.T(),
                  effects=[ir.Assignment("ordered", ir.T())],
                  linearization='send(charge)'),
        ir.Action(name="cancel", owner="client",
                  guard=ir.And(ir.V("ordered"), ir.Not(ir.V("cancelled"))),
                  effects=[ir.Assignment("cancelled", ir.T())],
                  linearization='send(settle)'),
    ]
    return ir.ProtocolIR(
        name="client",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
    )


def build_payment_ir(buggy=False):
    """The payment service: charges (idempotently) and settles an order.

    ``buggy=False`` (correct): ``charge`` fires only while ``charges == 0``
    and sets ``charges = 1`` -- charging is idempotent.

    ``buggy=True`` (the seeded regression): ``charge`` fires whenever the
    order exists and increments ``charges`` -- a re-issued charge request
    double-charges the order.
    """
    variables = [
        ir.StateVar("charges", ir.IntRange(0, 2), ir.MODE_PRECISE, "payment",
                    "how many times the order has been charged (capped at 2)"),
        ir.StateVar("settled", ir.Bool(), ir.MODE_PRECISE, "payment",
                    "the payment has been settled"),
    ]
    if buggy:
        # charge fires whenever the order exists and increments ``charges`` --
        # a re-issued charge request double-charges the order.  The counter is
        # *saturated* at 2: the concrete engine does not enforce variable
        # domains, so an unguarded ``charges = charges + 1`` would make the
        # state space infinite and exhaust the witness-search budget on
        # invariants that *hold* (e.g. ``charge_requires_order``).  Capping at
        # 2 keeps the space finite while preserving the exact discriminator
        # the invariants need: charges reaches 2  <=>  double-charged.
        charge_guard = ir.V("ordered")
        charge_effects = [
            ir.Assignment(
                "charges",
                ir.If(ir.BinOp(">=", ir.V("charges"), ir.C(2)),
                      ir.C(2),
                      ir.BinOp("+", ir.V("charges"), ir.C(1))))
        ]
    else:
        charge_guard = ir.And(ir.V("ordered"), ir.eq(ir.V("charges"), ir.C(0)))
        charge_effects = [ir.Assignment("charges", ir.C(1))]

    actions = [
        ir.Action(name="init", owner="payment", guard=ir.T(),
                  effects=[ir.Assignment("charges", ir.C(0)),
                           ir.Assignment("settled", ir.F())],
                  is_initial=True),
        ir.Action(name="charge", owner="payment", guard=charge_guard,
                  effects=charge_effects,
                  linearization='send(charge)'),
        ir.Action(name="settle", owner="payment",
                  guard=ir.And(ir.eq(ir.V("charges"), ir.C(1)),
                               ir.Not(ir.V("settled"))),
                  effects=[ir.Assignment("settled", ir.T())],
                  linearization='send(settle)'),
    ]
    return ir.ProtocolIR(
        name="payment",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
    )


def build_ir(n=1, buggy=False):
    """Build the composed client+payment IR (the Phase 2 target).

    Parameters mirror the other targets in :mod:`rot.targets` (``n`` is
    accepted for interface uniformity and ignored; this protocol has a fixed
    single order).
    """
    return composition.compose(
        "payment",
        [build_client_ir(), build_payment_ir(buggy=buggy)],
        metadata={"protocol": "PAYMENT", "phase": "composition"},
    )


# ---------------------------------------------------------------------------
# Cross-service properties (used to build the Invariants in rot.invariants)
# ---------------------------------------------------------------------------
def no_double_charge_property():
    """Cross-service: an order is never charged more than once.

    ``charges <= 1`` -- the client's order state and the payment's charge
    counter must jointly guarantee idempotent charging.  Broken by the buggy
    payment service (``charges`` reaches 2).
    """
    return ir.BinOp("<=", ir.V("charges"), ir.C(1))


def charge_requires_order_property():
    """Cross-service: the payment service never charges an order that the
    client never placed (``charges >= 1  ==>  ordered``).

    Holds in both variants: a discriminator property (it must not be a
    vacuous PASS).
    """
    return ir.If(ir.BinOp(">=", ir.V("charges"), ir.C(1)), ir.V("ordered"), ir.T())


def settle_requires_charge_property():
    """Payment-local: a payment is settled only after it has been charged
    (``settled  ==>  charges >= 1``).

    Involves only the payment service's state -- hence a RUNG_LOCAL
    invariant, which the assurance ladder caps at WARN.
    """
    return ir.If(ir.V("settled"), ir.BinOp(">=", ir.V("charges"), ir.C(1)), ir.T())