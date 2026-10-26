# -*- coding: utf-8 -*-
"""order_service.py -- order + billing services as a composition-plane demo.

A second, independent example of the Phase 2 *composition plane*: two
independently modelled services (an **order** service and a **billing**
service) merged into one concurrent IR, verified against cross-service
invariants.

It deliberately reuses the same shape as ``rot.payment`` -- a state machine
with a guarded, idempotent transition -- so it exercises the same machinery,
but with different state, different action names, and a different seeded bug:
the billing service charges as soon as the order is *placed* (before it is
*confirmed*), and the charge is re-issuable, so the order can be charged more
than once.

The correct implementation charges exactly once, only after the order has been
confirmed, and never again.  The buggy implementation drops both the
confirmation guard and the idempotency guard, so a re-issued charge
double-charges the order.  The pinned property ``order_no_double_charge``
therefore *holds* on the correct variant and *breaks* on the buggy variant --
the discriminator the MR gate uses.

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir
import rot.composition as composition


# ---------------------------------------------------------------------------
# Per-service IRs
# ---------------------------------------------------------------------------
def build_order_ir():
    """Order service (owner "order"): a placed/confirmed order lifecycle.

    State:
      ``placed``    -- the order has been placed.
      ``confirmed`` -- the order has been confirmed (ready to bill).
    Actions:
      ``order_init``    -- placed=false, confirmed=false (the initial state).
      ``order_place``   -- placed=true (from the not-yet-placed state).
      ``order_confirm`` -- confirmed=true, once the order has been placed.
    """
    variables = [
        ir.StateVar(name="placed", domain=ir.Bool(), owner="order",
                    desc="order has been placed"),
        ir.StateVar(name="confirmed", domain=ir.Bool(), owner="order",
                    desc="order has been confirmed"),
    ]
    actions = [
        ir.Action(name="order_init", owner="order",
                  guard=ir.T(),
                  effects=[ir.Assignment("placed", ir.F()),
                           ir.Assignment("confirmed", ir.F())],
                  is_initial=True),
        ir.Action(name="order_place", owner="order",
                  guard=ir.Not(ir.V("placed")),
                  effects=[ir.Assignment("placed", ir.T())]),
        ir.Action(name="order_confirm", owner="order",
                  guard=ir.And(ir.V("placed"), ir.Not(ir.V("confirmed"))),
                  effects=[ir.Assignment("confirmed", ir.T())]),
    ]
    return ir.ProtocolIR(
        name="order",
        variables=variables,
        actions=actions,
    )

def build_billing_ir(buggy=False):
    """Billing service (owner "billing"): charges the order exactly once.

    State:
      ``charges`` -- how many times this order has been charged (0, 1 or 2).

    Correct:
      ``billing_charge`` -- charges the order, but only once and only after it
      has been confirmed (idempotent: a re-issue is a no-op).

    Buggy:
      ``billing_charge`` -- charges as soon as the order has been placed
      (before confirmation), and a re-issue charges again (no idempotency
      guard), so the order can be charged more than once.
    """
    variables = [
        ir.StateVar(name="charges", domain=ir.IntRange(0, 2), owner="billing",
                    desc="how many times this order has been charged"),
    ]
    if buggy:
        charge = ir.Action(
            name="billing_charge", owner="billing",
            guard=ir.V("placed"),  # charges as soon as the order is placed
            effects=[ir.Assignment(
                "charges",
                # saturate at 2 so the concrete state space stays finite:
                # charges reaches 2  <=>  double-charged.
                ir.If(ir.BinOp(">=", ir.V("charges"), ir.C(2)),
                      ir.C(2),
                      ir.BinOp("+", ir.V("charges"), ir.C(1))))])
    else:
        charge = ir.Action(
            name="billing_charge", owner="billing",
            guard=ir.And(ir.V("confirmed"), ir.eq(ir.V("charges"), ir.C(0))),
            effects=[ir.Assignment("charges", ir.C(1))])
    actions = [
        ir.Action(name="billing_init", owner="billing",
                  guard=ir.T(),
                  effects=[ir.Assignment("charges", ir.C(0))],
                  is_initial=True),
        charge,
    ]
    return ir.ProtocolIR(
        name="billing",
        variables=variables,
        actions=actions,
    )


# ---------------------------------------------------------------------------
# Composition (the Phase 2 demo: two services, one concurrent IR)
# ---------------------------------------------------------------------------
def build_ir(n=1, buggy=False):
    """Compose the order and billing services into one concurrent IR.

    ``n`` is accepted for target-registry signature parity (this demo models a
    single order, so it is otherwise unused).
    """
    int_ = int(n)
    return composition.compose(
        name="order_service",
        services=[build_order_ir(), build_billing_ir(buggy=bool(buggy))],
        metadata={"buggy": bool(buggy), "n": int_},
    )


# ---------------------------------------------------------------------------
# Properties (raw IR predicates; rot.invariants wraps these as Invariants)
# ---------------------------------------------------------------------------
def no_double_charge_property():
    """An order is never charged more than once (idempotent billing).

    This is the discriminator: it holds on the correct variant and is
    reachable-and-violated on the buggy variant (a double charge).
    """
    return ir.BinOp("<=", ir.V("charges"), ir.C(1))


def charge_requires_place_property():
    """The billing service never charges an order that was never placed.

    Holds in *both* variants (the seeded bug is *when* and *how many times*
    the billing service charges, not that it charges an unplaced order), so
    the gate must not report it as broken by the bug -- a genuine invariant.
    """
    return ir.If(ir.BinOp(">=", ir.V("charges"), ir.C(1)), ir.V("placed"), ir.T())


def confirm_requires_place_property():
    """An order is confirmed only after it has been placed (order-local).

    An order-service-local property: it depends only on the order service's
    own state and holds in both variants, so it is a genuine (RUNG_LOCAL)
    invariant the gate must not report as broken by the seeded bug.
    """
    return ir.If(ir.V("confirmed"), ir.V("placed"), ir.T())


__all__ = [
    "build_order_ir", "build_billing_ir", "build_ir",
    "no_double_charge_property", "charge_requires_place_property",
    "confirm_requires_place_property",
]

