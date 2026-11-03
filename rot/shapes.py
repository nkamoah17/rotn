# -*- coding: utf-8 -*-
"""shapes.py -- hand-written oracle models for the non-spendcap safe-range
temporal shapes lowered by :mod:`rot.lower`.

Phase B1 extends the spend-cap class to the full safe-range temporal class
present in the AWS Dogwood corpus.  Each shape below is the *hand-written
model* (the oracle) that the ``.dw`` derivation in :mod:`rot.lower` must
reproduce structurally -- the same discipline the spend-cap shape has with
:mod:`rot.spendcap`:

  * **count-window** (``Count - Count < cap``) -- the
    ``cap_open_agent_prs_windowed`` shape.
  * **exists-sum** (``exists total. (sum == total && total <op> cap)``) --
    the corpus ``0299`` / ``0301`` filtered-sum shape.
  * **refund-budget** (``(Sum + context.*) <op> cap``) -- the
    ``refund_budget_settled_plus_current`` shape.
  * **taint-egress** (``formerly within <window> <event>``) -- the
    thesis's "never contact outsiders after touching confidential data"
    shape (temporal + data-dependent).

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir

__all__ = [
    "build_count_window_ir",
    "build_exists_sum_ir",
    "build_refund_budget_ir",
    "build_taint_egress_ir",
    "build_approval_replay_ir",
    "build_distinct_count_ir",
    "build_scoped_cap_ir",
    "build_event_ordering_ir",
    "build_window_boundary_ir",
]



# ---------------------------------------------------------------------------
# Shape 2: count-window (``Count - Count < cap``)
# ---------------------------------------------------------------------------

def build_count_window_ir(cap, open_action="open", close_action="close",
                          open_kind="response", close_kind="response"):
    """Hand-written oracle for the count-window shape.

    ``cap_open_agent_prs_windowed`` shape: a cap on concurrently open PRs,
    measured as opens minus completed reviews in a time window.

    The IR models the net open count (opens minus completed reviews in the
    window) as a single state variable ``open``.  The ``open_pr`` action is
    the service decision (allow the open while ``open < cap``);
    ``complete_review`` is the environment transition that decrements it.
    The pinned property is the cap condition ``open < cap``.

    Parameters
    ----------
    cap : int
        The maximum number of concurrently open PRs (must be >= 1).
    open_action : str
        The policy action name for the open event.
    close_action : str
        The policy action name for the close/complete event.
    open_kind : str
        The event kind of the open event.
    close_kind : str
        The event kind of the close event.

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with one state variable, four actions,
        and the pinned property ``open < cap``.
    """
    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))

    variables = [
        ir.StateVar("open", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "net open count (opens minus completed reviews in window)"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("open", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="open_pr", owner="service",
                  guard=ir.BinOp("<", ir.V("open"), ir.C(cap)),
                  effects=[ir.Assignment("open",
                                         ir.BinOp("+", ir.V("open"), ir.C(1)))],
                  linearization="send(open_pr)",
                  source="lower.py:open_pr"),
        ir.Action(name="deny_open", owner="service",
                  guard=ir.BinOp(">=", ir.V("open"), ir.C(cap)),
                  effects=[],
                  source="lower.py:deny_open"),
        ir.Action(name="complete_review", owner="service",
                  guard=ir.BinOp(">=", ir.V("open"), ir.C(1)),
                  effects=[ir.Assignment("open",
                                         ir.BinOp("-", ir.V("open"), ir.C(1)))],
                  linearization="send(complete_review)",
                  source="lower.py:complete_review"),
    ]
    pinned = ir.BinOp("<", ir.V("open"), ir.C(cap))

    return ir.ProtocolIR(
        name="count-window",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "COUNT_WINDOW", "target": "count_window",
                  "cap": cap,
                  "open_event": "%s::%s" % (open_action, open_kind),
                  "close_event": "%s::%s" % (close_action, close_kind)},
    )



# ---------------------------------------------------------------------------
# Shape 3: exists-sum (``exists total. (sum == total && total <op> cap)``)
# ---------------------------------------------------------------------------

def build_exists_sum_ir(cap, op="<=", kind="response", max_inflight=4):
    """Hand-written oracle for the exists-sum shape.

    The exists-sum shape (``exists total. (sum == total && total <op> cap)``)
    is the *same protocol* as the spend-cap shape, expressed with an explicit
    ``total`` binding over the windowed sum.  The event kind the sum
    quantifies over drives the decision rule -- the SAFE / UNSAFE distinction:

    * **request-sum** (SAFE): the sum includes in-flight requests.
      The policy charges in-flight against the cap.
    * **response-sum** (UNSAFE): the sum covers settled responses only, so
      in-flight requests are invisible to the guard.

    Parameters
    ----------
    cap : int
        The cap on the windowed sum (must be >= 1).
    op : str
        The comparison operator.
    kind : str
        The event kind (``"request"`` for SAFE, ``"response"`` for UNSAFE).
    max_inflight : int
        The client-side request-pool bound K (must be >= 1).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, four actions,
        and the pinned property ``completed + inflight * amount <= cap``.
    """
    import rot.spendcap as spendcap

    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))
    k = int(max_inflight)
    if k < 1:
        raise ValueError("max_inflight must be an integer >= 1 (got %r)"
                         % (max_inflight,))

    amount = max(1, cap // 2)

    if kind == "request":
        decision = spendcap.spend_ok_guard_correct(amount, cap)
        buggy = False
    else:
        decision = spendcap.spend_ok_guard_buggy(amount, cap)
        buggy = True

    spend_ok_guard = ir.And(decision, ir.BinOp("<", ir.V("inflight"), ir.C(k)))
    spend_deny_guard = ir.Not(decision)

    variables = [
        ir.StateVar("completed", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "settled amount (sum of responded requests)"),
        ir.StateVar("inflight", ir.IntRange(0, k), ir.MODE_PRECISE, "service",
                    "approved-but-unsettled (in-flight) request count"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("completed", ir.C(0)),
                           ir.Assignment("inflight", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="spend_ok", owner="service", guard=spend_ok_guard,
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("+", ir.V("inflight"), ir.C(1)))],
                  linearization="send(spend_ok)",
                  source="lower.py:spend_ok"),
        ir.Action(name="spend_deny", owner="service", guard=spend_deny_guard,
                  effects=[],
                  source="lower.py:spend_deny"),
        ir.Action(name="respond", owner="service",
                  guard=ir.BinOp(">=", ir.V("inflight"), ir.C(1)),
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("-", ir.V("inflight"), ir.C(1))),
                           ir.Assignment("completed",
                                         ir.BinOp("+", ir.V("completed"), ir.C(amount)))],
                  linearization="send(respond)",
                  source="lower.py:respond"),
    ]

    return ir.ProtocolIR(
        name="exists-sum",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=spendcap.within_cap_property(amount, cap),
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "EXISTS_SUM", "target": "exists_sum",
                  "op": op, "cap": cap, "amount": amount,
                  "max_inflight": k, "buggy": buggy,
                  "dw_event_kind": kind,
                  "event": "%s::%s" % ("Transfer", kind),
                  "context_bound": False},
    )



# ---------------------------------------------------------------------------
# Shape 4: refund-budget (``(Sum + context.*) <op> cap``)
# ---------------------------------------------------------------------------

def build_refund_budget_ir(cap, op="<=", context_ref="context.input.amount"):
    """Hand-written oracle for the refund-budget shape.

    ``refund_budget_settled_plus_current`` shape: a cap on settled refunds
    plus the current request's amount.

    The policy permits a refund while the already-settled amount plus the
    current in-flight amount stay within the cap.  The IR tracks two state
    variables: ``settled`` (accumulated windowed sum of settled refunds,
    clamped at ``cap + 1``) and ``current`` (the in-flight request amount,
    likewise clamped).  The decision is the sum of the two against the cap.

    Parameters
    ----------
    cap : int
        The cap on settled + current (must be >= 1).
    op : str
        The comparison operator (``"<"`` / ``"<="`` / ``">"`` / ``">="``).
    context_ref : str
        The ``context.*`` dotted reference string.

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, five actions,
        and the pinned property ``settled + current <op> cap``.
    """
    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))

    decision = ir.BinOp(op, ir.BinOp("+", ir.V("settled"), ir.V("current")),
                        ir.C(cap))
    op_name = {"<": "lt", "<=": "le", ">": "gt", ">=": "ge"}.get(op, "cmp")

    variables = [
        ir.StateVar("settled", ir.IntRange(0, cap + 1), ir.MODE_PRECISE,
                    "service",
                    "accumulated settled refunds (clamped at cap + 1)"),
        ir.StateVar("current", ir.IntRange(0, cap + 1), ir.MODE_PRECISE,
                    "service",
                    "in-flight refund amount (clamped at cap + 1)"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("settled", ir.C(0)),
                           ir.Assignment("current", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="settle", owner="service",
                  guard=ir.BinOp("<", ir.V("settled"), ir.C(cap + 1)),
                  effects=[ir.Assignment("settled",
                                         ir.BinOp("+", ir.V("settled"), ir.C(1)))],
                  linearization="send(settle)",
                  source="lower.py:settle"),
        ir.Action(name="request", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("current",
                                         ir.BinOp("+", ir.V("current"), ir.C(1)))],
                  linearization="send(request)",
                  source="lower.py:request"),
        ir.Action(name="decision_%s" % op_name, owner="service",
                  guard=decision,
                  effects=[],
                  source="lower.py:decision"),
        ir.Action(name="decision_not_%s" % op_name, owner="service",
                  guard=ir.Not(decision),
                  effects=[],
                  source="lower.py:decision_not"),
    ]

    return ir.ProtocolIR(
        name="refund-budget",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=decision,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "REFUND_BUDGET", "target": "refund_budget",
                  "op": op, "cap": cap,
                  "event": "Transfer::response",
                  "context_ref": context_ref},
    )



# ---------------------------------------------------------------------------
# Shape 5: taint-egress (``formerly within <window> <event>``)
# ---------------------------------------------------------------------------

def build_taint_egress_ir(buggy=False, trigger_action="ReadConfidential",
                          trigger_kind="request",
                          egress_action="Send"):
    """Hand-written oracle for the taint-egress shape.

    The thesis's "never contact outsiders after touching confidential data"
    rule -- a *temporal + data-dependent* policy that the four aggregate
    shapes (spend-cap / count-window / exists-sum / refund-budget) cannot
    express.  The model is the same exfiltration model as
    :func:`rot.agent_harness.exfiltrate_build_ir`:

    * the trigger (touching confidential data) sets ``holding_private``;
    * the egress (contacting an outsider) sets ``exfiltrated`` iff the agent
      is holding private data;
    * the pinned property is ``NOT exfiltrated`` (NoExfiltration).

    The correct / buggy distinction is driven by the event kind of the
    trigger, mirroring the spend-cap shape:

    * **request-trigger** (SAFE): the egress is admitted only when the agent
      is NOT holding private data (the ``NoExfiltration`` rule);
    * **response-trigger** (UNSAFE): the egress is always admitted (the hole:
      private data can reach an unapproved channel while held).

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    trigger_action : str
        The policy action name for the confidential-data event.
    trigger_kind : str
        The event kind of the trigger (``"request"`` for SAFE,
        ``"response"`` for UNSAFE).
    egress_action : str
        The policy action name for the egress (contact-outsider) event.

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, five actions, and
        the pinned property ``NOT exfiltrated``.
    """
    if not buggy:
        egress_guard = ir.Not(ir.V("holding_private"))
        deny_guard = ir.V("holding_private")
    else:
        egress_guard = ir.T()
        deny_guard = ir.F()

    variables = [
        ir.StateVar("holding_private", ir.Bool(), ir.MODE_PRECISE, "service",
                    "the agent currently holds private (confidential) data"),
        ir.StateVar("exfiltrated", ir.Bool(), ir.MODE_PRECISE, "service",
                    "private data has been sent to an unapproved channel"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(False)),
                           ir.Assignment("exfiltrated", ir.C(False))],
                  is_initial=True,
                  source="lower.py:init"),
        # The trigger: the agent touches confidential data (taints its context).
        ir.Action(name="touch_confidential", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(True))],
                  linearization="send(touch_confidential)",
                  source="lower.py:touch_confidential"),
        # The egress (the thing under test): contacting an outsider.  If the
        # agent is holding private data this is an exfiltration.
        ir.Action(name="contact_outsider", owner="service", guard=egress_guard,
                  effects=[ir.Assignment("exfiltrated",
                                         ir.Or(ir.V("exfiltrated"),
                                               ir.V("holding_private")))],
                  linearization="send(contact_outsider)",
                  source="lower.py:contact_outsider"),
        # The other branch of the decision: deny the egress.
        ir.Action(name="contact_deny", owner="service", guard=deny_guard,
                  effects=[],
                  source="lower.py:contact_deny"),
        # The clear: the agent strips private data from its context.
        ir.Action(name="redact", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("holding_private", ir.C(False))],
                  linearization="send(redact)",
                  source="lower.py:redact"),
    ]
    pinned = ir.Not(ir.V("exfiltrated"))

    return ir.ProtocolIR(
        name="taint-egress",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "TAINT_EGRESS", "target": "taint_egress",
                  "buggy": bool(buggy),
                  "dw_event_kind": trigger_kind,
                  "event": "%s::%s" % (trigger_action, trigger_kind),
                  "egress_event": egress_action},
    )



# ---------------------------------------------------------------------------
# APW-2: approval-replay (single-use approval, ``… since within … …``)
# ---------------------------------------------------------------------------

def build_approval_replay_ir(buggy=False,
                             trigger_action="get_cart",
                             gated_action="place_order",
                             max_orders=2):
    """Hand-written oracle for the approval-replay shape.

    A *single-use* approval gates a follow-up action: "you may place an order
    only after a cart check, and the cart check may be used once".  The two
    variants differ in whether the approval is consumed on use:

    * **correct** (single-use): ``place_order`` *consumes* the approval
      (clears ``approved``), so at most one order can be placed per cart
      check; the pinned property ``orders <= 1`` holds.
    * **buggy** (replayable): ``place_order`` does *not* consume the
      approval, so the same cart check can be replayed into an unbounded
      number of orders; the property ``orders <= 1`` is violated (witness
      ``orders >= 2``).

    This is the Dogwood ``!gated::response{…} since within <w>
    trigger::response{…}`` idiom (the ``since`` operator is what makes the
    trigger single-use).

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    trigger_action : str
        The approval / trigger action name (the cart check).
    gated_action : str
        The action gated on the approval (the order).
    max_orders : int
        Upper bound on the ``orders`` counter (must be >= 2 so the replay
        violation is reachable).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, four actions, and
        the pinned property ``orders <= 1``.
    """
    if max_orders < 2:
        raise ValueError("max_orders must be >= 2 (got %r)" % (max_orders,))

    if buggy:
        # Replayable: placing an order does NOT consume the approval.
        place_order_effects = [
            ir.Assignment("orders",
                          ir.BinOp("+", ir.V("orders"), ir.C(1))),
        ]
    else:
        # Single-use: placing an order CONSUMES the approval.
        place_order_effects = [
            ir.Assignment("orders",
                          ir.BinOp("+", ir.V("orders"), ir.C(1))),
            ir.Assignment("approved", ir.C(False)),
        ]

    place_order_guard = ir.V("approved")
    variables = [
        ir.StateVar("approved", ir.Bool(), ir.MODE_PRECISE, "service",
                    "a valid, un-consumed approval (cart check) is present"),
        ir.StateVar("orders", ir.IntRange(0, max_orders), ir.MODE_PRECISE,
                    "service",
                    "orders placed since the last approval"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("approved", ir.C(False)),
                           ir.Assignment("orders", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        # The approval / trigger: a fresh cart check (re-arms the approval and
        # resets the order count).
        ir.Action(name="cart_check", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("approved", ir.C(True)),
                           ir.Assignment("orders", ir.C(0))],
                  linearization="send(cart_check)",
                  source="lower.py:cart_check"),
        # The gated action (the thing under test): place an order.
        ir.Action(name="place_order", owner="service", guard=place_order_guard,
                  effects=place_order_effects,
                  linearization="send(place_order)",
                  source="lower.py:place_order"),
        # The deny branch: no valid approval is present.
        ir.Action(name="order_deny", owner="service",
                  guard=ir.Not(place_order_guard),
                  effects=[],
                  source="lower.py:order_deny"),
    ]
    pinned = ir.BinOp("<=", ir.V("orders"), ir.C(1))

    return ir.ProtocolIR(
        name="approval-replay",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="samples/apw2",
        metadata={"protocol": "APPROVAL_REPLAY", "target": "approval_replay",
                  "buggy": bool(buggy),
                  "trigger_event": "%s::response" % trigger_action,
                  "gated_event": gated_action,
                  "single_use": not buggy},
    )



# ---------------------------------------------------------------------------
# APW-4: distinct-count (a cap on *distinct* values)
# ---------------------------------------------------------------------------

def build_distinct_count_ir(buggy=False, cap=3):
    """Hand-written oracle for the distinct-count shape.

    A cap on the number of *distinct* values observed (e.g. "at most K
    distinct recipients").  The two variants differ in the fidelity of the
    counter the guard actually sees:

    * **correct**: the dedup counter tracks the true distinct count, so the
      guard admits values only while the distinct count is below the cap; the
      pinned property ``distinct <= cap`` holds.
    * **buggy**: the dedup counter is broken (it never advances -- a collapsed
      / reset dedup), so the guard is always satisfied and the true distinct
      count runs past the cap; the property ``distinct <= cap`` is violated.

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    cap : int
        The maximum number of distinct values (must be >= 1).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, three actions, and
        the pinned property ``distinct <= cap``.
    """
    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))
    top = 2 * cap

    admit_guard = ir.BinOp("<", ir.V("counted"), ir.C(cap))
    new_value_effects = [
        ir.Assignment("distinct",
                      ir.BinOp("+", ir.V("distinct"), ir.C(1))),
    ]
    if not buggy:
        # Accurate dedup: the counter tracks the true distinct count.
        new_value_effects.append(
            ir.Assignment("counted",
                          ir.BinOp("+", ir.V("counted"), ir.C(1))))
    # else: broken dedup -- the counter never advances (stays at 0).

    variables = [
        ir.StateVar("distinct", ir.IntRange(0, top), ir.MODE_PRECISE, "service",
                    "the true number of distinct values observed"),
        ir.StateVar("counted", ir.IntRange(0, top), ir.MODE_PRECISE, "service",
                    "the value the policy's dedup counter reports"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("distinct", ir.C(0)),
                           ir.Assignment("counted", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        # A new (or repeated) value arrives; the policy admits it while the
        # counter it sees is below the cap.
        ir.Action(name="new_value", owner="service", guard=admit_guard,
                  effects=new_value_effects,
                  linearization="send(new_value)",
                  source="lower.py:new_value"),
        ir.Action(name="deny", owner="service", guard=ir.Not(admit_guard),
                  effects=[],
                  source="lower.py:deny"),
    ]
    pinned = ir.BinOp("<=", ir.V("distinct"), ir.C(cap))

    return ir.ProtocolIR(
        name="distinct-count",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="samples/apw4",
        metadata={"protocol": "DISTINCT_COUNT", "target": "distinct_count",
                  "buggy": bool(buggy), "cap": cap, "distinct": True,
                  "counter_broken": buggy},
    )



# ---------------------------------------------------------------------------
# APW-5: scoped-cap (a cap scoped to a unit, e.g. a session)
# ---------------------------------------------------------------------------

def build_scoped_cap_ir(buggy=False, cap=3, unit="session"):
    """Hand-written oracle for the scoped-cap shape.

    A cap scoped to a unit (a session / window / user): "at most K events per
    unit".  The two variants differ in how the counter the guard sees relates
    to the unit's true event count:

    * **correct**: the guard's counter tracks the unit's event count
      (lock-step), so the unit's count is bounded by the cap; the pinned
      property ``<unit>_count <= cap`` holds.
    * **buggy**: the scope is broken (the counter is reset after every event,
      so it only ever sees the most recent one); the guard is always
      satisfied and the unit's true count runs past the cap; the property is
      violated.

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    cap : int
        The per-unit cap (must be >= 1).
    unit : str
        The scope unit name (``"session"``, ``"window"``, ``"user"``).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, three actions, and
        the pinned property ``<unit>_count <= cap``.
    """
    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))
    top = 2 * cap
    unit_var = "%s_count" % unit

    admit_guard = ir.BinOp("<", ir.V("scope_count"), ir.C(cap))
    do_event_effects = [
        ir.Assignment(unit_var,
                      ir.BinOp("+", ir.V(unit_var), ir.C(1))),
    ]
    if buggy:
        # Scope bug: the counter is reset to 1 after every event.
        do_event_effects.append(ir.Assignment("scope_count", ir.C(1)))
    else:
        # Correct: the counter tracks the unit's event count (lock-step).
        do_event_effects.append(
            ir.Assignment("scope_count",
                          ir.BinOp("+", ir.V("scope_count"), ir.C(1))))

    variables = [
        ir.StateVar(unit_var, ir.IntRange(0, top), ir.MODE_PRECISE, "service",
                    "events in the current %s (the property-relevant count)"
                    % unit),
        ir.StateVar("scope_count", ir.IntRange(0, cap + 1), ir.MODE_PRECISE,
                    "service",
                    "the counter the policy's guard actually uses"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment(unit_var, ir.C(0)),
                           ir.Assignment("scope_count", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="do_event", owner="service", guard=admit_guard,
                  effects=do_event_effects,
                  linearization="send(do_event)",
                  source="lower.py:do_event"),
        ir.Action(name="deny", owner="service", guard=ir.Not(admit_guard),
                  effects=[],
                  source="lower.py:deny"),
    ]
    pinned = ir.BinOp("<=", ir.V(unit_var), ir.C(cap))

    return ir.ProtocolIR(
        name="scoped-cap",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="samples/apw5",
        metadata={"protocol": "SCOPED_CAP", "target": "scoped_cap",
                  "buggy": bool(buggy), "cap": cap, "unit": unit,
                  "scope_bug": buggy},
    )



# ---------------------------------------------------------------------------
# APW-6: event-ordering (A must precede B)
# ---------------------------------------------------------------------------

def build_event_ordering_ir(buggy=False, first_action="read",
                            second_action="write"):
    """Hand-written oracle for the event-ordering shape.

    An ordering obligation: "B may happen only after A" (e.g. "a write may
    only follow a read of the same resource").  The two variants differ in
    whether the order is enforced:

    * **correct**: ``do_b`` is guarded on ``a_done`` (A has occurred), so B
      can never precede A; the pinned property ``NOT b_done OR a_done`` holds.
    * **buggy**: ``do_b`` is unguarded, so B can occur before A; the property
      is violated (witness ``b_done = true, a_done = false``).

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    first_action : str
        The action that must come first (A).
    second_action : str
        The action that must come second (B).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, four actions, and
        the pinned property ``NOT b_done OR a_done``.
    """
    if buggy:
        do_b_guard = ir.T()             # order not enforced: B may precede A
    else:
        do_b_guard = ir.V("a_done")     # order enforced: B only after A

    variables = [
        ir.StateVar("a_done", ir.Bool(), ir.MODE_PRECISE, "service",
                    "A (the required first action) has occurred"),
        ir.StateVar("b_done", ir.Bool(), ir.MODE_PRECISE, "service",
                    "B (the gated action) has occurred"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("a_done", ir.C(False)),
                           ir.Assignment("b_done", ir.C(False))],
                  is_initial=True,
                  source="lower.py:init"),
        # A: the required first action.
        ir.Action(name="do_a", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("a_done", ir.C(True))],
                  linearization="send(do_a)",
                  source="lower.py:do_a"),
        # B: the gated action (the thing under test).
        ir.Action(name="do_b", owner="service", guard=do_b_guard,
                  effects=[ir.Assignment("b_done", ir.C(True))],
                  linearization="send(do_b)",
                  source="lower.py:do_b"),
        # The deny branch: B is not yet permitted.
        ir.Action(name="b_deny", owner="service", guard=ir.Not(do_b_guard),
                  effects=[],
                  source="lower.py:b_deny"),
    ]
    # "B has not happened before A": NOT b_done OR a_done.
    pinned = ir.Or(ir.Not(ir.V("b_done")), ir.V("a_done"))

    return ir.ProtocolIR(
        name="event-ordering",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="samples/apw6",
        metadata={"protocol": "EVENT_ORDERING", "target": "event_ordering",
                  "buggy": bool(buggy),
                  "first_event": first_action,
                  "second_event": second_action,
                  "order_enforced": not buggy},
    )



# ---------------------------------------------------------------------------
# APW-6: window-boundary (absolute "daily" windows — 2× burst across the reset)
# ---------------------------------------------------------------------------

def build_window_boundary_ir(buggy=False, cap=3):
    """Hand-written oracle for the window-boundary burst shape (APW-6).

    An absolute-window cap: "at most K events per (absolute) window" (e.g. per
    day).  The two variants differ in whether the counter hard-resets at the
    window boundary:

    * **correct**: the counter does NOT hard-reset at the boundary (a sliding
      window), so the total admitted across windows is bounded by the cap; the
      pinned property ``total <= cap`` holds.
    * **buggy**: the counter hard-resets to zero at the boundary (an absolute
      window), so an attacker can do ``cap`` events just before the boundary and
      ``cap`` more just after it — a 2× burst; the property is violated.

    Parameters
    ----------
    buggy : bool
        Select the *policy* variant (the thing under test).
    cap : int
        The per-window cap (must be >= 1).

    Returns
    -------
    rot.ir.ProtocolIR
        A structurally valid IR with two state variables, three or four actions
        (the buggy variant adds ``reset_boundary``), and the pinned property
        ``total <= cap``.
    """
    if not isinstance(cap, int) or cap < 1:
        raise ValueError("cap must be an integer >= 1 (got %r)" % (cap,))

    admit_guard = ir.BinOp("<", ir.V("count"), ir.C(cap))
    variables = [
        ir.StateVar("count", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "events in the current window (the counter the guard uses)"),
        ir.StateVar("total", ir.IntRange(0, 2 * cap), ir.MODE_PRECISE, "service",
                    "total events admitted across windows (the property target)"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("count", ir.C(0)),
                           ir.Assignment("total", ir.C(0))],
                  is_initial=True,
                  source="lower.py:init"),
        ir.Action(name="do_event", owner="service", guard=admit_guard,
                  effects=[ir.Assignment("count",
                                         ir.BinOp("+", ir.V("count"), ir.C(1))),
                           ir.Assignment("total",
                                         ir.BinOp("+", ir.V("total"), ir.C(1)))],
                  linearization="send(do_event)",
                  source="lower.py:do_event"),
        ir.Action(name="deny", owner="service", guard=ir.Not(admit_guard),
                  effects=[],
                  source="lower.py:deny"),
    ]
    if buggy:
        # Absolute window: the counter hard-resets to zero at the boundary,
        # allowing a 2× burst (cap before + cap after).
        actions.append(
            ir.Action(name="reset_boundary", owner="service", guard=ir.T(),
                      effects=[ir.Assignment("count", ir.C(0))],
                      linearization="send(reset_boundary)",
                      source="lower.py:reset_boundary"),
        )
    # Correct: no reset_boundary action (a sliding window), so the total is
    # bounded by the cap.
    pinned = ir.BinOp("<=", ir.V("total"), ir.C(cap))

    return ir.ProtocolIR(
        name="window-boundary",
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=pinned,
        source_path="samples/apw6",
        metadata={"protocol": "WINDOW_BOUNDARY", "target": "window_boundary",
                  "buggy": bool(buggy), "cap": cap,
                  "absolute_window": buggy},
    )
