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

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir

__all__ = [
    "build_count_window_ir",
    "build_exists_sum_ir",
    "build_refund_budget_ir",
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

