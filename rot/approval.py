# -*- coding: utf-8 -*-
"""approval.py -- the approval / delegation / multi-agent orchestration family.

This is the G4 model family of the thesis: the *governance* rules that sit on
top of the single-agent policy model (``agent_harness``).  The thesis's rule
for this family is::

    NoUnapprovedIrreversible  ==  \\A a in Irreversible :
                                  Executed(a) => Approved(a)

plus the multi-agent orchestration guarantees -- no deadlocks, no runaway
budgets, no privilege escalation through delegation.  What was missing is now
modelled as bounded transition systems over the same :class:`rot.ir.ProtocolIR`
narrow waist the rest of the pipeline consumes, so **no new engine** is
required: the symbolic model checker explores the (finite) reachable state
space exhaustively and either proves the rule holds in every reachable state
(PROVEN) or returns a concrete witness -- the *governance bypass* -- that is
the attack path (VIOLATED).

The family has four sub-models.  Each ships a *correct* variant (the rule
holds -- the harness enforces the governance decision) and a *buggy* variant
(the seeded hole -- the harness forgets the governance check), so the model
checker discriminates exactly like the spend-cap pair:

* **approval** -- the :data:`NoUnapprovedIrreversible` rule.  An agent may
  request an irreversible action; a human approver may approve or deny it; the
  agent may execute it *only* once an approval token is in force.  The buggy
  harness executes the action without a valid approval.

* **delegation** -- no privilege escalation through delegation.  A delegatee
  may execute a privileged action only if the delegator was entitled to it.
  The buggy harness delegates regardless of the delegator's own entitlement.

* **orchestration** -- multi-agent deadlock + the liveness rule
  :data:`TaskEndsOrEscalates`.  An acyclic A -> B -> approver dependency chain
  always unwinds (the task ends) or is escalated.  The buggy orchestration adds
  the cycle edge (the approver waits on A), so the circular-wait state becomes
  reachable -- a deadlock.  ``escalate`` is the escape hatch that keeps the
  liveness rule true even in the deadlock-prone orchestration.

* **budget** -- no runaway budget across agents.  Two agents spend against a
  shared cap; the correct harness charges *both* agents' spend against the
  shared total, the buggy harness charges each agent's *local* spend only, so
  the shared total can run past the cap.

Every sub-model is parameterised by ``n`` (accepted for registry uniformity;
the slices are single-system) and ``buggy`` (selects the seeded decision
rule).  All state variables are :data:`rot.ir.MODE_PRECISE` over finite
domains, so the concrete engines decide them exhaustively.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import rot.ir as ir

__all__ = [
    "CAP", "AMOUNT",
    # approval
    "no_unapproved_irreversible_property", "approval_build_ir",
    # delegation
    "no_privilege_escalation_property", "delegation_build_ir",
    # orchestration
    "no_deadlock_property", "task_ends_or_escalates_property",
    "orchestration_build_ir",
    # budget
    "no_runaway_budget_property", "budget_build_ir",
    # livelock (G5 liveness core)
    "livelock_build_ir",
    # deadlock (G6 deadlock bind)
    "deadlock_build_ir",
]


#: Shared budget constants for the :func:`budget` sub-model.  ``AMOUNT`` is the
#: size of one spend; ``CAP`` is the shared cap.  With ``AMOUNT = 60`` and
#: ``CAP = 100`` a single spend fits but two do not, which is exactly what makes
#: the local-accounting bug (each agent sees only its own spend) observable.
CAP = 100
AMOUNT = 60


# ---------------------------------------------------------------------------
# Sub-model 1: approval -- the NoUnapprovedIrreversible rule
# ---------------------------------------------------------------------------
def no_unapproved_irreversible_property():
    """The :data:`NoUnapprovedIrreversible` rule as a state predicate.

    ``phase != "executed"  OR  approved_once`` -- the irreversible action may
    be in the ``executed`` phase only if an approval token was granted for it
    (``approved_once`` is the monotonic history flag set by the approver).
    Equivalently: an irreversible action is executed only if it was approved.
    """
    return ir.Or(
        ir.neq(ir.V("phase"), ir.C("executed")),
        ir.V("approved_once"),
    )


def approval_build_ir(n=1, buggy=False):
    """Build the approval state-machine :class:`rot.ir.ProtocolIR`.

    State (single system; all variables owned as noted):

    * ``phase``         -- the approval state machine:
      ``none -> pending -> approved -> executed`` with a ``denied`` re-request
      loop (``pending -> denied -> pending``).
    * ``approved_once`` -- monotonic history flag: an approval token was granted
      for this action (set once by the approver, never cleared).

    Actions (the agent is *adversarial*: it may attempt any of its actions;
    only the harness guard decides whether the effect applies):

    * ``agent_request``    -- request the irreversible action
      (``none | denied -> pending``).
    * ``approver_approve`` -- grant the approval token (``pending -> approved``;
      sets ``approved_once``).
    * ``approver_deny``    -- deny the request (``pending -> denied``).
    * ``agent_execute``    -- execute the irreversible action.  **Correct:**
      enabled only from ``approved`` (the harness enforces the approval).
      **Buggy:** enabled from any non-``executed`` phase (the harness executes
      without a valid approval).

    Pinned property: :func:`no_unapproved_irreversible_property`.
    """
    if int(n) < 1:
        raise ValueError("n must be >= 1 (got %r)" % (n,))
    phase_values = ["none", "pending", "approved", "denied", "executed"]
    variables = [
        ir.StateVar("phase", ir.Enum(phase_values), ir.MODE_PRECISE, "agent",
                    "approval state machine phase"),
        ir.StateVar("approved_once", ir.Bool(), ir.MODE_PRECISE, "approver",
                    "an approval token was granted for this action (monotonic)"),
    ]
    if buggy:
        # The seeded hole: the harness executes without requiring a valid
        # approval -- enabled from any non-executed phase.
        execute_guard = ir.neq(ir.V("phase"), ir.C("executed"))
    else:
        # Correct: the irreversible action executes only once approved.
        execute_guard = ir.eq(ir.V("phase"), ir.C("approved"))

    actions = [
        ir.Action("init", "agent", guard=ir.T(),
                  effects=[ir.Assignment("phase", ir.C("none")),
                           ir.Assignment("approved_once", ir.C(False))],
                  is_initial=True,
                  source="approval.py:init"),
        ir.Action("agent_request", "agent",
                  guard=ir.Or(ir.eq(ir.V("phase"), ir.C("none")),
                              ir.eq(ir.V("phase"), ir.C("denied"))),
                  effects=[ir.Assignment("phase", ir.C("pending"))],
                  source="approval.py:agent_request"),
        ir.Action("approver_approve", "approver",
                  guard=ir.eq(ir.V("phase"), ir.C("pending")),
                  effects=[ir.Assignment("phase", ir.C("approved")),
                           ir.Assignment("approved_once", ir.C(True))],
                  linearization="send(approve)",
                  source="approval.py:approver_approve"),
        ir.Action("approver_deny", "approver",
                  guard=ir.eq(ir.V("phase"), ir.C("pending")),
                  effects=[ir.Assignment("phase", ir.C("denied"))],
                  source="approval.py:approver_deny"),
        ir.Action("agent_execute", "agent", guard=execute_guard,
                  effects=[ir.Assignment("phase", ir.C("executed"))],
                  linearization="send(execute)",
                  source="approval.py:agent_execute"),
    ]
    name = "approval-buggy" if buggy else "approval-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=no_unapproved_irreversible_property(),
        source_path="",
        metadata={
            "protocol": "APPROVAL",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "no_unapproved_irreversible",
            "property_kind": "safety",
            "adversarial_agent": True,
        },
    )


# ---------------------------------------------------------------------------
# Sub-model 2: delegation -- no privilege escalation through delegation
# ---------------------------------------------------------------------------
def no_privilege_escalation_property():
    """The no-privilege-escalation rule as a state predicate.

    ``NOT executed  OR  delegator_perm`` -- the privileged action may have been
    executed only if the *delegator* was entitled to it (held the base
    permission).  Equivalently: a delegatee never executes an action the
    delegator itself was not entitled to.
    """
    return ir.Or(
        ir.Not(ir.V("executed")),
        ir.V("delegator_perm"),
    )


def delegation_build_ir(n=1, buggy=False):
    """Build the delegation :class:`rot.ir.ProtocolIR`.

    State (delegator + delegatee):

    * ``delegator_perm`` -- the delegator holds the base permission for the
      privileged action.  This is an *environment fact*: the delegator may or
      may not be entitled, modelled as a nondeterministic initial choice (the
      ``grant_delegator_perm`` action) so the property is checked in both
      worlds (entitled and not).
    * ``token``          -- the delegatee holds a delegated token.
    * ``executed``       -- the privileged action has been executed (by the
      delegatee).

    Actions:

    * ``grant_delegator_perm`` -- the delegator is granted the base permission
      (nondeterministic environment choice; ``delegator_perm := True``).
    * ``delegator_delegate``   -- the delegator grants the delegatee a token.
      **Correct:** enabled only when the delegator holds the permission
      (``delegator_perm AND NOT token``).  **Buggy:** enabled regardless of the
      delegator's own entitlement (``NOT token``) -- the escalation hole.
    * ``delegatee_execute``    -- the delegatee executes the privileged action
      (``token AND NOT executed``).

    Pinned property: :func:`no_privilege_escalation_property`.
    """
    if int(n) < 1:
        raise ValueError("n must be >= 1 (got %r)" % (n,))
    variables = [
        ir.StateVar("delegator_perm", ir.Bool(), ir.MODE_PRECISE, "delegator",
                    "the delegator holds the base permission (an env fact)"),
        ir.StateVar("token", ir.Bool(), ir.MODE_PRECISE, "delegatee",
                    "the delegatee holds a delegated token"),
        ir.StateVar("executed", ir.Bool(), ir.MODE_PRECISE, "delegatee",
                    "the privileged action has been executed"),
    ]
    if buggy:
        # The seeded hole: the delegator delegates regardless of its own
        # entitlement -- the delegatee can acquire a permission the delegator
        # never held.
        delegate_guard = ir.Not(ir.V("token"))
    else:
        # Correct: the delegator delegates only what it is entitled to.
        delegate_guard = ir.And(ir.V("delegator_perm"), ir.Not(ir.V("token")))

    actions = [
        ir.Action("init", "delegator", guard=ir.T(),
                  effects=[ir.Assignment("delegator_perm", ir.C(False)),
                           ir.Assignment("token", ir.C(False)),
                           ir.Assignment("executed", ir.C(False))],
                  is_initial=True,
                  source="approval.py:delegation_init"),
        ir.Action("grant_delegator_perm", "delegator",
                  guard=ir.Not(ir.V("delegator_perm")),
                  effects=[ir.Assignment("delegator_perm", ir.C(True))],
                  source="approval.py:grant_delegator_perm"),
        ir.Action("delegator_delegate", "delegator", guard=delegate_guard,
                  effects=[ir.Assignment("token", ir.C(True))],
                  linearization="send(delegate)",
                  source="approval.py:delegator_delegate"),
        ir.Action("delegatee_execute", "delegatee",
                  guard=ir.And(ir.V("token"), ir.Not(ir.V("executed"))),
                  effects=[ir.Assignment("executed", ir.C(True))],
                  linearization="send(execute)",
                  source="approval.py:delegatee_execute"),
    ]
    name = "delegation-buggy" if buggy else "delegation-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=no_privilege_escalation_property(),
        source_path="",
        metadata={
            "protocol": "DELEGATION",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "no_privilege_escalation",
            "property_kind": "safety",
            "adversarial_agent": True,
        },
    )


# ---------------------------------------------------------------------------
# Sub-model 3: orchestration -- multi-agent deadlock + TaskEndsOrEscalates
# ---------------------------------------------------------------------------
def no_deadlock_property():
    """The no-deadlock rule as a state predicate.

    ``NOT (task_pending AND a_waiting AND b_waiting AND approver_waiting)`` --
    the *circular wait* state (agent A waiting on B, B waiting on the approver,
    the approver waiting on A, with the task still pending) is unreachable.
    A circular wait is the classic deadlock condition: every participant is
    blocked on another, and no progress action is enabled.
    """
    return ir.Not(ir.And(
        ir.V("task_pending"),
        ir.V("a_waiting"),
        ir.V("b_waiting"),
        ir.V("approver_waiting"),
    ))


def task_ends_or_escalates_property():
    """The :data:`TaskEndsOrEscalates` liveness goal as a state predicate.

    ``done OR escalated`` -- the shared task either completes (``done``) or is
    escalated to a human (``escalated``).  This is a *goal* (liveness)
    predicate, not a universal safety predicate: it is dispatched to
    ``SymbolicEngine.reach_within`` and must be *reachable* within the bounded
    horizon.  The ``escalate`` action is the escape hatch that makes this hold
    even in the deadlock-prone orchestration: a task that would deadlock can
    still be escalated, so the task always ends or escalates.
    """
    return ir.Or(ir.V("done"), ir.V("escalated"))


def orchestration_build_ir(n=1, buggy=False):
    """Build the multi-agent orchestration :class:`rot.ir.ProtocolIR`.

    State (agent A, agent B, the approver; single shared task):

    * ``task_pending``     -- the shared task is still open (not done/escalated).
    * ``a_waiting``        -- agent A has delegated to B and waits on it.
    * ``b_waiting``        -- agent B has requested the approver and waits on it.
    * ``approver_waiting`` -- the approver has (in the buggy cycle) requested A.
    * ``b_approved``       -- the approver granted B's request.
    * ``b_done``           -- B finished its sub-task.
    * ``done``             -- the task completed (A finished).
    * ``escalated``        -- the task was escalated to a human.

    Actions (the acyclic chain A -> B -> approver, plus the escape hatch):

    * ``a_request_b``, ``b_request_approver``, ``approver_decide``,
      ``b_complete``, ``a_complete`` -- the acyclic dependency chain that
      unwinds into ``done``; and ``escalate`` -- the human escape hatch that
      sets ``escalated``.  Both keep the :func:`task_ends_or_escalates_property`
      liveness goal reachable.
    * ``approver_request_a`` -- **the cycle edge.**  **Correct:** disabled
      (``guard = False``; the approver never waits on A, so the chain stays
      acyclic and no circular wait is reachable).  **Buggy:** enabled when the
      approver is pending (``task_pending AND b_waiting AND NOT approver_waiting``),
      closing the A -> B -> approver -> A cycle so the circular-wait state
      becomes reachable (a deadlock).

    Pinned properties: :func:`no_deadlock_property` (safety) and
    :func:`task_ends_or_escalates_property` (liveness).
    """
    if int(n) < 1:
        raise ValueError("n must be >= 1 (got %r)" % (n,))
    variables = [
        ir.StateVar("task_pending", ir.Bool(), ir.MODE_PRECISE, "system",
                    "the shared task is still open"),
        ir.StateVar("a_waiting", ir.Bool(), ir.MODE_PRECISE, "agent_a",
                    "agent A has delegated to B and waits on it"),
        ir.StateVar("b_waiting", ir.Bool(), ir.MODE_PRECISE, "agent_b",
                    "agent B has requested the approver and waits on it"),
        ir.StateVar("approver_waiting", ir.Bool(), ir.MODE_PRECISE, "approver",
                    "the approver has requested A (the cycle edge)"),
        ir.StateVar("b_approved", ir.Bool(), ir.MODE_PRECISE, "approver",
                    "the approver granted B's request"),
        ir.StateVar("b_done", ir.Bool(), ir.MODE_PRECISE, "agent_b",
                    "B finished its sub-task"),
        ir.StateVar("done", ir.Bool(), ir.MODE_PRECISE, "agent_a",
                    "the task completed"),
        ir.StateVar("escalated", ir.Bool(), ir.MODE_PRECISE, "system",
                    "the task was escalated to a human"),
    ]
    if buggy:
        # The seeded hole: the approver waits on A, closing the cycle.
        cycle_guard = ir.And(ir.V("task_pending"), ir.V("b_waiting"),
                             ir.Not(ir.V("approver_waiting")))
    else:
        # Correct: the approver never waits on A -- the chain stays acyclic.
        cycle_guard = ir.F()

    actions = [
        ir.Action("init", "system", guard=ir.T(),
                  effects=[ir.Assignment("task_pending", ir.C(True)),
                           ir.Assignment("a_waiting", ir.C(False)),
                           ir.Assignment("b_waiting", ir.C(False)),
                           ir.Assignment("approver_waiting", ir.C(False)),
                           ir.Assignment("b_approved", ir.C(False)),
                           ir.Assignment("b_done", ir.C(False)),
                           ir.Assignment("done", ir.C(False)),
                           ir.Assignment("escalated", ir.C(False))],
                  is_initial=True,
                  source="approval.py:orchestration_init"),
        ir.Action("a_request_b", "agent_a",
                  guard=ir.And(ir.V("task_pending"), ir.Not(ir.V("a_waiting"))),
                  effects=[ir.Assignment("a_waiting", ir.C(True))],
                  source="approval.py:a_request_b"),
        ir.Action("b_request_approver", "agent_b",
                  guard=ir.And(ir.V("task_pending"), ir.V("a_waiting"),
                               ir.Not(ir.V("b_waiting"))),
                  effects=[ir.Assignment("b_waiting", ir.C(True))],
                  source="approval.py:b_request_approver"),
        ir.Action("approver_decide", "approver",
                  guard=ir.And(ir.V("task_pending"), ir.V("b_waiting"),
                               ir.Not(ir.V("approver_waiting"))),
                  effects=[ir.Assignment("b_approved", ir.C(True))],
                  source="approval.py:approver_decide"),
        ir.Action("b_complete", "agent_b",
                  guard=ir.And(ir.V("task_pending"), ir.V("b_waiting"),
                               ir.V("b_approved")),
                  effects=[ir.Assignment("b_waiting", ir.C(False)),
                           ir.Assignment("b_done", ir.C(True))],
                  source="approval.py:b_complete"),
        ir.Action("a_complete", "agent_a",
                  guard=ir.And(ir.V("task_pending"), ir.V("a_waiting"),
                               ir.V("b_done")),
                  effects=[ir.Assignment("a_waiting", ir.C(False)),
                           ir.Assignment("done", ir.C(True)),
                           ir.Assignment("task_pending", ir.C(False))],
                  linearization="send(done)",
                  source="approval.py:a_complete"),
        ir.Action("escalate", "system", guard=ir.V("task_pending"),
                  effects=[ir.Assignment("task_pending", ir.C(False)),
                           ir.Assignment("a_waiting", ir.C(False)),
                           ir.Assignment("b_waiting", ir.C(False)),
                           ir.Assignment("approver_waiting", ir.C(False)),
                           ir.Assignment("escalated", ir.C(True))],
                  linearization="send(escalate)",
                  source="approval.py:escalate"),
        ir.Action("approver_request_a", "approver", guard=cycle_guard,
                  effects=[ir.Assignment("approver_waiting", ir.C(True))],
                  source="approval.py:approver_request_a"),
    ]
    name = "orchestration-buggy" if buggy else "orchestration-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=no_deadlock_property(),
        source_path="",
        metadata={
            "protocol": "ORCHESTRATION",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "no_deadlock",
            "property_kind": "safety",
            "liveness_property": "task_ends_or_escalates",
            "adversarial_agent": True,
        },
    )


# ---------------------------------------------------------------------------
# Sub-model 4: budget -- no runaway budget across agents
# ---------------------------------------------------------------------------
def no_runaway_budget_property(cap=CAP):
    """The no-runaway-budget rule as a state predicate.

    ``spent_a + spent_b <= cap`` -- the *shared* total spend of all agents stays
    within the shared cap.  This is the multi-agent version of the spend-cap
    rule: instead of one agent's settled + in-flight amount, it is the sum of
    two agents' spend that must never exceed the shared cap.
    """
    return ir.BinOp("<=",
                    ir.BinOp("+", ir.V("spent_a"), ir.V("spent_b")),
                    ir.C(int(cap)))


def budget_build_ir(n=1, buggy=False, cap=CAP, amount=AMOUNT):
    """Build the multi-agent budget :class:`rot.ir.ProtocolIR`.

    State (two agents sharing one cap):

    * ``spent_a`` -- agent A's cumulative spend (an integer in ``[0, cap]``).
    * ``spent_b`` -- agent B's cumulative spend (an integer in ``[0, cap]``).

    Actions (each agent is adversarial: it may spend any time; the harness
    guard decides whether the shared cap is respected):

    * ``a_spend`` -- agent A spends ``amount``.  **Correct:** enabled only if
      the *shared* total would stay within the cap
      (``spent_a + spent_b + amount <= cap``).  **Buggy:** enabled if agent A's
      *local* spend would stay within the cap (``spent_a + amount <= cap``),
      ignoring agent B's spend -- the runaway hole.
    * ``b_spend`` -- agent B spends ``amount`` (mirror of ``a_spend``).

    With ``amount = 60`` and ``cap = 100`` a single spend fits but two do not:
    the correct harness lets at most one spend through, the buggy harness lets
    both through (total 120 > 100), so the shared cap is violated.

    Pinned property: :func:`no_runaway_budget_property`.
    """
    if int(n) < 1:
        raise ValueError("n must be >= 1 (got %r)" % (n,))
    cap = int(cap)
    amount = int(amount)
    variables = [
        ir.StateVar("spent_a", ir.IntRange(0, cap), ir.MODE_PRECISE, "agent_a",
                    "agent A's cumulative spend"),
        ir.StateVar("spent_b", ir.IntRange(0, cap), ir.MODE_PRECISE, "agent_b",
                    "agent B's cumulative spend"),
    ]
    if buggy:
        # The seeded hole: each agent accounts only its own local spend, so the
        # shared total can run past the cap.
        a_guard = ir.BinOp("<=", ir.BinOp("+", ir.V("spent_a"), ir.C(amount)),
                           ir.C(cap))
        b_guard = ir.BinOp("<=", ir.BinOp("+", ir.V("spent_b"), ir.C(amount)),
                           ir.C(cap))
    else:
        # Correct: each spend is charged against the shared total.
        a_guard = ir.BinOp(
            "<=",
            ir.BinOp("+", ir.BinOp("+", ir.V("spent_a"), ir.V("spent_b")),
                     ir.C(amount)),
            ir.C(cap))
        b_guard = ir.BinOp(
            "<=",
            ir.BinOp("+", ir.BinOp("+", ir.V("spent_a"), ir.V("spent_b")),
                     ir.C(amount)),
            ir.C(cap))

    actions = [
        ir.Action("init", "system", guard=ir.T(),
                  effects=[ir.Assignment("spent_a", ir.C(0)),
                           ir.Assignment("spent_b", ir.C(0))],
                  is_initial=True,
                  source="approval.py:budget_init"),
        ir.Action("a_spend", "agent_a", guard=a_guard,
                  effects=[ir.Assignment(
                      "spent_a",
                      ir.BinOp("+", ir.V("spent_a"), ir.C(amount)))],
                  linearization="send(spend_a)",
                  source="approval.py:a_spend"),
        ir.Action("b_spend", "agent_b", guard=b_guard,
                  effects=[ir.Assignment(
                      "spent_b",
                      ir.BinOp("+", ir.V("spent_b"), ir.C(amount)))],
                  linearization="send(spend_b)",
                  source="approval.py:b_spend"),
    ]
    name = "budget-buggy" if buggy else "budget-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=no_runaway_budget_property(cap),
        source_path="",
        metadata={
            "protocol": "BUDGET",
            "buggy": bool(buggy),
            "n": int(n),
            "cap": cap,
            "amount": amount,
            "property_name": "no_runaway_budget",
            "property_kind": "safety",
            "adversarial_agent": True,
        },
    )


# ---------------------------------------------------------------------------
# Sub-model 4: livelock -- progress without completion (G5 liveness core)
# ---------------------------------------------------------------------------
def livelock_build_ir(n=1, buggy=False):
    """Build the two-agent livelock :class:`rot.ir.ProtocolIR` (G5).

    State (two agents A and B sharing one task):

    * ``task_pending`` -- the shared task is still open (not done/escalated).
    * ``a_turn``       -- whose turn it is to act (A when True, B when False).
    * ``done``         -- the task completed.
    * ``escalated``    -- the task was escalated to a human.

    Actions (the agent is adversarial -- it may attempt **any** of these; the
    harness *policy* (the guards) is the thing under test):

    * ``a_request_b``  -- A passes the task to B (``a_turn -> False``).
    * ``b_request_a``  -- B passes the task back to A (``a_turn -> True``).
    * ``b_complete``   -- B completes the task (``done -> True``).
    * ``escalate``     -- the task is escalated to a human (``escalated -> True``).

    correct -- ``b_complete`` is admitted when it is B's turn and the task is
               still pending, and ``escalate`` is admitted while the task is
               pending; so the task *ends* (``done``) or *escalates* and the
               pinned liveness rule ``TaskEndsOrEscalates`` is REACHED.
    buggy   -- ``b_complete`` and ``escalate`` are never admitted (guard
               ``False``); the only enabled actions are ``a_request_b`` and
               ``b_request_a``, which bounce the task back and forth forever.
               The task never completes and never escalates, so
               ``TaskEndsOrEscalates`` is NOT_REACHED (liveness VIOLATED), yet
               the system keeps making progress (an action is always enabled)
               -- a *livelock*, not a deadlock.  Use :func:`find_deadlock_state`
               (with ``terminal = done OR escalated``) to confirm the buggy
               model has no stuck state and so is a livelock, not a deadlock.

    This is the G5 liveness core: a real ``TaskEndsOrEscalates`` rule
    (``done OR escalated``) that the correct model satisfies and the buggy
    model refutes, plus a clean livelock/deadlock distinction.
    """
    variables = [
        ir.StateVar("task_pending", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the shared task is still open (not done/escalated)"),
        ir.StateVar("a_turn", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "whose turn it is to act (A when True, B when False)"),
        ir.StateVar("done", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the task completed"),
        ir.StateVar("escalated", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the task was escalated to a human"),
    ]
    if buggy:
        # The buggy harness never admits completion or escalation: the task
        # bounces between A and B forever (a livelock).
        b_complete_guard = ir.F()
        escalate_guard = ir.F()
    else:
        b_complete_guard = ir.And(
            ir.V("task_pending"), ir.Not(ir.V("a_turn")),
            ir.Not(ir.V("done")), ir.Not(ir.V("escalated")))
        escalate_guard = ir.And(
            ir.V("task_pending"),
            ir.Not(ir.V("done")), ir.Not(ir.V("escalated")))
    actions = [
        ir.Action(name="init", owner="harness", guard=ir.T(),
                  effects=[
                      ir.Assignment("task_pending", ir.C(True)),
                      ir.Assignment("a_turn", ir.C(True)),
                      ir.Assignment("done", ir.C(False)),
                      ir.Assignment("escalated", ir.C(False)),
                  ],
                  is_initial=True,
                  source="approval.py:init"),
        ir.Action(name="a_request_b", owner="agent",
                  guard=ir.And(ir.V("task_pending"), ir.V("a_turn"),
                               ir.Not(ir.V("done")), ir.Not(ir.V("escalated"))),
                  effects=[ir.Assignment("a_turn", ir.C(False))],
                  source="approval.py:a_request_b"),
        ir.Action(name="b_request_a", owner="agent",
                  guard=ir.And(ir.V("task_pending"), ir.Not(ir.V("a_turn")),
                               ir.Not(ir.V("done")), ir.Not(ir.V("escalated"))),
                  effects=[ir.Assignment("a_turn", ir.C(True))],
                  source="approval.py:b_request_a"),
        ir.Action(name="b_complete", owner="agent",
                  guard=b_complete_guard,
                  effects=[ir.Assignment("done", ir.C(True)),
                           ir.Assignment("task_pending", ir.C(False))],
                  source="approval.py:b_complete"),
        ir.Action(name="escalate", owner="human",
                  guard=escalate_guard,
                  effects=[ir.Assignment("escalated", ir.C(True)),
                           ir.Assignment("task_pending", ir.C(False))],
                  source="approval.py:escalate"),
    ]
    name = "livelock-buggy" if buggy else "livelock-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=task_ends_or_escalates_property(),
        source_path="",
        metadata={
            "protocol": "LIVELOCK",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "task_ends_or_escalates",
            "property_kind": "liveness",
            "adversarial_agent": True,
        },
    )


# ---------------------------------------------------------------------------
# Sub-model 5: deadlock -- the system is stuck (G6 deadlock bind)
# ---------------------------------------------------------------------------
def deadlock_build_ir(n=1, buggy=False):
    """Build the two-agent deadlock :class:`rot.ir.ProtocolIR` (G6 bind).

    State (two agents A and B sharing one task):

    * ``task_pending`` -- the shared task is still open (not done/escalated).
    * ``a_waiting``    -- A is blocked waiting on B.
    * ``b_waiting``    -- B is blocked waiting on A.
    * ``done``         -- the task completed.
    * ``escalated``    -- the task was escalated to a human.

    Actions (the agent is adversarial -- it may attempt **any** of these; the
    harness *policy* (the guards) is the thing under test):

    * ``a_wait``       -- A starts waiting on B (``a_waiting -> True``).
    * ``b_wait``       -- B starts waiting on A (``b_waiting -> True``).
    * ``b_complete``   -- B completes the task (``done -> True``).
    * ``escalate``     -- the task is escalated to a human (``escalated -> True``).

    correct -- ``b_complete`` and ``escalate`` are admitted, so the task ends
               (``done``) or is escalated: ``TaskEndsOrEscalates`` is REACHED
               (liveness holds).
    buggy   -- ``b_complete`` and ``escalate`` are never admitted (guard
               ``False``); A and B wait on each other and reach the *circular
               wait* state (``task_pending AND a_waiting AND b_waiting``) where
               **no action is enabled** -- the system is *stuck*.  This is a
               genuine *deadlock*: :func:`find_deadlock_state` (with
               ``terminal = done OR escalated``) reports a stuck state, and
               ``TaskEndsOrEscalates`` is NOT_REACHED (liveness VIOLATED).

    This contrasts with the :func:`livelock_build_ir` buggy model (also
    liveness-VIOLATED) which is **not** stuck -- it keeps making progress.
    Stuck + never ends is a deadlock; progressing + never ends is a livelock.
    """
    variables = [
        ir.StateVar("task_pending", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the shared task is still open (not done/escalated)"),
        ir.StateVar("a_waiting", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "A is blocked waiting on B"),
        ir.StateVar("b_waiting", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "B is blocked waiting on A"),
        ir.StateVar("done", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the task completed"),
        ir.StateVar("escalated", ir.Bool(), ir.MODE_PRECISE, "harness",
                    "the task was escalated to a human"),
    ]
    if buggy:
        # The buggy harness never admits completion or escalation: the two
        # agents wait on each other forever (a deadlock).
        b_complete_guard = ir.F()
        escalate_guard = ir.F()
    else:
        b_complete_guard = ir.And(
            ir.V("task_pending"),
            ir.Not(ir.V("done")), ir.Not(ir.V("escalated")))
        escalate_guard = ir.And(
            ir.V("task_pending"),
            ir.Not(ir.V("done")), ir.Not(ir.V("escalated")))
    actions = [
        ir.Action(name="init", owner="harness", guard=ir.T(),
                  effects=[
                      ir.Assignment("task_pending", ir.C(True)),
                      ir.Assignment("a_waiting", ir.C(False)),
                      ir.Assignment("b_waiting", ir.C(False)),
                      ir.Assignment("done", ir.C(False)),
                      ir.Assignment("escalated", ir.C(False)),
                  ],
                  is_initial=True,
                  source="approval.py:init"),
        ir.Action(name="a_wait", owner="agent",
                  guard=ir.And(ir.V("task_pending"), ir.Not(ir.V("a_waiting")),
                               ir.Not(ir.V("done")), ir.Not(ir.V("escalated"))),
                  effects=[ir.Assignment("a_waiting", ir.C(True))],
                  source="approval.py:a_wait"),
        ir.Action(name="b_wait", owner="agent",
                  guard=ir.And(ir.V("task_pending"), ir.Not(ir.V("b_waiting")),
                               ir.Not(ir.V("done")), ir.Not(ir.V("escalated"))),
                  effects=[ir.Assignment("b_waiting", ir.C(True))],
                  source="approval.py:b_wait"),
        ir.Action(name="b_complete", owner="agent",
                  guard=b_complete_guard,
                  effects=[ir.Assignment("done", ir.C(True)),
                           ir.Assignment("task_pending", ir.C(False))],
                  source="approval.py:b_complete"),
        ir.Action(name="escalate", owner="human",
                  guard=escalate_guard,
                  effects=[ir.Assignment("escalated", ir.C(True)),
                           ir.Assignment("task_pending", ir.C(False))],
                  source="approval.py:escalate"),
    ]
    name = "deadlock-buggy" if buggy else "deadlock-correct"
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        pinned_property=task_ends_or_escalates_property(),
        source_path="",
        metadata={
            "protocol": "DEADLOCK",
            "buggy": bool(buggy),
            "n": int(n),
            "property_name": "task_ends_or_escalates",
            "property_kind": "liveness",
            "adversarial_agent": True,
        },
    )