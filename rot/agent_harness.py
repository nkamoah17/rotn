# -*- coding: utf-8 -*-
"""agent_harness.py -- the general "adversarial agent + policy harness" model.

This is the G1 generalization of the ``agent_step`` vertical slice.  The
thesis's core model is::

    AgentStep == \\E t in Tools : Request(t)
    Request(t) == /\\ Policy(t, state)      * the harness decision (the guard)
               /\\ <the tool's effect>

i.e. the agent is a *nondeterministic actor* allowed to attempt **any** tool
in its catalog, and the *only* thing that can stop it is the harness's policy
decision, evaluated as a guard over the harness state.  The policy is the
*thing under test*: if it is correct, the forbidden effect is unreachable
(PROVEN); if it has a hole, the forbidden effect is reachable (VIOLATED, with
a witness that is the attack path).

The pieces:

  * :class:`Tool` -- one tool in the agent's catalog (name, effect, desc).
    The effect is the state change that applies *if the policy admits the
    attempt*.  The agent may attempt any tool; whether it is admitted is
    decided by the policy guard.

  * :class:`HarnessPolicy` -- the ``policy_eval(action, state) -> allow|deny``
    interface.  It maps each tool to a *guard expression* over the harness
    state (the harness's decision).  This is the thing under test.

  * :func:`build_ir` -- the general builder: turns ``(tools, policy, state,
    property)`` into a :class:`rot.ir.ProtocolIR` where every tool is an
    agent-attempted transition guarded by the policy decision.

Two instances ship, to show the model is general (not a one-off):

  * :func:`exfiltrate_build_ir` -- a *new* shape the old ``agent_step`` toy
    could not express: data labels + channels and the ``NoExfiltration`` rule
    (private data never reaches an unapproved channel).  The correct policy
    denies the send while the agent holds private data; the buggy policy does
    not, so the exfiltration is reachable.

  * :func:`spendcap_build_ir` -- the spend-cap (AWS Dogwood) model expressed
    as an instance of this general builder, showing the "strong core"
    (:mod:`rot.spendcap`) is a special case.

The agent is *always* adversarial in this model: it can attempt any tool in
the catalog.  The ``buggy`` flag selects the *policy* variant (the thing under
test), not the agent -- which is exactly the thesis's claim that "only the
harness policy (the thing under test) can stop it."

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir
import rot.spendcap as spendcap


# ---------------------------------------------------------------------------
# Tool: one action in the agent's catalog
# ---------------------------------------------------------------------------
class Tool(object):
    """One tool the agent can *attempt*.

    ``name``   -- stable tool name (becomes the ``agent_take_<name>`` action).
    ``effect`` -- list of ``(var, expr)`` pairs (or :class:`rot.ir.Assignment`)
                  applied *if the policy admits the attempt* (a post-state
                  update; ``expr`` may reference the pre-state).  An empty
                  list means the tool has no state effect (a safe channel).
    ``desc``   -- human description.
    """

    def __init__(self, name, effect, desc=""):
        self.name = name
        self.effect = list(effect)
        self.desc = desc

    def to_dict(self):
        out = []
        for e in self.effect:
            if isinstance(e, (tuple, list)):
                out.append([e[0], e[1].to_dict()])
            else:
                out.append(e.to_dict())
        return {"name": self.name, "effect": out, "desc": self.desc}

    def __repr__(self):
        return "Tool(%r, %d effects)" % (self.name, len(self.effect))


# ---------------------------------------------------------------------------
# HarnessPolicy: the policy_eval(action, state) -> allow|deny interface
# ---------------------------------------------------------------------------
class HarnessPolicy(object):
    """The harness's policy: a decision function over ``(tool, state)``.

    This is the ``policy_eval(action, state) -> allow|deny`` interface from
    the thesis.  It maps each tool to a *guard expression* (an
    :class:`rot.ir.Expr` over the harness state variables) that the harness
    evaluates to decide whether to admit the agent's attempt.  Tools with no
    explicit decision default to *allow* (guard ``True``) -- the harness only
    restricts the tools it names.

    The policy is the *thing under test*: a correct policy makes the forbidden
    effect unreachable; a buggy policy leaves a hole the model checker finds.
    """

    def __init__(self, decisions, name="harness"):
        # decisions: dict tool_name -> Expr (the guard / decision)
        self.decisions = dict(decisions or {})
        self.name = name

    def guard(self, tool):
        """The guard expression for ``tool`` (default: allow / ``True``)."""
        if tool in self.decisions:
            return self.decisions[tool]
        return ir.T()

    def policy_eval(self, tool, state):
        """``policy_eval(action, state) -> allow | deny | unknown``.

        Evaluates the harness's decision guard for ``tool`` in ``state`` and
        reports the harness's verdict: ``"allow"`` when the guard holds,
        ``"deny"`` when it is definitely False, ``"unknown"`` when the guard
        is UNDEF in ``state``.  This is the human/semantic API on top of the
        guard expression the IR actually carries.
        """
        r = self.guard(tool).eval(state)
        if r is ir.Expr.UNDEF:
            return "unknown"
        return "allow" if r else "deny"

    def tools(self):
        """Sorted list of the tools with an explicit decision."""
        return sorted(self.decisions.keys())

    def to_dict(self):
        return {
            "name": self.name,
            "decisions": {t: e.to_dict() for t, e in self.decisions.items()},
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            {t: ir.Expr.from_dict(e) for t, e in d.get("decisions", {}).items()},
            d.get("name", "harness"))

    def __repr__(self):
        return "HarnessPolicy(%r, %d decisions)" % (
            self.name, len(self.decisions))


# ---------------------------------------------------------------------------
# build_ir: the general adversarial-agent + policy-harness builder
# ---------------------------------------------------------------------------
def build_ir(tools, policy, state_vars, property, init,
             name="agent-harness", metadata=None):
    """Build the general agent-harness :class:`rot.ir.ProtocolIR`.

    Parameters
    ----------
    tools : list of Tool
        The agent's full tool catalog.  The agent is *adversarial*: it may
        attempt **any** tool here.
    policy : HarnessPolicy
        The harness decision per tool (the thing under test).
    state_vars : list of rot.ir.StateVar
        The harness's bookkeeping state.
    property : rot.ir.Expr
        The rule to verify (must hold in every reachable state).
    init : dict
        ``var -> initial value`` (the initial state, set by the init action).
    name : str
        IR name.
    metadata : dict or None
        Extra metadata merged over the defaults.

    Returns
    -------
    rot.ir.ProtocolIR
        One init action (setting the initial state) plus one transition action
        per tool (``agent_take_<tool>``), each guarded by the policy decision
        for that tool and carrying the tool's effect.
    """
    init_effects = [ir.Assignment(v, ir.C(init[v])) for v in init]
    actions = [
        ir.Action(name="init", owner="harness", guard=ir.T(),
                  effects=init_effects, is_initial=True,
                  source="agent_harness:init"),
    ]
    for t in tools:
        actions.append(
            ir.Action(
                name="agent_take_%s" % t.name,
                owner="agent",
                guard=policy.guard(t.name),
                effects=t.effect,
                source="agent_harness:%s" % t.name))
    meta = {
        "family": "AGENT_HARNESS",
        "adversarial_agent": True,
        "tools": [t.name for t in tools],
        "harness_policy": policy.to_dict(),
    }
    if metadata:
        meta.update(metadata)
    return ir.ProtocolIR(
        name=name,
        variables=list(state_vars),
        actions=actions,
        init=ir.T(),
        pinned_property=property,
        metadata=meta,
    )


# ---------------------------------------------------------------------------
# Instance 1: NoExfiltration (data labels + channels)
# ---------------------------------------------------------------------------
def no_exfiltration_property():
    """The rule: private data never reaches an unapproved channel.

    ``NOT exfiltrated`` in every reachable state, where ``exfiltrated`` is set
    when the agent sends to an unapproved channel while holding private data.
    This is the thesis's ``NoExfiltration`` rule expressed as a harness state
    predicate (the structural, provable half of the guarantee).
    """
    return ir.Not(ir.V("exfiltrated"))


def exfiltrate_tools():
    """The agent's tool catalog for the exfiltration model.

    The agent is adversarial: it may attempt *any* of these.  Whether a
    harmful attempt is admitted is decided by the policy guard, not by the
    agent.
    """
    return [
        Tool("read_private",
             [("holding_private", ir.C(True))],
             "read a private document (taints the agent's context)"),
        Tool("send_unapproved",
             [("exfiltrated",
               ir.Or(ir.V("exfiltrated"), ir.V("holding_private")))],
             "send to an unapproved (external) channel; if the agent is "
             "holding private data this is an exfiltration"),
        Tool("send_approved",
             [],
             "send to an approved recipient (a safe channel; no effect)"),
        Tool("redact",
             [("holding_private", ir.C(False))],
             "strip private data from the agent's context"),
    ]


def exfiltrate_policy(buggy=False):
    """The harness decision for the exfiltration model.

    correct -- ``send_unapproved`` is admitted only when the agent is NOT
               holding private data (the ``NoExfiltration`` rule);
    buggy   -- ``send_unapproved`` is always admitted (the hole: private data
               can be sent to an unapproved channel while held).
    """
    if buggy:
        return HarnessPolicy({"send_unapproved": ir.T()},
                             name="exfil-buggy")
    return HarnessPolicy(
        {"send_unapproved": ir.Not(ir.V("holding_private"))},
        name="exfil-correct")


def exfiltrate_build_ir(n=1, buggy=False):
    """Build the exfiltration agent-harness IR (registry-compatible).

    ``n`` is accepted for registry uniformity (this slice is a single agent).
    ``buggy`` selects the *policy* variant (the thing under test), not the
    agent -- the agent is always adversarial (it may attempt any tool).
    """
    state_vars = [
        ir.StateVar("holding_private", ir.Bool(), ir.MODE_PRECISE, "agent",
                    "the agent currently holds private data"),
        ir.StateVar("exfiltrated", ir.Bool(), ir.MODE_PRECISE, "agent",
                    "private data has been sent to an unapproved channel"),
    ]
    return build_ir(
        tools=exfiltrate_tools(),
        policy=exfiltrate_policy(buggy=buggy),
        state_vars=state_vars,
        property=no_exfiltration_property(),
        init={"holding_private": False, "exfiltrated": False},
        name="agent-harness-exfil-%s" % ("buggy" if buggy else "correct"),
        metadata={"protocol": "EXFILTRATION", "buggy": buggy, "n": int(n)},
    )


# ---------------------------------------------------------------------------
# Instance 2: SpendCap (AWS Dogwood) as an instance of the general builder
# ---------------------------------------------------------------------------
def spendcap_tools(amount=spendcap.AMOUNT):
    """The agent's tool catalog for the spendcap model.

    ``request`` fires a spend request (admitted by the policy, settles later);
    ``respond`` settles one in-flight request (the asynchronous response).
    """
    return [
        Tool("request",
             [("inflight", ir.BinOp("+", ir.V("inflight"), ir.C(1)))],
             "fire a spend request (admitted by the policy, settles later)"),
        Tool("respond",
             [("inflight", ir.BinOp("-", ir.V("inflight"), ir.C(1))),
              ("completed",
               ir.BinOp("+", ir.V("completed"), ir.C(amount)))],
             "settle one in-flight request (the asynchronous response)"),
    ]


def spendcap_policy(buggy=False, max_inflight=spendcap.MAX_INFLIGHT,
                    amount=spendcap.AMOUNT, cap=spendcap.CAP):
    """The harness decision for the spendcap model.

    ``request`` -- guarded by the policy decision (the thing under test) AND
                   the structural request-pool bound ``inflight < K``:
                   correct = in-flight accounting; buggy = settled-only.
    ``respond`` -- guarded by its structural precondition ``inflight >= 1``.
    """
    k = int(max_inflight)
    if buggy:
        decision = spendcap.spend_ok_guard_buggy(amount, cap)
        name = "spendcap-buggy"
    else:
        decision = spendcap.spend_ok_guard_correct(amount, cap)
        name = "spendcap-correct"
    return HarnessPolicy(
        {
            "request": ir.And(decision,
                              ir.BinOp("<", ir.V("inflight"), ir.C(k))),
            "respond": ir.BinOp(">=", ir.V("inflight"), ir.C(1)),
        },
        name=name)


def spendcap_build_ir(n=1, buggy=False, max_inflight=spendcap.MAX_INFLIGHT,
                      amount=spendcap.AMOUNT, cap=spendcap.CAP):
    """Build the spendcap agent-harness IR (registry-compatible).

    Shows the "strong core" (:mod:`rot.spendcap`) is an instance of the
    general adversarial-agent + policy-harness builder: the ``request`` tool
    is guarded by the policy decision and the ``respond`` tool by its
    structural precondition.  The reachable state space -- and therefore the
    verdicts -- match :func:`rot.spendcap.build_ir` (the no-op ``spend_deny``
    outcome is omitted because it has no effect and so never adds a state).
    """
    k = int(max_inflight)
    if k < 1:
        raise ValueError(
            "max_inflight (K) must be an integer >= 1 (got %r)" % (max_inflight,))
    state_vars = [
        ir.StateVar("completed", ir.IntRange(0, cap), ir.MODE_PRECISE,
                    "service", "settled amount (sum of responded requests)"),
        ir.StateVar("inflight", ir.IntRange(0, k), ir.MODE_PRECISE,
                    "service",
                    "approved-but-unsettled (in-flight) request count"),
    ]
    return build_ir(
        tools=spendcap_tools(amount),
        policy=spendcap_policy(buggy=buggy, max_inflight=k,
                               amount=amount, cap=cap),
        state_vars=state_vars,
        property=spendcap.within_cap_property(amount, cap),
        init={"completed": 0, "inflight": 0},
        name="agent-harness-spendcap-%s" % ("buggy" if buggy else "correct"),
        metadata={"protocol": "SPENDCAP", "buggy": buggy, "n": int(n),
                  "max_inflight": k, "amount": amount, "cap": cap},
    )


__all__ = [
    "Tool",
    "HarnessPolicy",
    "build_ir",
    "no_exfiltration_property",
    "exfiltrate_tools",
    "exfiltrate_policy",
    "exfiltrate_build_ir",
    "spendcap_tools",
    "spendcap_policy",
    "spendcap_build_ir",
]

