# -*- coding: utf-8 -*-
"""targets.py -- registry of verifiable protocol targets for the vertical slice.

The pipeline is target-agnostic: it receives a target name, resolves the
concrete ProtocolIR to build, and the set of named invariants that can be
pinned for it. Five protocols ship as targets, each with a correct and a buggy
variant that share state and actions and differ only in a seeded decision rule:

  2PC (rot.twopc):
    * ``correct`` -- participants apply the coordinator's decision (agreement
      holds; every engine should prove it).
    * ``buggy``   -- participants self-decide from their own vote (a seeded bug;
      agreement breaks; every engine should find a counterexample).
    Both expose the three named invariants (rot.invariants): ``agreement``,
    ``validity``, ``no_spurious_abort``.

  ZAB (rot.zab):
    * ``zab-correct`` -- followers apply only after the leader commits
      (``zab_no_premature_apply`` holds; every engine should prove it).
    * ``zab-buggy``   -- followers apply as soon as they persist, before the
      leader commits (a seeded bug; ``zab_no_premature_apply`` breaks; every
      engine should find a counterexample).
    Both expose the two named invariants: ``zab_no_premature_apply``,
    ``zab_apply_persisted``.

  PBFT (rot.pbft):
    * ``pbft-correct`` -- nodes commit only on a quorum certificate
      (``pbft_quorum`` holds; every engine should prove it).
    * ``pbft-buggy``   -- nodes commit as soon as they have prepared
      themselves, without a quorum certificate (a seeded bug; ``pbft_quorum``
      breaks; every engine should find a counterexample).
    Both expose the two named invariants: ``pbft_quorum``,
    ``pbft_prepare_before_commit``.

  Payment (rot.payment, via rot.composition) -- the Phase 2 *composition
  plane* demo: two independently modelled services (client + payment) merged
  into one concurrent IR, verified against cross-service invariants:
    * ``payment-correct`` -- charge is idempotent (``no_double_charge``
      holds; every engine should prove it).
    * ``payment-buggy``   -- charge ignores the idempotency guard, so a
      re-issued charge double-charges (a seeded bug; ``no_double_charge``
      breaks; every engine should find a counterexample).
    Both expose the three named invariants: ``no_double_charge`` (cross-
    service, RUNG_E2E, blocking), ``charge_requires_order`` (cross-service,
    RUNG_E2E), ``settle_requires_charge`` (payment-local, RUNG_LOCAL).

  SpendCap (rot.spendcap, AWS Dogwood) -- the decision-plane *parallel fire
  race*: one service approves a spend (``spend_ok``) and settles it later
  (``respond``); in-flight requests must count against the cap:
    * ``spendcap-correct`` -- ``spend_ok`` charges in-flight requests against
      the cap (``spendcap_within_cap`` holds; every engine should prove it).
    * ``spendcap-buggy``   -- ``spend_ok`` charges settled responses only, so
      a parallel burst of fires grows the in-flight amount past the cap (a
      seeded bug; ``spendcap_within_cap`` breaks; every engine should find a
      counterexample).
    Both expose the one named invariant: ``spendcap_within_cap`` (service-
    local, RUNG_PROTOCOL, blocking).

  G4 governance (rot.approval) -- the approval / delegation / multi-agent
  orchestration family.  Each is a correct and a buggy variant that share
  state and actions and differ only in a seeded governance decision:
    * ``approval-correct`` / ``approval-buggy`` -- the
      ``NoUnapprovedIrreversible`` rule: the irreversible action executes only
      once approved.  The buggy harness executes without a valid approval
      (``no_unapproved_irreversible`` breaks).
    * ``delegation-correct`` / ``delegation-buggy`` -- no privilege escalation
      through delegation: the delegatee never executes what the delegator was
      not entitled to.  The buggy harness delegates regardless (
      ``no_privilege_escalation`` breaks).
    * ``orchestration-correct`` / ``orchestration-buggy`` -- no deadlock plus
      the liveness rule ``TaskEndsOrEscalates``.  The buggy orchestration
      closes the A -> B -> approver -> A cycle (``no_deadlock`` breaks); the
      ``escalate`` escape hatch keeps ``task_ends_or_escalates`` reachable.
    * ``budget-correct`` / ``budget-buggy`` -- no runaway budget across agents:
      the shared total spend stays within the cap.  The buggy harness accounts
      local spend only (``no_runaway_budget`` breaks).

Adding a new target is a registration of a builder that returns a ProtocolIR
plus its property list -- nothing else in the pipeline needs to change.
Pure stdlib, Python 3.6 compatible.
"""

import rot.invariants as invariants
import rot.twopc as twopc
import rot.zab as zab
import rot.pbft as pbft
import rot.payment as payment
import rot.spendcap as spendcap
import rot.agent_step as agent_step
import rot.agent_harness as agent_harness
import rot.approval as approval


class TargetSpec(object):
    """A named, buildable verification target.

    ``protocol`` is a short human-facing family name (e.g. "2PC", "ZAB") used
    for report titles/labels. It defaults to "2PC" so the existing 2PC targets
    are unchanged; non-2PC targets (e.g. ZAB) set it explicitly.
    """

    def __init__(self, name, description, build, properties, default_property,
                 protocol="2PC"):
        self.name = name
        self.description = description
        self.build = build                 # callable(n) -> ProtocolIR
        self.properties = list(properties)
        self.default_property = default_property
        self.protocol = protocol

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "properties": self.properties,
            "default_property": self.default_property,
        }


# Per-protocol named invariants (drives which properties each target exposes).
TWOPC_PROPS = ["agreement", "validity", "no_spurious_abort"]
ZAB_PROPS = ["zab_no_premature_apply", "zab_apply_persisted"]
PBFT_PROPS = ["pbft_quorum", "pbft_prepare_before_commit"]
PAYMENT_PROPS = ["no_double_charge", "charge_requires_order",
                 "settle_requires_charge"]
AGENT_PROPS = ["policy_conformance", "bounded_eventually"]
SPENDCAP_PROPS = ["spendcap_within_cap"]
EXFIL_PROPS = ["no_exfiltration"]
# G4: approval / delegation / multi-agent orchestration (rot.approval).
APPROVAL_PROPS = ["no_unapproved_irreversible"]
DELEGATION_PROPS = ["no_privilege_escalation"]
ORCHESTRATION_PROPS = ["no_deadlock", "task_ends_or_escalates"]
BUDGET_PROPS = ["no_runaway_budget"]
# G5 liveness core (livelock): the real TaskEndsOrEscalates rule.
LIVELOCK_PROPS = ["task_ends_or_escalates"]
# G6 over-privileged tool bind (model-checked over-grant).
OVERPRIV_PROPS = ["no_over_privileged_tool"]


def _spec(name, description, buggy, build, properties, default_property,
          protocol="2PC"):
    return TargetSpec(
        name=name,
        description=description,
        build=lambda n: build(n=n, buggy=buggy),
        properties=list(properties),
        default_property=default_property,
        protocol=protocol,
    )


_REGISTRY = {
    "correct": _spec(
        "correct",
        "Two-phase commit: participants apply the coordinator's decision "
        "(the correct implementation).",
        buggy=False,
        build=twopc.build_ir,
        properties=TWOPC_PROPS,
        default_property="agreement"),
    "buggy": _spec(
        "buggy",
        "Two-phase commit: participants self-decide from their own vote "
        "(a seeded bug; agreement breaks).",
        buggy=True,
        build=twopc.build_ir,
        properties=TWOPC_PROPS,
        default_property="agreement"),
    "zab-correct": _spec(
        "zab-correct",
        "ZAB broadcast/commit: followers apply only after the leader commits "
        "(the correct implementation).",
        buggy=False,
        build=zab.build_ir,
        properties=ZAB_PROPS,
        default_property="zab_no_premature_apply",
        protocol="ZAB"),
    "zab-buggy": _spec(
        "zab-buggy",
        "ZAB broadcast/commit: followers apply as soon as they persist, even "
        "before the leader commits (a seeded bug; no-premature-apply breaks).",
        buggy=True,
        build=zab.build_ir,
        properties=ZAB_PROPS,
        default_property="zab_no_premature_apply",
        protocol="ZAB"),
    "pbft-correct": _spec(
        "pbft-correct",
        "PBFT prepare/commit: nodes commit only on a quorum certificate "
        "(the correct implementation).",
        buggy=False,
        build=pbft.build_ir,
        properties=PBFT_PROPS,
        default_property="pbft_quorum",
        protocol="PBFT"),
    "pbft-buggy": _spec(
        "pbft-buggy",
        "PBFT prepare/commit: nodes commit as soon as they have prepared "
        "themselves, without a quorum certificate (a seeded bug; "
        "pbft_quorum breaks).",
        buggy=True,
        build=pbft.build_ir,
        properties=PBFT_PROPS,
        default_property="pbft_quorum",
        protocol="PBFT"),
    "payment-correct": _spec(
        "payment-correct",
        "Client + payment services composed: charging is idempotent "
        "(the correct implementation; no_double_charge holds).",
        buggy=False,
        build=payment.build_ir,
        properties=PAYMENT_PROPS,
        default_property="no_double_charge",
        protocol="PAYMENT"),
    "payment-buggy": _spec(
        "payment-buggy",
        "Client + payment services composed: charge ignores the idempotency "
        "guard, so a re-issued charge double-charges the order (a seeded bug; "
        "no_double_charge breaks).",
        buggy=True,
        build=payment.build_ir,
        properties=PAYMENT_PROPS,
        default_property="no_double_charge",
        protocol="PAYMENT"),
    "spendcap-correct": _spec(
        "spendcap-correct",
        "Spend cap (AWS Dogwood): spend_ok charges in-flight requests against "
        "the cap, so settled + in-flight never exceeds the cap (the correct "
        "implementation; spendcap_within_cap holds).",
        buggy=False,
        build=spendcap.build_ir,
        properties=SPENDCAP_PROPS,
        default_property="spendcap_within_cap",
        protocol="SPENDCAP"),
    "spendcap-buggy": _spec(
        "spendcap-buggy",
        "Spend cap (AWS Dogwood): spend_ok charges settled responses only, "
        "so a parallel burst of fires grows the in-flight amount past the cap "
        "(a seeded bug; spendcap_within_cap breaks).",
        buggy=True,
        build=spendcap.build_ir,
        properties=SPENDCAP_PROPS,
        default_property="spendcap_within_cap",
        protocol="SPENDCAP"),
    "agent-step": _spec(
        "agent-step",
        "Adversarial agent step: a conforming agent never takes an action "
        "denied by its policy (the correct implementation; "
        "policy_conformance holds).",
        buggy=False,
        build=agent_step.build_ir,
        properties=AGENT_PROPS,
        default_property="policy_conformance",
        protocol="AGENT_STEP"),
    "agent-step-buggy": _spec(
        "agent-step-buggy",
        "Adversarial agent step: a compromised/mis-configured agent is free "
        "to attempt a denied action (a seeded bug; policy_conformance breaks).",
        buggy=True,
        build=agent_step.build_ir,
        properties=AGENT_PROPS,
        default_property="policy_conformance",
        protocol="AGENT_STEP"),
    "exfil-correct": _spec(
        "exfil-correct",
        "Agent harness (NoExfiltration): the policy denies an unapproved send "
        "while the agent holds private data, so private data never reaches an "
        "unapproved channel (the correct implementation; no_exfiltration "
        "holds).",
        buggy=False,
        build=agent_harness.exfiltrate_build_ir,
        properties=EXFIL_PROPS,
        default_property="no_exfiltration",
        protocol="EXFILTRATION"),
    "exfil-buggy": _spec(
        "exfil-buggy",
        "Agent harness (NoExfiltration): the policy admits an unapproved send "
        "even while the agent holds private data, so an exfiltration is "
        "reachable (a seeded bug; no_exfiltration breaks).",
        buggy=True,
        build=agent_harness.exfiltrate_build_ir,
        properties=EXFIL_PROPS,
        default_property="no_exfiltration",
        protocol="EXFILTRATION"),
    # G4: approval / delegation / multi-agent orchestration (rot.approval).
    "approval-correct": _spec(
        "approval-correct",
        "Approval state machine (NoUnapprovedIrreversible): the irreversible "
        "action executes only once approved (the correct implementation; "
        "no_unapproved_irreversible holds).",
        buggy=False,
        build=approval.approval_build_ir,
        properties=APPROVAL_PROPS,
        default_property="no_unapproved_irreversible",
        protocol="APPROVAL"),
    "approval-buggy": _spec(
        "approval-buggy",
        "Approval state machine (NoUnapprovedIrreversible): the harness "
        "executes the irreversible action without a valid approval (a seeded "
        "bug; no_unapproved_irreversible breaks).",
        buggy=True,
        build=approval.approval_build_ir,
        properties=APPROVAL_PROPS,
        default_property="no_unapproved_irreversible",
        protocol="APPROVAL"),
    "delegation-correct": _spec(
        "delegation-correct",
        "Delegation (NoPrivilegeEscalation): the delegatee never executes an "
        "action the delegator was not entitled to (the correct implementation; "
        "no_privilege_escalation holds).",
        buggy=False,
        build=approval.delegation_build_ir,
        properties=DELEGATION_PROPS,
        default_property="no_privilege_escalation",
        protocol="DELEGATION"),
    "delegation-buggy": _spec(
        "delegation-buggy",
        "Delegation (NoPrivilegeEscalation): the delegator delegates "
        "regardless of its own entitlement, so the delegatee executes a "
        "permission the delegator never held (a seeded bug; "
        "no_privilege_escalation breaks).",
        buggy=True,
        build=approval.delegation_build_ir,
        properties=DELEGATION_PROPS,
        default_property="no_privilege_escalation",
        protocol="DELEGATION"),
    "orchestration-correct": _spec(
        "orchestration-correct",
        "Multi-agent orchestration (NoDeadlock + TaskEndsOrEscalates): an "
        "acyclic A -> B -> approver dependency chain that always unwinds or "
        "escalates (the correct implementation; no_deadlock holds and "
        "task_ends_or_escalates is reachable).",
        buggy=False,
        build=approval.orchestration_build_ir,
        properties=ORCHESTRATION_PROPS,
        default_property="no_deadlock",
        protocol="ORCHESTRATION"),
    "orchestration-buggy": _spec(
        "orchestration-buggy",
        "Multi-agent orchestration (NoDeadlock + TaskEndsOrEscalates): the "
        "approver waits on A, closing the A -> B -> approver -> A cycle, so a "
        "circular-wait (deadlock) state is reachable (a seeded bug; no_deadlock "
        "breaks; task_ends_or_escalates still reachable via escalate).",
        buggy=True,
        build=approval.orchestration_build_ir,
        properties=ORCHESTRATION_PROPS,
        default_property="no_deadlock",
        protocol="ORCHESTRATION"),
    "budget-correct": _spec(
        "budget-correct",
        "Multi-agent budget (NoRunawayBudget): both agents' spend is charged "
        "against the shared cap, so the shared total stays within it (the "
        "correct implementation; no_runaway_budget holds).",
        buggy=False,
        build=approval.budget_build_ir,
        properties=BUDGET_PROPS,
        default_property="no_runaway_budget",
        protocol="BUDGET"),
    "budget-buggy": _spec(
        "budget-buggy",
        "Multi-agent budget (NoRunawayBudget): each agent accounts only its "
        "local spend, so the shared total runs past the cap (a seeded bug; "
        "no_runaway_budget breaks).",
        buggy=True,
        build=approval.budget_build_ir,
        properties=BUDGET_PROPS,
        default_property="no_runaway_budget",
        protocol="BUDGET"),
    # G5 liveness core: livelock (progress without completion).  The correct
    # model ends or escalates the task (TaskEndsOrEscalates REACHED); the
    # buggy harness never admits completion or escalation, so the task bounces
    # forever (TaskEndsOrEscalates NOT_REACHED) -- a livelock, not a deadlock.
    "livelock-correct": _spec(
        "livelock-correct",
        "Livelock (G5 liveness core): the task is admitted to complete (or be "
        "escalated), so TaskEndsOrEscalates is REACHED (the correct "
        "implementation; liveness holds).",
        buggy=False,
        build=approval.livelock_build_ir,
        properties=LIVELOCK_PROPS,
        default_property="task_ends_or_escalates",
        protocol="LIVELOCK"),
    "livelock-buggy": _spec(
        "livelock-buggy",
        "Livelock (G5 liveness core): the harness never admits completion or "
        "escalation, so the task bounces between the agents forever "
        "(TaskEndsOrEscalates NOT_REACHED) -- the system keeps making progress "
        "(no stuck state), so this is a livelock, not a deadlock.",
        buggy=True,
        build=approval.livelock_build_ir,
        properties=LIVELOCK_PROPS,
        default_property="task_ends_or_escalates",
        protocol="LIVELOCK"),
    # G6 over-privileged tool bind (model-checked over-grant): the correct
    # policy denies the unneeded tool (no_over_privileged_tool holds); the
    # buggy policy over-grants it, so the agent can take it and the property
    # is refuted (witness = the over-privileged tool taken).
    "overpriv-correct": _spec(
        "overpriv-correct",
        "Over-privileged tool (G6 bind): the harness denies the unneeded tool, "
        "so the agent never takes a tool it was not required to (the correct "
        "implementation; no_over_privileged_tool holds).",
        buggy=False,
        build=agent_harness.overpriv_build_ir,
        properties=OVERPRIV_PROPS,
        default_property="no_over_privileged_tool",
        protocol="OVERPRIVILEGED"),
    "overpriv-buggy": _spec(
        "overpriv-buggy",
        "Over-privileged tool (G6 bind): the harness over-grants the unneeded "
        "tool, so the (adversarial) agent can take it -- no_over_privileged_tool "
        "is refuted with a witness (the over-privileged tool taken).",
        buggy=True,
        build=agent_harness.overpriv_build_ir,
        properties=OVERPRIV_PROPS,
        default_property="no_over_privileged_tool",
        protocol="OVERPRIVILEGED"),
    # G6 deadlock bind: the buggy harness makes the two agents wait on each
    # other, reaching a circular-wait state where NO action is enabled -- the
    # system is *stuck* (a genuine deadlock).  TaskEndsOrEscalates is
    # NOT_REACHED (liveness VIOLATED).  This contrasts with the livelock
    # (also liveness-VIOLATED) which is NOT stuck -- it keeps making progress.
    "deadlock-correct": _spec(
        "deadlock-correct",
        "Deadlock (G6 bind): the task is admitted to complete (or be "
        "escalated), so it never reaches a stuck circular-wait state and "
        "TaskEndsOrEscalates is REACHED (the correct implementation).",
        buggy=False,
        build=approval.deadlock_build_ir,
        properties=LIVELOCK_PROPS,
        default_property="task_ends_or_escalates",
        protocol="DEADLOCK"),
    "deadlock-buggy": _spec(
        "deadlock-buggy",
        "Deadlock (G6 bind): the harness never admits completion or "
        "escalation, so the two agents wait on each other and reach a stuck "
        "circular-wait state (no action enabled) -- a genuine deadlock; "
        "TaskEndsOrEscalates is NOT_REACHED (liveness VIOLATED).",
        buggy=True,
        build=approval.deadlock_build_ir,
        properties=LIVELOCK_PROPS,
        default_property="task_ends_or_escalates",
        protocol="DEADLOCK"),
}


def names():
    """Ordered list of registered target names."""
    return ["correct", "buggy", "zab-correct", "zab-buggy",
            "pbft-correct", "pbft-buggy",
            "payment-correct", "payment-buggy",
            "spendcap-correct", "spendcap-buggy",
            "agent-step", "agent-step-buggy",
            "exfil-correct", "exfil-buggy",
            "approval-correct", "approval-buggy",
            "delegation-correct", "delegation-buggy",
            "orchestration-correct", "orchestration-buggy",
            "budget-correct", "budget-buggy",
            "livelock-correct", "livelock-buggy",
            "overpriv-correct", "overpriv-buggy",
            "deadlock-correct", "deadlock-buggy"]


def get(name):
    """Look up a :class:`TargetSpec` by name (raises ``KeyError`` if unknown)."""
    if name not in _REGISTRY:
        raise KeyError("no target %r; have %r" % (name, names()))
    return _REGISTRY[name]


def build(target, n=3):
    """Build the :class:`rot.ir.ProtocolIR` for ``target`` (default 3 nodes)."""
    return get(target).build(int(n))


def list_properties(target):
    """Named invariants that can be pinned for ``target``."""
    return list(get(target).properties)


def get_property(target, prop, n=3):
    """Resolve a named invariant for ``target`` to an :class:`Invariant`."""
    if prop not in get(target).properties:
        raise KeyError("target %r has no property %r; have %r"
                       % (target, prop, list_properties(target)))
    return invariants.get(prop, int(n))


def default_property(target):
    """The invariant pinned by default for ``target``."""
    return get(target).default_property


__all__ = ["TargetSpec", "TWOPC_PROPS", "ZAB_PROPS", "PBFT_PROPS",
           "PAYMENT_PROPS", "SPENDCAP_PROPS", "AGENT_PROPS", "EXFIL_PROPS",
           "APPROVAL_PROPS", "DELEGATION_PROPS", "ORCHESTRATION_PROPS",
           "BUDGET_PROPS",
           "names", "get", "build",
           "list_properties", "get_property", "default_property"]
