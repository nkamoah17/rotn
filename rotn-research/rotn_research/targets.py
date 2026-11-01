# -*- coding: utf-8 -*-
"""Research protocol targets (2PC / ZAB / PBFT / payment / approval family).

These targets were previously defined in ``rot.targets``; after the
product/research split they live here and are re-registered into the shared
``rot.targets`` registry via ``register`` so that ``targets.build("zab-buggy")``
and friends resolve exactly as before.

The product never imports this module.  Research targets reference research
modules (``rotn_research.{twopc,zab,pbft,payment,approval}``) and the product
``TargetSpec`` / ``invariants``.
"""
from rot.targets import TargetSpec          # product (data model)
import rot.invariants as invariants         # product (named invariants)
import rotn_research.twopc as twopc         # research
import rotn_research.zab as zab             # research
import rotn_research.pbft as pbft           # research
import rotn_research.payment as payment     # research
import rotn_research.approval as approval   # research


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


TWOPC_PROPS = ["agreement", "validity", "no_spurious_abort"]
ZAB_PROPS = ["zab_no_premature_apply", "zab_apply_persisted"]
PBFT_PROPS = ["pbft_quorum", "pbft_prepare_before_commit"]
PAYMENT_PROPS = ["no_double_charge", "charge_requires_order",
                 "settle_requires_charge"]
APPROVAL_PROPS = ["no_unapproved_irreversible"]
DELEGATION_PROPS = ["no_privilege_escalation"]
ORCHESTRATION_PROPS = ["no_deadlock", "task_ends_or_escalates"]
BUDGET_PROPS = ["no_runaway_budget"]
LIVELOCK_PROPS = ["task_ends_or_escalates"]


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


# --- register into the shared product registry ---------------------
import rot.targets as _targets
_targets.register("correct", _REGISTRY["correct"])
_targets.register("buggy", _REGISTRY["buggy"])
_targets.register("zab-correct", _REGISTRY["zab-correct"])
_targets.register("zab-buggy", _REGISTRY["zab-buggy"])
_targets.register("pbft-correct", _REGISTRY["pbft-correct"])
_targets.register("pbft-buggy", _REGISTRY["pbft-buggy"])
_targets.register("payment-correct", _REGISTRY["payment-correct"])
_targets.register("payment-buggy", _REGISTRY["payment-buggy"])
_targets.register("approval-correct", _REGISTRY["approval-correct"])
_targets.register("approval-buggy", _REGISTRY["approval-buggy"])
_targets.register("delegation-correct", _REGISTRY["delegation-correct"])
_targets.register("delegation-buggy", _REGISTRY["delegation-buggy"])
_targets.register("orchestration-correct", _REGISTRY["orchestration-correct"])
_targets.register("orchestration-buggy", _REGISTRY["orchestration-buggy"])
_targets.register("budget-correct", _REGISTRY["budget-correct"])
_targets.register("budget-buggy", _REGISTRY["budget-buggy"])
_targets.register("livelock-correct", _REGISTRY["livelock-correct"])
_targets.register("livelock-buggy", _REGISTRY["livelock-buggy"])
_targets.register("deadlock-correct", _REGISTRY["deadlock-correct"])
_targets.register("deadlock-buggy", _REGISTRY["deadlock-buggy"])

__all__ = ['correct', 'buggy', 'zab-correct', 'zab-buggy', 'pbft-correct', 'pbft-buggy', 'payment-correct', 'payment-buggy', 'approval-correct', 'approval-buggy', 'delegation-correct', 'delegation-buggy', 'orchestration-correct', 'orchestration-buggy', 'budget-correct', 'budget-buggy', 'livelock-correct', 'livelock-buggy', 'deadlock-correct', 'deadlock-buggy', 'TWOPC_PROPS', 'ZAB_PROPS', 'PBFT_PROPS', 'PAYMENT_PROPS', 'APPROVAL_PROPS', 'DELEGATION_PROPS', 'ORCHESTRATION_PROPS', 'BUDGET_PROPS', 'LIVELOCK_PROPS']
