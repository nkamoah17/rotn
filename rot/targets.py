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
}


def names():
    """Ordered list of registered target names."""
    return ["correct", "buggy", "zab-correct", "zab-buggy",
            "pbft-correct", "pbft-buggy",
            "payment-correct", "payment-buggy",
            "spendcap-correct", "spendcap-buggy",
            "agent-step", "agent-step-buggy",
            "exfil-correct", "exfil-buggy"]


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
           "names", "get", "build",
           "list_properties", "get_property", "default_property"]
