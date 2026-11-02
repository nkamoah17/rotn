# -*- coding: utf-8 -*-
"""targets.py -- registry of verifiable targets for the product plane.

The pipeline is target-agnostic: it receives a target name, resolves the
concrete ProtocolIR to build, and the set of named invariants that can be
pinned for it.  Each target ships a correct and a buggy variant that share
state and actions and differ only in a seeded decision rule:

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

  AgentStep (rot.agent_step) -- the adversarial-agent conformance pair:
    * ``agent-step``       -- a conforming agent never takes an action denied
      by its policy (``policy_conformance`` holds).
    * ``agent-step-buggy`` -- a compromised/mis-configured agent is free to
      attempt a denied action (``policy_conformance`` breaks).
    Both expose: ``policy_conformance``, ``bounded_eventually``.

  Exfiltration (rot.agent_harness, NoExfiltration) -- the lethal-trifecta
  data-flow guard:
    * ``exfil-correct`` -- the policy denies an unapproved send while the
      agent holds private data (``no_exfiltration`` holds).
    * ``exfil-buggy``   -- the policy admits an unapproved send even while
      the agent holds private data (``no_exfiltration`` breaks).
    Both expose: ``no_exfiltration``.

  Over-privilege (rot.agent_harness, NoOverPrivilegedTool) -- the model-
  checked over-grant:
    * ``overpriv-correct`` -- the harness denies the unneeded tool
      (``no_over_privileged_tool`` holds).
    * ``overpriv-buggy``   -- the harness over-grants the unneeded tool, so
      the (adversarial) agent can take it (``no_over_privileged_tool``
      refuted with a witness).
    Both expose: ``no_over_privileged_tool``.

The protocol-plane and governance-plane targets (2PC, ZAB, PBFT, payment
composition, approval/delegation, orchestration liveness) live in the
research plane -- the ``rotn_research`` package (the ``rotn-research``
repository), which extends this registry (see ``rotn_research.targets``).

Adding a new target is a registration of a builder that returns a ProtocolIR
plus its property list -- nothing else in the pipeline needs to change.
Pure stdlib, Python 3.6 compatible.
"""

import rot.invariants as invariants
import rot.spendcap as spendcap
import rot.agent_step as agent_step
import rot.agent_harness as agent_harness


class TargetSpec(object):
    """A named, buildable verification target.

    ``protocol`` is a short human-facing family name (e.g. "SPENDCAP",
    "EXFILTRATION") used for report titles/labels.
    """

    def __init__(self, name, description, build, properties, default_property,
                 protocol="POLICY"):
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
AGENT_PROPS = ["policy_conformance", "bounded_eventually"]
SPENDCAP_PROPS = ["spendcap_within_cap"]
EXFIL_PROPS = ["no_exfiltration"]
# G6 over-privileged tool bind (model-checked over-grant).
OVERPRIV_PROPS = ["no_over_privileged_tool"]


def _spec(name, description, buggy, build, properties, default_property,
          protocol="POLICY"):
    return TargetSpec(
        name=name,
        description=description,
        build=lambda n: build(n=n, buggy=buggy),
        properties=list(properties),
        default_property=default_property,
        protocol=protocol,
    )


_REGISTRY = {
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
}


def names():
    """Ordered list of registered target names.

    Dynamic: includes any research targets added via :func:`register`
    (e.g. ZAB/PBFT/payment/approval from ``rotn_research``).
    """
    return sorted(_REGISTRY)


def get(name):
    """Look up a :class:`TargetSpec` by name (raises ``KeyError`` if unknown)."""
    if name not in _REGISTRY:
        raise KeyError("no target %r; have %r" % (name, names()))
    return _REGISTRY[name]


def register(name, spec):
    """Register a target under ``name`` (extension point).

    Research packages (``rotn_research``) use this to add their targets
    (e.g. ZAB/PBFT/payment/approval) to the shared registry without the
    product importing any research module.  They resolve only once the
    research package has been imported (which re-registers them here).
    """
    _REGISTRY[name] = spec
    return spec


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


__all__ = ["TargetSpec", "AGENT_PROPS", "SPENDCAP_PROPS", "EXFIL_PROPS",
           "OVERPRIV_PROPS",
           "names", "get", "register", "build",
           "list_properties", "get_property", "default_property"]
