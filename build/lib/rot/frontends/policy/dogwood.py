# -*- coding: utf-8 -*-
"""rot.frontends.policy.dogwood -- Dogwood JSON policy front-end adapter.

Dogwood policies are plain JSON.  A ``policy.json`` file carries the
adversarial policy (the ``allowed``/``denied`` action sets), and an
optional ``tools.json`` carries the catalog of tools the agent actually has.

``policy.json``::

    {"allowed": ["read_log", "update_balance"],
     "denied":  ["exfiltrate_secret"]}

``allowed`` / ``denied`` are lists of action-name strings that must be
disjoint (enforced by :class:`rot.ir.AdversarialPolicy`).

``tools.json``::

    {"tools": [{"name": "read_log",
                "description": "read the application log"}]}

Each tool is an object with a required ``name`` and optional
``description``.  The catalog is descriptive provenance: it is cross-checked
against the policy (an action named by the policy but absent from the catalog
is recorded in the IR metadata so a report can flag it), but it does not
change the model.

The adapter builds the *conforming* AgentStep model -- exactly the
``agent_step.build_ir(buggy=False, policy=P)`` construction, but with the
policy loaded from a file and the IR restricted to ``rot.ir`` so it stays on
the front-end side of the narrow waist.  It pins the *policy conformance*
safety property: the conforming agent never takes a denied action.  The model
finder answers it with ``forall_reachable``: ``True`` -> conformance holds
(verdict: **proven**); ``False`` -> a denied action is reachable (verdict:
**violated**); ``UNKNOWN`` -> the state budget was exhausted.

Narrow waist: imports only stdlib and ``rot.ir``.  Python 3.6 compatible.
"""

import json

import rot.ir as ir

PROPERTY_NAME = "policy_conformance"
PROPERTY_KIND = "safety"


class DogwoodFrontendError(ValueError):
    """Raised when a Dogwood policy or tools file is malformed."""


class Tool(object):
    """A single entry in a Dogwood tools catalog.

    ``name`` is the action the tool performs (must match the action names in
    the policy).  ``description`` is free text, carried into IR metadata for
    reporting.
    """

    __slots__ = ("name", "description")

    def __init__(self, name, description=""):
        self.name = name
        self.description = description

    def __repr__(self):
        return "Tool(%r)" % (self.name,)


def _read_json(path, what):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (IOError, OSError) as exc:
        raise DogwoodFrontendError("could not read %s file %r: %s"
                                   % (what, path, exc))
    except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
        raise DogwoodFrontendError("malformed JSON in %s file %r: %s"
                                   % (what, path, exc))


def _action_list(data, key, what):
    if key not in data:
        raise DogwoodFrontendError("%s file missing required key %r"
                                   % (what, key))
    raw = data[key]
    if not isinstance(raw, list):
        raise DogwoodFrontendError(
            "%s file: %r must be a list of action-name strings" % (what, key))
    out = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise DogwoodFrontendError(
                "%s file: %r must contain non-empty action-name strings, "
                "got %r" % (what, key, item))
        out.append(item)
    return out


def parse_policy(policy_path):
    """Parse a Dogwood ``policy.json`` into an ``AdversarialPolicy``."""
    data = _read_json(policy_path, "policy")
    if not isinstance(data, dict):
        raise DogwoodFrontendError(
            "policy file must be a JSON object with 'allowed' and 'denied'")
    allowed = _action_list(data, "allowed", "policy")
    denied = _action_list(data, "denied", "policy")
    # AdversarialPolicy rejects overlapping allowed/denied sets.
    return ir.AdversarialPolicy(allowed=allowed, denied=denied)


def parse_tools(tools_path):
    """Parse a Dogwood ``tools.json`` into an ordered ``name -> Tool`` map."""
    data = _read_json(tools_path, "tools")
    if not isinstance(data, dict) or "tools" not in data:
        raise DogwoodFrontendError(
            "tools file must be a JSON object with a 'tools' list")
    raw = data["tools"]
    if not isinstance(raw, list):
        raise DogwoodFrontendError("tools file: 'tools' must be a list")
    tools = {}
    for item in raw:
        if not isinstance(item, dict) or "name" not in item:
            raise DogwoodFrontendError(
                "tools file: each tool must be an object with a 'name'")
        name = item["name"]
        if not isinstance(name, str) or not name:
            raise DogwoodFrontendError(
                "tools file: tool 'name' must be a non-empty string")
        desc = item.get("description", "")
        if not isinstance(desc, str):
            raise DogwoodFrontendError(
                "tools file: tool 'description' must be a string")
        tools[name] = Tool(name, desc)
    return tools


def policy_conformance_property(policy):
    """The safety predicate: the agent never chooses a denied action.

    Returns an ``Expr`` over the ``decision`` state variable equivalent to
    ``decision not-in policy.denied`` -- i.e. ``AND_{d in denied} decision != d``.
    When ``denied`` is empty the predicate is trivially true (``ir.T()``).

    Reimplemented here on the front-end side (mirroring
    ``rot.agent_step.policy_conformance_property``) so this module keeps the
    narrow waist -- it imports only ``rot.ir``.
    """
    if not policy.denied:
        return ir.T()
    return ir.And(*[ir.neq(ir.V("decision"), ir.C(d)) for d in policy.denied])


def build_ir(policy_path, tools_path=None, n_steps=1):
    """Parse a Dogwood policy (+ optional tools) and build a ``ProtocolIR``.

    The model mirrors the *conforming* ``AgentStep`` vertical slice
    (``rot.agent_step.build_ir(buggy=False)``), lowered here on the front-end
    side so this module keeps the narrow waist (imports only ``rot.ir``).

    The agent chooses one action each step from the policy's universe
    (``allowed union denied``).  Because the agent is *conforming*, every
    denied action is policy-enforced: its transition is guarded to be never-
    enabled (``ir.F()``), so a denied action is unreachable and the
    ``policy_conformance`` safety property holds in every reachable state.

    Parameters
    ----------
    policy_path : str
        Path to the Dogwood policy file (JSON with ``allowed``/``denied``).
    tools_path : str or None
        Optional path to a tools file (JSON ``{"tools": [...]}``).  Tool
        descriptions are recorded as provenance; the decision domain is the
        policy's ``allowed union denied``.
    n_steps : int
        Bounded step count (recorded in metadata; the AgentStep slice is
        single-actor so it does not change the model).

    Returns
    -------
    rot.ir.ProtocolIR
        A validated ``ProtocolIR`` with ``policy_conformance`` pinned and
        metadata recording ``property_kind="safety"`` and the source paths.
    """
    policy = parse_policy(policy_path)
    tools = parse_tools(tools_path) if tools_path else None

    universe = sorted(policy.allowed | policy.denied)

    decision = ir.StateVar(
        "decision",
        ir.Enum(["idle"] + universe),
        mode=ir.MODE_EXISTENTIAL,
        owner="agent",
        desc="the action the agent chose this step (existential choice)",
    )

    acts = [
        ir.Action(
            "agent_init",
            "agent",
            is_initial=True,
            effects=[("decision", ir.C("idle"))],
        )
    ]
    for a in universe:
        # Conforming agent: the policy enforces the denial -- the transition
        # to a denied action is never-enabled, so conformance holds.
        guard = ir.F() if a in policy.denied \
            else ir.eq(ir.V("decision"), ir.C("idle"))
        acts.append(
            ir.Action(
                "agent_take_%s" % a,
                "agent",
                guard=guard,
                effects=[("decision", ir.C(a))],
            )
        )

    metadata = {
        "family": "AGENT_STEP",
        "frontend": "dogwood",
        "buggy": False,
        "n": int(n_steps),
        "property_name": PROPERTY_NAME,
        "property_kind": PROPERTY_KIND,
        "denied": sorted(policy.denied),
        "allowed": sorted(policy.allowed),
        "policy_source": str(policy_path),
        "tools_source": str(tools_path) if tools_path else "",
    }
    if tools is not None:
        metadata["tool_names"] = [
            t.name for t in sorted(tools.values(), key=lambda x: x.name)
        ]

    model = ir.ProtocolIR(
        name="agent-step",
        variables=[decision],
        actions=acts,
        init=ir.T(),
        pinned_property=policy_conformance_property(policy),
        policy=policy,
        metadata=metadata,
    )
    model.validate()
    return model


__all__ = [
    "Tool",
    "DogwoodFrontendError",
    "PROPERTY_NAME",
    "PROPERTY_KIND",
    "parse_policy",
    "parse_tools",
    "policy_conformance_property",
    "build_ir",
]
