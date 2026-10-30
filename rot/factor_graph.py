# -*- coding: utf-8 -*-
"""factor_graph.py -- the multi-connected + distributed view over a ProtocolIR.

This is the **second lift** (the *general state space*, ``§2.6``) of the
Joern-primary rework (``docs/joern-primary-ab-plan.md``).  GSSM (Lü, 2022)
frames a protocol model as a **factor graph**: the ``LinearModel`` chain
(ordered actions over one unified state) is the *Kalman-filter special case*,
and the general state space keeps the structure the chain drops.  This module
is the **multi-connected (3a)** + **distributed (3b)** half of that lift:

  * **Multi-connected graph.**  A 2PC protocol is *not* a chain -- it is *two*
    sides, the **coordinator ∥ participants**, joined by message / channel
    edges.  :func:`build_factor_graph` recovers that structure from the IR by
    grouping the actions and state variables by their ``owner`` (the process
    that owns them) and surfacing the shared variables as the connections.
  * **Distributed, not unified.**  Instead of one unified state vector, the
    state space is the **product of local factor graphs** (one per component)
    **+ the connection factors** (the channels).  :class:`FactorGraph` is that
    product construction; :func:`rot.env.distributed_view` builds it from a
    list of self-contained IR fragments.

The **``LinearModel`` chain remains the sound special-case fallback**: when the
protocol is a single process (one owner), the factor graph degenerates to a
chain (``FactorGraph.is_chain`` is True) and the ordered-action engine applies
exactly as before.  Nothing here changes how the chain is verified -- it only
makes the *structure* visible.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from .ir import ProtocolIR


class Component(object):
    """A local factor graph (one process / component of the protocol).

    A component owns a set of :class:`rot.ir.Action` (the actions it performs)
    and a set of :class:`rot.ir.StateVar` (the state it holds).  The whole
    protocol is the product of its components joined by the channel factors.
    """

    def __init__(self, name, owner, actions, variables):
        self.name = name
        self.owner = owner
        self.actions = list(actions)      # Action list owned by this component
        self.variables = list(variables)  # StateVar list owned by this component

    def action_names(self):
        return [a.name for a in self.actions]

    def variable_names(self):
        return [v.name for v in self.variables]

    def to_dict(self):
        return {
            "name": self.name,
            "owner": self.owner,
            "action_names": self.action_names(),
            "variable_names": self.variable_names(),
        }


class ChannelFactor(object):
    """A connection factor (a channel / message mediating between components).

    A channel factor is the *connection* between two components: the shared
    state variable(s) that one component writes and another reads (the
    coordinator's decision, the phase, the votes).  In the factor-graph view
    these are the edges that join the local factor graphs.
    """

    def __init__(self, name, from_component, to_component, variables):
        self.name = name
        self.from_component = from_component
        self.to_component = to_component
        self.variables = list(variables)  # the shared var(s) that mediate it

    def to_dict(self):
        return {
            "name": self.name,
            "from": self.from_component,
            "to": self.to_component,
            "variables": self.variables,
        }


class FactorGraph(object):
    """The multi-connected + distributed view of a protocol model.

    The protocol is the **product** of its :class:`Component` local factor
    graphs, joined by the :class:`ChannelFactor` connection factors.  When the
    protocol is a single process (``is_chain`` is True) this *is* the
    ``LinearModel`` chain -- the sound special-case fallback.
    """

    def __init__(self, ir, components, channels, is_chain=False):
        self.ir = ir                        # the source ProtocolIR (or None)
        self.components = list(components)  # Component list (local factor graphs)
        self.channels = list(channels)      # ChannelFactor list (the connections)
        self.is_chain = bool(is_chain)      # True iff this degenerates to a chain

    def component(self, name):
        """Look up a :class:`Component` by name (None if absent)."""
        for c in self.components:
            if c.name == name:
                return c
        return None

    def component_names(self):
        return [c.name for c in self.components]

    def channel_names(self):
        return [c.name for c in self.channels]

    def to_dict(self):
        return {
            "n_components": len(self.components),
            "n_channels": len(self.channels),
            "is_chain": self.is_chain,
            "components": [c.to_dict() for c in self.components],
            "channels": [ch.to_dict() for ch in self.channels],
        }


def _touched_by_owner(ir):
    """Map each state variable name to the set of owners that read or write it.

    A variable is "touched" by an action if it is the action's effect target,
    appears in the action's guard, or appears in an effect expression.  The map
    is what lets :func:`build_factor_graph` find the *shared* variables -- the
    ones that more than one component touches, i.e. the connections (channels).
    """
    touched = {}
    for a in ir.actions:
        names = set()
        for e in a.effects:
            if e.var != "pc":
                names.add(e.var)
        for n in ir.vars_in(a.guard):
            names.add(n)
        for e in a.effects:
            for n in ir.vars_in(e.expr):
                names.add(n)
        for n in names:
            touched.setdefault(n, set()).add(a.owner)
    return touched


def build_factor_graph(ir):
    """Build the multi-connected + distributed view of a :class:`ProtocolIR`.

    * **Components** are the protocol's processes: the actions and state
      variables grouped by their ``owner`` (e.g. the 2PC ``coordinator`` and
      the ``participant_i`` processes).
    * **Channel factors** are the state variables *shared* across more than one
      component (touched by actions of different owners) -- the coordinator's
      ``decision`` / ``phase`` that the participants read are the 2PC channels.

    The ``LinearModel`` chain is the sound special-case fallback: when the IR
    has a single owner, the result has one component and ``is_chain`` is True.
    """
    if not isinstance(ir, ProtocolIR):
        raise TypeError("build_factor_graph expects a ProtocolIR, got %r" % (type(ir),))

    actions_by_owner = {}
    for a in ir.actions:
        actions_by_owner.setdefault(a.owner, []).append(a)
    vars_by_owner = {}
    for v in ir.variables:
        vars_by_owner.setdefault(v.owner, []).append(v)

    owners = sorted(set(list(actions_by_owner.keys()) + list(vars_by_owner.keys())))
    components = [
        Component(
            name=owner,
            owner=owner,
            actions=actions_by_owner.get(owner, []),
            variables=vars_by_owner.get(owner, []),
        )
        for owner in owners
    ]

    # Channel factors: the variables shared across >1 component are the
    # connections (the coordinator <-> participant channels).
    touched = _touched_by_owner(ir)
    channels = []
    for varname in sorted(touched):
        owners_touching = touched[varname]
        if len(owners_touching) > 1:
            ordered = sorted(owners_touching)
            channels.append(ChannelFactor(
                name="channel_" + varname,
                from_component=ordered[0],
                to_component=ordered[1],
                variables=[varname],
            ))

    return FactorGraph(ir, components, channels, is_chain=(len(components) <= 1))


__all__ = ["Component", "ChannelFactor", "FactorGraph", "build_factor_graph"]
