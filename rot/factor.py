# -*- coding: utf-8 -*-
"""factor.py -- the 3-factor decomposition lens over the IR (GSSM §III).

This is the **second lift** (the *general state space*, ``§2.6``) of the
Joern-primary rework (``docs/joern-primary-ab-plan.md``).  GSSM (Lü, 2022)
frames a protocol model as a **factor graph**; the ``LinearModel`` chain
(ordered actions over one unified state) is the *Kalman-filter special case*.
The factor-graph view keeps the structure the chain flattens away, and the
first thing it names is the **3-factor decomposition** every state-space model
has:

  * **Prior factor**          ``p(x0)``           = the ``init`` action.
  * **Between factor**        ``p(x_{k+1}|x_k)``  = the transition ``actions``.
  * **Measurement factor**    ``p(y_{k+1}|x_{k+1})`` = the ``pinned_property``.

This module is a **pure lens** over :mod:`rot.ir`: it *views* a
:class:`rot.ir.ProtocolIR` through the three factors and exposes each factor's
support (which variables / actions it touches) so the objective A/B
(``rot.ab``) can score **per-factor fidelity** (prior / between / measurement)
separately.

**Zero behavior change.**  The lens only *reads* the IR -- it never mutates it,
never re-derives it, and is not on any engine's code path.  Importing and
calling this module changes nothing about how the protocol is verified.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from .ir import ProtocolIR

#: ``p(x0)`` -- the prior (the init action / initial state).
PRIOR = "prior"
#: ``p(x_{k+1} | x_k)`` -- the between factor (the transition actions / delta).
BETWEEN = "between"
#: ``p(y_{k+1} | x_{k+1})`` -- the measurement (the pinned property / query).
MEASUREMENT = "measurement"


class Factor(object):
    """One factor of the 3-factor decomposition.

    A factor is a *view* over a :class:`rot.ir.ProtocolIR`: it names one of the
    three roles (prior / between / measurement) and exposes the IR material that
    plays that role.  It never modifies the IR.
    """

    #: The factor kind (overridden: PRIOR / BETWEEN / MEASUREMENT).
    kind = None

    def __init__(self, ir):
        self.ir = ir

    def to_dict(self):
        raise NotImplementedError


class PriorFactor(Factor):
    """``p(x0)`` -- the prior: the ``init`` action (the initial state)."""

    kind = PRIOR

    def __init__(self, ir):
        super(PriorFactor, self).__init__(ir)
        self.action = self._find_init_action(ir)

    @staticmethod
    def _find_init_action(ir):
        for a in ir.actions:
            if a.is_initial:
                return a
        return None

    def written_vars(self):
        """The state variables the prior establishes (the init effect targets)."""
        if self.action is None:
            return []
        return sorted(e.var for e in self.action.effects if e.var != "pc")

    def to_dict(self):
        return {
            "kind": self.kind,
            "action": self.action.name if self.action is not None else None,
            "written_vars": self.written_vars(),
        }


class BetweenFactor(Factor):
    """``p(x_{k+1} | x_k)`` -- the between factor: the transition actions (delta).

    In the chain (the Kalman special case) these are ordered into a sequence;
    in the general factor graph they are the edges of the multi-connected graph.
    """

    kind = BETWEEN

    def actions(self):
        """The transition (non-initial) actions -- the dynamics ``delta``."""
        return [a for a in self.ir.actions if not a.is_initial]

    def to_dict(self):
        acts = self.actions()
        return {
            "kind": self.kind,
            "n_actions": len(acts),
            "action_names": [a.name for a in acts],
        }


class MeasurementFactor(Factor):
    """``p(y_{k+1} | x_{k+1})`` -- the measurement: the pinned property (query)."""

    kind = MEASUREMENT

    def expression(self):
        """The pinned property expression (the observation)."""
        return self.ir.pinned_property

    def free_vars(self):
        """The state variables the measurement references (its support)."""
        return self.ir.vars_in(self.expression())

    def to_dict(self):
        return {
            "kind": self.kind,
            "free_vars": self.free_vars(),
        }


class FactorDecomposition(object):
    """The 3-factor decomposition (prior / between / measurement) of one IR.

    The same ``ProtocolIR`` read as a product of the three factors.  Pure view:
    constructing it does not touch the IR.
    """

    def __init__(self, ir):
        self.ir = ir
        self.prior = PriorFactor(ir)
        self.between = BetweenFactor(ir)
        self.measurement = MeasurementFactor(ir)

    def factors(self):
        """The three factors, in the canonical prior / between / measurement order."""
        return [self.prior, self.between, self.measurement]

    def factor(self, kind):
        """Look up a factor by PRIOR / BETWEEN / MEASUREMENT."""
        for f in self.factors():
            if f.kind == kind:
                return f
        raise KeyError("unknown factor kind %r" % (kind,))

    def to_dict(self):
        return {
            "prior": self.prior.to_dict(),
            "between": self.between.to_dict(),
            "measurement": self.measurement.to_dict(),
        }


def decompose(ir):
    """The 3-factor decomposition of a :class:`rot.ir.ProtocolIR`.

    Returns a :class:`FactorDecomposition` exposing the prior / between /
    measurement factors.  Pure lens: it only reads ``ir`` and never modifies it
    (zero behavior change -- the A/B uses it to score per-factor fidelity without
    altering the model that is verified).
    """
    if not isinstance(ir, ProtocolIR):
        raise TypeError("decompose expects a ProtocolIR, got %r" % (type(ir),))
    return FactorDecomposition(ir)


__all__ = [
    "PRIOR", "BETWEEN", "MEASUREMENT",
    "Factor", "PriorFactor", "BetweenFactor", "MeasurementFactor",
    "FactorDecomposition", "decompose",
]
