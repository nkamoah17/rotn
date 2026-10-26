# -*- coding: utf-8 -*-
"""agent_step_liveness.py -- agent-step *bounded-liveness* front-end (policy JSON -> ``ProtocolIR``).

This is the liveness twin of :mod:`rot.frontends.policy.dogwood`.  Both
front-ends build the *same* agent-step model (one ``decision`` state variable
and one action per policy action, where the policy's ``allowed`` / ``denied``
sets decide which transitions are enabled).  They differ only in the property
they pin:

* ``dogwood`` pins the safety property ``policy_conformance`` -- the agent
  never takes a denied action.
* this module pins the bounded-liveness property ``bounded_eventually`` --
  within the horizon the agent commits to a concrete action (i.e. it is not
  stuck).

The model is built by re-using the Dogwood front-end (the same agent-step
model); only the pinned property and the ``property_kind`` metadata differ.
The bounded check itself is the existing machinery
(``rot.symbolic.SymbolicEngine.reach_within`` + ``rot.cegar.cegar_liveness``),
which this front-end deliberately does NOT re-invent: a front-end's only job
is to produce a ``ProtocolIR`` (the narrow waist), and the pipeline dispatches
liveness properties to the bounded engine.

Narrow waist: this module imports only the IR (``rot.ir``) and its own
package (the sibling ``dogwood`` front-end) -- never a downstream engine.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import rot.ir as ir
from rot.frontends.policy import dogwood

__all__ = ["PolicyFrontendError", "build_ir"]


class PolicyFrontendError(Exception):
    """Raised when the agent-step liveness front-end cannot build an IR."""


def _liveness_goal():
    """The bounded-liveness goal: ``decision != idle`` (the agent acts)."""
    return ir.neq(ir.V("decision"), ir.C("idle"))


def build_ir(policy_path, tools_path=None, n=1, goal=None):
    """Build the agent-step model and pin the bounded-liveness property.

    ``policy_path`` is the JSON policy (the same shape the Dogwood front-end
    understands); ``tools_path`` is optional; ``n`` is the agent-step width
    (kept for a compatible signature); ``goal`` may override the liveness
    goal.

    The returned ``ProtocolIR`` has ``metadata["property_kind"] ==
    "liveness"``, ``metadata["property_name"] == "bounded_eventually"`` and
    ``pinned_property == decision != idle``.  Hand it to the existing
    bounded-liveness machinery (``cegar_liveness`` / ``reach_within``) for the
    verdict -- do not re-implement the bounded engine here.
    """
    try:
        base = dogwood.build_ir(policy_path, tools_path, int(n or 1))
    except dogwood.DogwoodFrontendError as exc:
        raise PolicyFrontendError(str(exc))
    base.pinned_property = goal if goal is not None else _liveness_goal()
    base.metadata["frontend"] = "agent_step_liveness"
    base.metadata["property_kind"] = "liveness"
    base.metadata["property_name"] = "bounded_eventually"
    errors = base.validate()
    if errors:
        raise PolicyFrontendError("agent-step liveness IR invalid: %r" % (errors,))
    return base
