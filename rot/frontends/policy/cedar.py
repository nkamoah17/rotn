# -*- coding: utf-8 -*-
"""rot.frontends.policy.cedar -- Cedar policy front-end adapter.

Wraps :func:`rot.frontends.cedar.parse_cedar_file` (Cedar source text ->
``ProtocolIR``) and pins the *policy non-vacuity* property: the policy set
permits at least one concrete request, i.e. some reachable state has
``decision == True``.

Why non-vacuity?  A Cedar policy set that denies every request is useless;
the useful, sound, engine-checkable question is whether the permit set is
realizable over the bounded request space.  The model finder answers it
with ``exists_reachable(decision == True)``:

* ``SAT``  -> the policy permits at least one request  (verdict: **proven**,
  witness is a concrete permitted request);
* ``UNSAT``-> the policy is vacuous, it denies everything (verdict:
  **violated**);
* ``UNKNOWN`` -> the request space exceeded the state budget.

Narrow waist: imports only stdlib, ``rot.ir`` and ``rot.frontends.*``.
Python 3.6 compatible (stdlib only).
"""

import rot.ir as ir
from rot.frontends import cedar as cedar_fe

__all__ = ["build_ir", "PROPERTY_NAME", "PROPERTY_KIND"]

PROPERTY_NAME = "policy_permits_request"
PROPERTY_KIND = "realizability"


def build_ir(policy_path, tools_path=None, n_steps=1):
    """Parse a Cedar policy file and pin the non-vacuity property.

    Parameters
    ----------
    policy_path : str
        Path to a ``.cedar`` policy file.
    tools_path : str or None
        Accepted for a uniform front-end signature; Cedar policies are
        self-contained, so this is only recorded as provenance metadata.
    n_steps : int
        Accepted for a uniform front-end signature; recorded in metadata.

    Returns
    -------
    rot.ir.ProtocolIR
        The Cedar ``ProtocolIR`` with ``pinned_property`` set to
        ``decision == True`` and ``metadata["property_kind"] ==
        "realizability"``.
    """
    model = cedar_fe.parse_cedar_file(policy_path)

    # Pin: "the policy set permits at least one request".
    prop = ir.eq(ir.V("decision"), ir.C(True))
    model.pinned_property = prop
    model.metadata.update({
        "family": "CEDAR_POLICY",
        "property_name": PROPERTY_NAME,
        "property_kind": PROPERTY_KIND,
        "property_description":
            "the policy set permits at least one concrete request "
            "(decision == True in some reachable state)",
        "policy_source": policy_path,
        "tools_source": tools_path,
        "n_steps": int(n_steps),
    })
    model.validate()
    return model