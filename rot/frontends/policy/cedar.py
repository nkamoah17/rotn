# -*- coding: utf-8 -*-
"""rot.frontends.policy.cedar -- Cedar policy front-end adapter.

Wraps :func:`rot.frontends.cedar.parse_cedar_file` (Cedar source text ->
``ProtocolIR``) and pins one of the two *twin* policy properties that make
Cedar a real verifier:

* ``kind="realizability"`` (default) -- **non-vacuity**: the policy set
  permits at least one concrete request, i.e. some reachable state has
  ``decision == True``.  The model finder answers it with
  ``exists_reachable(decision == True)``:

  * ``SAT``  -> the policy permits at least one request  (verdict: **proven**,
    witness is a concrete permitted request);
  * ``UNSAT``-> the policy is vacuous, it denies everything (verdict:
    **violated**);
  * ``UNKNOWN`` -> the request space exceeded the state budget.

* ``kind="safety"`` -- **forbid-holds / no over-granting**: every forbidden
  request is denied, i.e. in *every* reachable state
  ``forbidden -> not decision`` (a matching ``forbid`` rule implies the
  verdict is Deny).  The model finder answers it with
  ``forall_reachable(not forbidden or not decision)`` over the whole bounded
  request space (principal x action x resource x attribute values):

  * ``True``    -> no forbidden request is permitted (verdict: **proven**);
  * ``False``   -> a forbidden request *is* permitted (verdict: **violated**,
    witness is that over-granted request);
  * ``UNKNOWN`` -> the request space exceeded the state budget.

The two are complementary directions of the same bounded sweep: one is the
*existential* (realizability) twin, the other the *universal* (safety) twin.

Narrow waist: imports only stdlib, ``rot.ir`` and ``rot.frontends.*``.
Python 3.6 compatible (stdlib only).
"""

import rot.ir as ir
from rot.frontends import cedar as cedar_fe

__all__ = [
    "build_ir",
    "CedarFrontendError",
    "PROPERTY_NAME",
    "PROPERTY_KIND",
    "SAFETY_PROPERTY_NAME",
    "SAFETY_PROPERTY_KIND",
    "policy_permits_request_property",
    "policy_denies_forbidden_property",
]

# --- Non-vacuity (realizability) twin: the policy permits >= 1 request. ------
PROPERTY_NAME = "policy_permits_request"
PROPERTY_KIND = "realizability"

# --- Safety (universal): forbid rules hold / permit rules don't over-grant. --
SAFETY_PROPERTY_NAME = "policy_denies_forbidden"
SAFETY_PROPERTY_KIND = "safety"

_KINDS = (PROPERTY_KIND, SAFETY_PROPERTY_KIND)


class CedarFrontendError(ValueError):
    """Raised when a Cedar policy cannot be pinned to the requested kind."""


def policy_permits_request_property():
    """The non-vacuity predicate: ``decision == True``.

    Checked with ``exists_reachable`` -- SAT means the policy set permits at
    least one concrete request (it is not vacuous).
    """
    return ir.eq(ir.V("decision"), ir.C(True))


def policy_denies_forbidden_property():
    """The safety predicate: ``forbidden -> not decision``.

    Checked with ``forall_reachable`` over the whole bounded request space --
    for *every* reachable request, if a ``forbid`` rule matches (``forbidden``
    is True) then the verdict is Deny (``decision`` is False).  This is the
    "forbid rules hold / permit rules don't over-grant" direction that a
    realizability-only (``exists``) query cannot express.
    """
    return ir.Or(ir.Not(ir.V("forbidden")), ir.Not(ir.V("decision")))


def build_ir(policy_path, tools_path=None, n_steps=1, kind=None):
    """Parse a Cedar policy file and pin a policy property.

    Two properties are available (the "twin" pair that makes Cedar a real
    verifier):

    * ``kind="realizability"`` (default) -- ``policy_permits_request``: the
      policy permits at least one concrete request (``decision == True`` in
      some reachable state; an ``exists`` query).
    * ``kind="safety"`` -- ``policy_denies_forbidden``: every forbidden
      request is denied (``forbidden -> not decision`` in *every* reachable
      state; a ``forall`` query over the bounded request space).

    Parameters
    ----------
    policy_path : str
        Path to a ``.cedar`` policy file.
    tools_path : str or None
        Accepted for a uniform front-end signature; Cedar policies are
        self-contained, so this is only recorded as provenance metadata.
    n_steps : int
        Accepted for a uniform front-end signature; recorded in metadata.
    kind : str or None
        ``"realizability"`` (default) or ``"safety"``.

    Returns
    -------
    rot.ir.ProtocolIR
        The Cedar ``ProtocolIR`` with ``pinned_property`` and
        ``metadata["property_kind"]`` set to the requested property.
    """
    if kind is None:
        kind = PROPERTY_KIND
    kind = str(kind).lower()
    if kind not in _KINDS:
        raise CedarFrontendError(
            "unknown property kind %r for a Cedar policy (expected one of "
            "realizability, safety)" % (kind,))

    model = cedar_fe.parse_cedar_file(policy_path)

    if kind == SAFETY_PROPERTY_KIND:
        prop = policy_denies_forbidden_property()
        name, knd = SAFETY_PROPERTY_NAME, SAFETY_PROPERTY_KIND
        desc = ("every forbidden request is denied (forbidden -> not "
                "decision, in every reachable state)")
    else:
        prop = policy_permits_request_property()
        name, knd = PROPERTY_NAME, PROPERTY_KIND
        desc = ("the policy set permits at least one concrete request "
                "(decision == True in some reachable state)")

    model.pinned_property = prop
    model.metadata.update({
        "family": "CEDAR_POLICY",
        "property_name": name,
        "property_kind": knd,
        "property_description": desc,
        "policy_source": policy_path,
        "tools_source": tools_path,
        "n_steps": int(n_steps),
    })
    model.validate()
    return model