# -*- coding: utf-8 -*-
"""rot.frontends.policy.dw -- the ``.dw`` (Dogwood source) spend-cap front-end.

Turns a hand-written ``.dw`` spend-cap policy (the one shape
:mod:`rot.dw` parses) into a validated ``rot.ir.ProtocolIR`` with the
*safety* property ``spendcap_within_cap`` pinned -- the settled amount plus
the in-flight amount must never exceed the cap (the parallel-fire guarantee).

The parsing and IR construction live in :mod:`rot.dw` (which reuses the
:mod:`rot.spendcap` IR builder -- the single source of truth for the model);
this module only does the narrow-waist front-end work that
:mod:`rot.frontends.policy` is responsible for:

  * routing a ``.dw`` file to the ``spendcap`` family;
  * pinning the safety property and recording the provenance metadata the
    router contract and ``pipeline.py --policy`` report expect
    (``family`` / ``frontend`` / ``property_kind`` / ``property_name`` /
    ``policy_source``);
  * validating the IR before handing it to the soundness core.

It deliberately does **not** re-implement the model or the property: both
come from :mod:`rot.spendcap` (via :mod:`rot.dw`), so the ``.dw`` route and
the ``rot.spendcap`` route are guaranteed to agree.  ``tools_path`` /
``n_steps`` are accepted for a compatible router signature but are unused by
this family (the policy is self-contained and single-service).

Narrow waist: imports only stdlib, ``rot.dw`` and ``rot.spendcap`` (the
model constants) -- never a downstream engine
(``rot.modelfind``, ``rot.cegar``, ``rot.emitter``, ``rot.tlc``).
Python 3.6 compatible.
"""

import os

import rot.dw as dw
import rot.spendcap as spendcap

__all__ = [
    "DwFrontendError",
    "PROPERTY_NAME",
    "PROPERTY_KIND",
    "build_ir",
]

#: The pinned property (matches :func:`rot.invariants.spendcap_within_cap`).
PROPERTY_NAME = "spendcap_within_cap"
#: A ``.dw`` spend-cap policy always pins a safety property.
PROPERTY_KIND = "safety"

#: Map the lowered shape (``rot.lower`` metadata ``protocol``) to the
#: ``(family, property_name)`` the router contract and the pipeline report
#: expect.  The four aggregate shapes all pin a "within-cap" safety invariant;
#: the taint-egress shape pins the ``no_exfiltration`` invariant instead
#: (the thesis's "never contact outsiders after touching confidential data").
_SHAPE = {
    "SPENDCAP": ("SPENDCAP", "spendcap_within_cap"),
    "COUNT_WINDOW": ("SPENDCAP", "spendcap_within_cap"),
    "EXISTS_SUM": ("SPENDCAP", "spendcap_within_cap"),
    "REFUND_BUDGET": ("SPENDCAP", "spendcap_within_cap"),
    "TAINT_EGRESS": ("TAINT_EGRESS", "no_exfiltration"),
}


class DwFrontendError(ValueError):
    """Raised when a ``.dw`` file cannot be lowered into a ProtocolIR."""


def build_ir(policy_path, tools_path=None, n_steps=1, max_inflight=None,
             amount=None, cap=None, window=None):
    """Lower a ``.dw`` spend-cap policy into a validated ``ProtocolIR``.

    Parameters
    ----------
    policy_path : str
        Path to a ``.dw`` spend-cap policy file (the subset ``rot.dw`` parses).
    tools_path : str or None
        Accepted for a compatible router signature; unused (the policy is
        self-contained -- no tools catalog).
    n_steps : int
        Accepted for a compatible router signature; unused (single-service).
    max_inflight : int or None
        ``K`` -- the client-side request-pool bound (the maximum number of
        concurrent in-flight requests the state space can express).  ``None``
        (default) uses :data:`rot.spendcap.MAX_INFLIGHT` (4).  Recorded in
        the IR metadata (``max_inflight``) so reports state the ``K`` a
        verdict was produced under.  See :func:`rot.spendcap.build_ir` for
        how ``K`` interacts with the parallel-fire race (``K = 1`` masks it).
    amount : int or None
        The policy's per-request amount; ``None`` uses
        :data:`rot.spendcap.AMOUNT`.  Threaded into the model.
    cap : int or None
        The policy's cap; ``None`` uses the policy's own cap (or
        :data:`rot.spendcap.CAP` for a document).  Threaded into the model.
    window : int or None
        The temporal window as a bounded event count ``W`` (the model is
        time-free; a ``FormerlyWithin`` window is approximated as "the last
        ``W`` events").  ``None`` uses :data:`rot.spendcap.MAX_WINDOW` (4).
        Recorded in the IR metadata (``window`` / ``dw_window``) so reports
        state the discretization a verdict was produced under.

    Returns
    -------
    rot.ir.ProtocolIR
        A validated IR with ``spendcap_within_cap`` pinned and metadata
        recording the family, front-end, property, and source path.

    Raises
    ------
    DwFrontendError
        If the file is missing, is outside the supported ``.dw`` subset, or
        the lowered IR fails validation.
    """
    if not os.path.isfile(policy_path):
        raise DwFrontendError("policy file not found: %s" % policy_path)

    k = spendcap.MAX_INFLIGHT if max_inflight is None else max_inflight
    w = spendcap.MAX_WINDOW if window is None else window
    # Parse + lowering is owned by rot.dw (rot.spendcap builds the model);
    # this front-end only pins the property and records provenance.
    try:
        model = dw.parse_file(policy_path).to_ir(max_inflight=k,
                                                 amount=amount, cap=cap,
                                                 window=w)
    except dw.DwParseError as exc:
        raise DwFrontendError(str(exc))

    # Stamp the family / property for the *shape* the policy lowered to.  The
    # four aggregate shapes pin a "within-cap" invariant; the taint-egress
    # shape pins ``no_exfiltration``.  Unknown shapes default to the spend-cap
    # contract (the original and most common shape).
    protocol = model.metadata.get("protocol", "SPENDCAP")
    family, property_name = _SHAPE.get(protocol,
                                       ("SPENDCAP", PROPERTY_NAME))
    model.metadata.update({
        "family": family,
        "frontend": "dw",
        "property_kind": PROPERTY_KIND,
        "property_name": property_name,
        "policy_source": os.path.abspath(policy_path),
    })

    errors = model.validate()
    if errors:
        raise DwFrontendError(
            ".dw spend-cap IR failed validation: %s" % "; ".join(errors))
    return model
