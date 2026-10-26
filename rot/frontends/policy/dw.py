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


class DwFrontendError(ValueError):
    """Raised when a ``.dw`` file cannot be lowered into a ProtocolIR."""


def build_ir(policy_path, tools_path=None, n_steps=1, max_inflight=None,
             amount=None, cap=None):
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
    # Parse + lowering is owned by rot.dw (rot.spendcap builds the model);
    # this front-end only pins the property and records provenance.
    try:
        model = dw.parse_file(policy_path).to_ir(max_inflight=k,
                                                 amount=amount, cap=cap)
    except dw.DwParseError as exc:
        raise DwFrontendError(str(exc))

    model.metadata.update({
        "family": "SPENDCAP",
        "frontend": "dw",
        "property_kind": PROPERTY_KIND,
        "property_name": PROPERTY_NAME,
        "policy_source": os.path.abspath(policy_path),
    })

    errors = model.validate()
    if errors:
        raise DwFrontendError(
            ".dw spend-cap IR failed validation: %s" % "; ".join(errors))
    return model
