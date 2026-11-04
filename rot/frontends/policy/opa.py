# -*- coding: utf-8 -*-
"""rot.frontends.policy.opa -- the ``.rego`` (OPA / Rego) STUB front-end.

Positioning (Phase 4): ROTN is the *neutral checker* across policy
languages.  This module proves that claim for OPA's Rego without building
a Rego engine: it is a **stub** that recognises the *canonical Rego
encoding* of a supported policy shape and lowers it to the **same**
``rot.ir.ProtocolIR`` the Dogwood front-end produces for the equivalent
``.dw`` policy.  ``ProtocolIR.__eq__`` ignores ``metadata``, so "the same
IR" is a structural assertion -- the two front-ends differ only in
provenance (``frontend`` / ``policy_source``), and the verdict decided on
that IR is identical by construction.

What the stub is, and is not
----------------------------
* **is**: a shape-recognition adapter.  A ``.rego`` policy carries a small
  set of ``# rotn:<key>=<value>`` annotations (``shape``, ``variant``,
  optionally ``amount`` / ``cap``) that name the canonical encoding it
  instantiates; the stub validates a minimal Rego skeleton (a ``package``
  declaration and at least one rule body) and then delegates the *model*
  to the single source of truth -- the same oracles the ``.dw`` route
  uses (:func:`rot.spendcap.build_ir` for the spend-cap shape,
  :func:`rot.shapes.build_approval_replay_ir` for the approval-replay
  shape).
* **is not**: a Rego interpreter.  The rule bodies are the human/AI-
  readable draft; the semantics the verdict is decided on come from the
  oracle the shape lowers to.  Building a full Rego -> IR lowering is
  deliberately out of scope (the audit's "freeze everything else"
  guidance): the point is the neutral waist, not another language engine.

Supported shapes (Phase 4 stub set)
-----------------------------------
* ``spendcap``        -- APW-1, the settled-sum spend cap
  (property ``spendcap_within_cap``);
* ``approval_replay`` -- APW-2, the single-use approval
  (property ``approval_single_use``).

Narrow waist: imports only stdlib, ``rot.spendcap`` and ``rot.shapes``
(the oracle builders -- the same modules the ``.dw`` front-end uses) --
never a downstream engine (``rot.modelfind``, ``rot.cegar``,
``rot.emitter``, ``rot.tlc``).  Python 3.6 compatible.
"""

import os
import re

import rot.spendcap as spendcap
import rot.shapes as shapes

from rot.frontends.policy import PolicyFrontendError

__all__ = [
    "OpaFrontendError",
    "PROPERTY_KIND",
    "SUPPORTED_SHAPES",
    "build_ir",
    "parse_annotations",
]

#: A ``.rego`` policy (like a ``.dw`` one) always pins a safety property.
PROPERTY_KIND = "safety"

#: The shapes this stub recognises: shape name -> (family, property_name).
#: The property names match the ``.dw`` front-end's shape map (``dw._SHAPE``)
#: so both routes report the same property for the same shape.
SUPPORTED_SHAPES = {
    "spendcap": ("SPENDCAP", "spendcap_within_cap"),
    "approval_replay": ("APPROVAL_REPLAY", "approval_single_use"),
}

#: The canonical-encoding annotations a stub front-end lowers on.
#: ``# rotn:shape=<shape>``       -- which canonical shape this policy is
#: ``# rotn:variant=<buggy|correct>`` -- which variant (the policy decision)
#: ``# rotn:amount=<int>``        -- optional per-request amount (spendcap)
#: ``# rotn:cap=<int>``           -- optional cap (spendcap)
ANNOTATION_PREFIX = "rotn:"


class OpaFrontendError(PolicyFrontendError):
    """Raised when a ``.rego`` file cannot be lowered into a ProtocolIR.

    (A subclass of the router's ``PolicyFrontendError`` so the whole
    ``frontends.policy`` package presents one error type.)
    """


def parse_annotations(text):
    """Extract the ``# rotn:<key>=<value>`` annotations from ``text``.

    Returns a dict keyed by the annotation name (without the ``rotn:``
    prefix), e.g. ``{"shape": "approval_replay", "variant": "buggy"}``.
    Lines that are not comments, do not start with ``rotn:``, or carry no
    ``=`` are ignored (Rego comments are free-form; only the canonical
    markers matter to the stub).
    """
    annos = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        body = stripped
        while body.startswith("#"):
            body = body[1:].strip()
        if not body.startswith(ANNOTATION_PREFIX):
            continue
        if "=" not in body:
            continue
        key, _, value = body.partition("=")
        key = key.strip()
        if key.startswith(ANNOTATION_PREFIX):
            key = key[len(ANNOTATION_PREFIX):]
        annos[key.strip()] = value.strip()
    return annos


def _check_rego_skeleton(text):
    """Minimal structural check on a ``.rego`` policy.

    A Rego policy needs a ``package`` declaration and at least one rule
    body.  This is a *skeleton* check only (the stub does not interpret
    Rego semantics -- that is deliberately out of scope).
    """
    problems = []
    if not re.search(r"(?m)^\s*package\s+[A-Za-z0-9_.]+\s*$", text):
        problems.append("no `package` declaration")
    if not re.search(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*(\{|\()", text):
        problems.append("no rule definition")
    if problems:
        raise OpaFrontendError(
            "Rego skeleton check failed: %s" % "; ".join(problems))


def _int_or_none(value, what, policy_path):
    """Parse an optional integer annotation (or CLI override)."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        raise OpaFrontendError(
            "invalid %s %r in %s (expected an integer)"
            % (what, value, policy_path))


def build_ir(policy_path, tools_path=None, n_steps=1, max_inflight=None,
             amount=None, cap=None, window=None, variant=None):
    """Lower a ``.rego`` policy (canonical encoding) to a validated IR.

    Parameters
    ----------
    policy_path : str
        Path to a ``.rego`` policy carrying the ``# rotn:`` canonical-
        encoding annotations (``shape`` required; ``variant`` / ``amount``
        / ``cap`` optional).
    tools_path : str or None
        Accepted for a compatible router signature; unused (the canonical
        encodings are self-contained).
    n_steps : int
        Accepted for a compatible router signature; unused (single-service
        shapes).
    max_inflight : int or None
        ``K`` -- the client-side request-pool bound (spend-cap shape);
        ``None`` uses :data:`rot.spendcap.MAX_INFLIGHT`.
    amount : int or None
        The policy's per-request amount (spend-cap shape); ``None`` uses
        the policy's ``# rotn:amount`` annotation, else
        :data:`rot.spendcap.AMOUNT`.
    cap : int or None
        The policy's cap (spend-cap shape); ``None`` uses the policy's
        ``# rotn:cap`` annotation, else :data:`rot.spendcap.CAP`.
    window : int or None
        The temporal window as a bounded event count ``W`` (spend-cap
        shape); ``None`` uses :data:`rot.spendcap.MAX_WINDOW`.
    variant : str or None
        ``"buggy"`` / ``"correct"`` -- overrides the policy's
        ``# rotn:variant`` annotation (the policy decision under test).

    Returns
    -------
    rot.ir.ProtocolIR
        A validated IR, structurally identical to the ``.dw`` front-end's
        lowering of the equivalent policy (``ProtocolIR.__eq__`` ignores
        metadata), with provenance metadata (``frontend: "opa"``,
        ``shape``, ``variant``, ``family``, ``property_kind``,
        ``property_name``, ``policy_source``).

    Raises
    ------
    OpaFrontendError
        If the file is missing, is not a recognisable ``.rego`` policy,
        names an unsupported shape/variant, or the lowered IR fails
        validation.
    """
    if not os.path.isfile(policy_path):
        raise OpaFrontendError("policy file not found: %s" % policy_path)
    with open(policy_path, "r") as f:
        text = f.read()

    annos = parse_annotations(text)
    shape = annos.get("shape")
    if shape is None:
        raise OpaFrontendError(
            "%s: missing `# rotn:shape=` annotation (the canonical-encoding "
            "marker this stub lowers on; supported: %s)"
            % (policy_path, ", ".join(sorted(SUPPORTED_SHAPES))))
    if shape not in SUPPORTED_SHAPES:
        raise OpaFrontendError(
            "%s: unsupported shape %r (supported: %s)"
            % (policy_path, shape, ", ".join(sorted(SUPPORTED_SHAPES))))
    _check_rego_skeleton(text)

    v = (variant or annos.get("variant") or "buggy").lower()
    if v not in ("buggy", "correct"):
        raise OpaFrontendError(
            "%s: unknown variant %r (expected buggy or correct)"
            % (policy_path, v))
    buggy = (v == "buggy")

    amount = _int_or_none(amount, "amount", policy_path)
    cap = _int_or_none(cap, "cap", policy_path)
    window = _int_or_none(window, "window", policy_path)
    if amount is None:
        amount = _int_or_none(annos.get("amount"), "amount", policy_path)
    if cap is None:
        cap = _int_or_none(annos.get("cap"), "cap", policy_path)

    # The *model* is delegated to the single source of truth -- the same
    # oracle the ``.dw`` route lowers to -- so the two front-ends are
    # guaranteed to agree structurally.
    if shape == "spendcap":
        model = spendcap.build_ir(
            buggy=buggy,
            max_inflight=spendcap.MAX_INFLIGHT if max_inflight is None
            else max_inflight,
            amount=spendcap.AMOUNT if amount is None else amount,
            cap=spendcap.CAP if cap is None else cap,
            window=spendcap.MAX_WINDOW if window is None else window)
    else:  # shape == "approval_replay" (SUPPORTED_SHAPES is closed above)
        model = shapes.build_approval_replay_ir(buggy=buggy)

    family, property_name = SUPPORTED_SHAPES[shape]
    model.metadata.update({
        "family": family,
        "frontend": "opa",
        "shape": shape,
        "variant": "buggy" if buggy else "correct",
        "property_kind": PROPERTY_KIND,
        "property_name": property_name,
        "policy_source": os.path.abspath(policy_path),
    })

    errors = model.validate()
    if errors:
        raise OpaFrontendError(
            ".rego IR failed validation: %s" % "; ".join(errors))
    return model