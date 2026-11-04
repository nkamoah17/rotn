# -*- coding: utf-8 -*-
"""rot.frontends.policy.ap2 -- the ``.ap2`` (AP2 mandate) STUB front-end.

Positioning (Phase 4): ROTN is the *neutral checker* across policy
languages.  This module proves that claim for the AP2 (Agent Payments
Protocol) mandate surface without building an AP2 runtime: it is a
**stub** that maps an AP2 mandate document -- the natural-language-grade
intent "spend up to $X on Y" -- onto the APW shape(s) it instantiates,
and lowers that shape to the **same** ``rot.ir.ProtocolIR`` the Dogwood
front-end produces for the equivalent ``.dw`` policy.

The mapping (the write-up lives in ``docs/positioning.md``)
-------------------------------------------------------------
An AP2 mandate is *intent*, not a policy: it says what the agent may do,
not how the enforcement is sequenced over interleaved events.  The three
mandate facets this stub models, and the APW class each one instantiates
when the enforcement is the natural first draft:

* ``amount_max``  -- "spend up to $X"  -> **APW-1** (settled-sum cap
  bypass): charging only *settled* responses against the cap is the
  natural per-request reading, and it is exactly the parallel-fire
  bypass (property ``spendcap_within_cap``).
* ``single_use``  -- "one mandate, one payment" -> **APW-2** (approval
  replay): a bare "mandate present" fact is sticky, so one mandate admits
  N payments (property ``approval_single_use``).
* ``session_scoped`` -- "up to K per session" -> **APW-5** (session
  splitting): a per-session counter that resets per event is always
  satisfied (property ``scoped_within_cap``).

The mandate's ``amount_max`` threads the cap into the APW-1 model (the
model is *derived from the mandate*), and ``enforcement`` names the
implementation under test: ``"settled_sum"`` (the natural first draft --
the buggy APW-1 variant, the one an AI author most often emits) or
``"request_sum"`` (the corrected rule).  ``maps_to`` may override the
inferred mapping.

Routing note: AP2 mandate documents are JSON, but they carry the ``.ap2``
extension (not ``.json``) so the router keeps them distinct from Dogwood
JSON policies (``rot.frontends.policy.dogwood``).

Narrow waist: imports only stdlib, ``rot.spendcap`` and ``rot.shapes``
(the oracle builders -- the same modules the ``.dw`` front-end uses) --
never a downstream engine (``rot.modelfind``, ``rot.cegar``,
``rot.emitter``, ``rot.tlc``).  Python 3.6 compatible.
"""

import json
import os

import rot.spendcap as spendcap
import rot.shapes as shapes

from rot.frontends.policy import PolicyFrontendError

__all__ = [
    "Ap2FrontendError",
    "PROPERTY_KIND",
    "SCHEMAS",
    "SUPPORTED_MAPPINGS",
    "build_ir",
    "map_mandate",
]

#: A ``.ap2`` mandate (like a ``.dw`` one) always pins a safety property.
PROPERTY_KIND = "safety"

#: Recognised mandate schemas (an absent ``schema`` field is accepted --
#: the fields, not the schema tag, drive the mapping).
SCHEMAS = ("ap2.mandate/v1",)

#: The mandate mappings this stub supports: APW id -> (family,
#: property_name).  Property names match the ``.dw`` front-end's shape
#: map (``dw._SHAPE``) so all routes report the same property per shape.
SUPPORTED_MAPPINGS = {
    "APW-1": ("SPENDCAP", "spendcap_within_cap"),
    "APW-2": ("APPROVAL_REPLAY", "approval_single_use"),
    "APW-5": ("SCOPED_CAP", "scoped_within_cap"),
}

#: The enforcement implementations of the APW-1 (cap) mandate facet.
ENFORCEMENTS = ("settled_sum", "request_sum")


class Ap2FrontendError(PolicyFrontendError):
    """Raised when a ``.ap2`` mandate cannot be lowered into a ProtocolIR.

    (A subclass of the router's ``PolicyFrontendError`` so the whole
    ``frontends.policy`` package presents one error type.)
    """


def map_mandate(mandate):
    """Map an AP2 mandate document to the APW shape it instantiates.

    Inference rules (documented in ``docs/positioning.md``), in priority
    order -- the most *binding* facet of the mandate determines the shape:

    * ``single_use`` true     -> ``APW-2`` (approval replay: one mandate,
      one payment);
    * ``session_scoped`` true -> ``APW-5`` (session splitting: a cap
      scoped to a session);
    * ``amount_max`` present  -> ``APW-1`` (settled-sum cap: "spend up to
      $X") -- the default facet.

    Returns the APW id (a key of :data:`SUPPORTED_MAPPINGS`).

    Raises
    ------
    Ap2FrontendError
        If no supported facet is present.
    """
    if bool(mandate.get("single_use")):
        return "APW-2"
    if bool(mandate.get("session_scoped")):
        return "APW-5"
    if mandate.get("amount_max") is not None:
        return "APW-1"
    raise Ap2FrontendError(
        "mandate maps to no supported shape (need single_use, "
        "session_scoped, or amount_max; supported mappings: %s)"
        % ", ".join(sorted(SUPPORTED_MAPPINGS)))


def _int_field(mandate, field, policy_path):
    """Read a positive-integer field from the mandate document."""
    value = mandate.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise Ap2FrontendError(
            "%s: field %r must be an integer (got %r)"
            % (policy_path, field, value))
    if value < 1:
        raise Ap2FrontendError(
            "%s: field %r must be >= 1 (got %r)" % (policy_path, field, value))
    return value


def build_ir(policy_path, tools_path=None, n_steps=1, max_inflight=None,
             amount=None, cap=None, window=None, variant=None):
    """Lower an AP2 mandate (``.ap2``) to a validated ``ProtocolIR``.

    The mandate is mapped onto its APW shape (:func:`map_mandate`, or an
    explicit ``maps_to`` field) and lowered through the *same* oracle the
    ``.dw`` route uses, so the verdict is decided on a structurally
    identical IR regardless of which language the policy was written in.

    Parameters
    ----------
    policy_path : str
        Path to an AP2 mandate document (JSON) with a ``.ap2`` extension.
    tools_path : str or None
        Accepted for a compatible router signature; unused (the mandate
        maps to a self-contained shape).
    n_steps : int
        Accepted for a compatible router signature; unused (single-service
        shapes).
    max_inflight : int or None
        ``K`` -- the client-side request-pool bound (APW-1 facet);
        ``None`` uses :data:`rot.spendcap.MAX_INFLIGHT`.
    amount : int or None
        The per-request amount (APW-1 facet); ``None`` uses the mandate's
        ``amount`` field, else :data:`rot.spendcap.AMOUNT`.
    cap : int or None
        The cap (APW-1 facet); ``None`` uses the mandate's ``amount_max``
        field, else :data:`rot.spendcap.CAP`.
    window : int or None
        The temporal window bound ``W`` (APW-1 facet); ``None`` uses
        :data:`rot.spendcap.MAX_WINDOW`.
    variant : str or None
        ``"buggy"`` / ``"correct"`` -- overrides the mandate's
        ``enforcement`` field (the implementation under test; default
        ``"settled_sum"`` -- the natural first draft).

    Returns
    -------
    rot.ir.ProtocolIR
        A validated IR with the mapped shape's safety property pinned and
        provenance metadata (``frontend: "ap2"``, ``ap2_apw``,
        ``ap2_intent``, ``family``, ``property_kind``, ``property_name``,
        ``policy_source``).

    Raises
    ------
    Ap2FrontendError
        If the file is missing, is not a valid mandate document, maps to
        an unsupported shape, or the lowered IR fails validation.
    """
    if not os.path.isfile(policy_path):
        raise Ap2FrontendError("mandate file not found: %s" % policy_path)
    with open(policy_path, "r") as f:
        try:
            mandate = json.load(f)
        except ValueError as exc:
            raise Ap2FrontendError(
                "%s: mandate is not valid JSON: %s" % (policy_path, exc))
    if not isinstance(mandate, dict):
        raise Ap2FrontendError(
            "%s: mandate must be a JSON object" % policy_path)

    schema = mandate.get("schema")
    if schema is not None and schema not in SCHEMAS:
        raise Ap2FrontendError(
            "%s: unknown mandate schema %r (expected one of %s)"
            % (policy_path, schema, " / ".join(SCHEMAS)))

    apw = mandate.get("maps_to") or map_mandate(mandate)
    if apw not in SUPPORTED_MAPPINGS:
        raise Ap2FrontendError(
            "%s: unsupported mandate mapping %r (supported: %s)"
            % (policy_path, apw, ", ".join(sorted(SUPPORTED_MAPPINGS))))

    # The variant (the implementation under test).  The mandate is intent;
    # enforcement is an implementation choice.  The stub defaults to the
    # natural first draft -- the settled sum -- which is exactly the class
    # an AI author most often emits, and the class ROTN exists to catch.
    v = (variant or mandate.get("enforcement") or "settled_sum").lower()
    if v not in ENFORCEMENTS:
        raise Ap2FrontendError(
            "%s: unknown enforcement %r (expected %s)"
            % (policy_path, v, " / ".join(ENFORCEMENTS)))
    buggy = (v == "settled_sum")

    # The *model* is delegated to the single source of truth -- the same
    # oracles the ``.dw`` route lowers to -- so all front-ends are
    # guaranteed to agree structurally.
    if apw == "APW-1":
        cap_v = cap if cap is not None else _int_field(mandate, "amount_max",
                                                       policy_path)
        if cap_v is None:
            cap_v = spendcap.CAP
        amount_v = amount if amount is not None \
            else _int_field(mandate, "amount", policy_path)
        if amount_v is None:
            amount_v = spendcap.AMOUNT
        window_v = window if window is not None else spendcap.MAX_WINDOW
        model = spendcap.build_ir(
            buggy=buggy,
            max_inflight=spendcap.MAX_INFLIGHT if max_inflight is None
            else max_inflight,
            amount=amount_v, cap=cap_v, window=window_v)
    elif apw == "APW-2":
        model = shapes.build_approval_replay_ir(buggy=buggy)
    else:  # APW-5 (SUPPORTED_MAPPINGS is closed above)
        cap_v = _int_field(mandate, "per_unit", policy_path)
        if cap_v is None:
            cap_v = 3
        model = shapes.build_scoped_cap_ir(buggy=buggy, cap=cap_v)

    family, property_name = SUPPORTED_MAPPINGS[apw]
    model.metadata.update({
        "family": family,
        "frontend": "ap2",
        "ap2_apw": apw,
        "ap2_intent": mandate.get("intent", ""),
        "variant": "buggy" if buggy else "correct",
        "property_kind": PROPERTY_KIND,
        "property_name": property_name,
        "policy_source": os.path.abspath(policy_path),
    })

    errors = model.validate()
    if errors:
        raise Ap2FrontendError(
            ".ap2 mandate IR failed validation: %s" % "; ".join(errors))
    return model