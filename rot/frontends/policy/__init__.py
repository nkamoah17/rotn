# -*- coding: utf-8 -*-
"""rot.frontends.policy -- policy-file front-ends (Cedar + Dogwood).

Turns a *policy file* on disk into a ``rot.ir.ProtocolIR`` with a pinned
property ready for the soundness core.  This is the front-end half of the
narrow waist for policy-driven verification: nothing in this package may
import the engines (``rot.modelfind``, ``rot.cegar``, ``rot.emitter``,
``rot.tlc``) -- only ``rot.ir`` and other ``rot.frontends`` modules.

Public entry point
------------------
``build_ir(policy_path, tools_path=None, n_steps=1)`` dispatches on the
policy file extension:

* ``.cedar`` -- Cedar policy text (:mod:`rot.frontends.policy.cedar`).
  Pinned property: the policy is *non-vacuous* -- some concrete request is
  permitted (a realizability query, checked with ``exists_reachable``).
* ``.dw``    -- Dogwood (AWS) spend-cap source
  (:mod:`rot.frontends.policy.dw`).  Pinned property: ``spendcap_within_cap``
  -- the settled + in-flight amount never exceeds the cap (a safety query,
  checked with ``forall_reachable``).  Self-contained (no tools catalog).
* ``.json``  -- Dogwood JSON policy (:mod:`rot.frontends.policy.dogwood`),
  optionally paired with a ``tools.json`` tool catalog.  Pinned property:
  *policy conformance* -- the conforming agent never takes a denied action
  (a safety query, checked with ``forall_reachable``).

Every returned IR carries:

* ``pinned_property`` -- the predicate to verify (an ``rot.ir`` expression);
* ``metadata["property_kind"]``  -- ``"safety"`` (must hold in every
  reachable state) or ``"realizability"`` (must hold in at least one);
* ``metadata["property_name"]``  -- stable property name for reports;
* ``metadata["policy_source"]`` / ``["tools_source"]`` -- provenance.

Pure stdlib, Python 3.6 compatible.
"""

import os

__all__ = ["build_ir", "PolicyFrontendError"]


class PolicyFrontendError(ValueError):
    """Raised when a policy file cannot be turned into a ProtocolIR."""


def _split_ext(path):
    """Lowercased file extension (including the dot), or '' if none."""
    base = os.path.basename(os.path.normpath(str(path)))
    dot = base.rfind(".")
    if dot <= 0:
        return ""
    return base[dot:].lower()


def build_ir(policy_path, tools_path=None, n_steps=1, kind=None,
             max_inflight=None, amount=None, cap=None, window=None):
    """Build a ``ProtocolIR`` from a policy file.

    Parameters
    ----------
    policy_path : str
        Path to a Cedar (``.cedar``), Dogwood spend-cap (``.dw``), or Dogwood
        (``.json``) policy file.
    tools_path : str or None
        Optional Dogwood ``tools.json`` catalog (ignored for Cedar and
        ``.dw`` spend-cap policies).
    n_steps : int
        Agent-step horizon bound (recorded in the IR metadata; the current
        agent-step model is a single decision step, matching
        ``rot.agent_step``).
    kind : str or None
        Property kind to force: ``"safety"`` (Dogwood conformance),
        ``"realizability"`` (Cedar non-vacuity) or ``"liveness"`` (the
        bounded-liveness front-end :mod:`agent_step_liveness`, which pins
        ``decision != idle`` as a goal reachable within the horizon).
        ``None`` (default) auto-routes by file extension.
    max_inflight : int or None
        ``K`` -- the client-side request-pool bound (max concurrent
        in-flight requests the state space can express).  Applies to the
        ``.dw`` **SPENDCAP** family only (recorded in the IR metadata as
        ``max_inflight``); ``None`` (default) uses
        :data:`rot.spendcap.MAX_INFLIGHT` (4).  Ignored for Cedar /
        Dogwood-JSON / liveness routes (those families have no in-flight
        request pool).
    amount : int or None
        The policy's per-request amount (``.dw`` SPENDCAP family only);
        ``None`` uses :data:`rot.spendcap.AMOUNT`.
    cap : int or None
        The policy's cap (``.dw`` SPENDCAP family only); ``None`` uses the
        policy's own cap (or :data:`rot.spendcap.CAP` for a document).
    window : int or None
        The temporal window as a bounded event count ``W`` (``.dw`` SPENDCAP
        family only).  ``None`` uses :data:`rot.spendcap.MAX_WINDOW` (4).
        A ``FormerlyWithin`` window is approximated as "the last ``W``
        events"; recorded in the IR metadata (``window`` / ``dw_window``).

    Returns
    -------
    rot.ir.ProtocolIR
        A validated IR with ``pinned_property`` and ``metadata`` set.

    Raises
    ------
    PolicyFrontendError
        If the extension is unknown, a file is missing, a source is
        malformed, or ``kind`` is not one of safety / realizability /
        liveness.
    """
    ext = _split_ext(policy_path)
    if not os.path.isfile(policy_path):
        raise PolicyFrontendError("policy file not found: %s" % policy_path)
    if tools_path is not None and not os.path.isfile(tools_path):
        raise PolicyFrontendError("tools file not found: %s" % tools_path)
    n_steps = int(n_steps)
    if n_steps < 1:
        raise PolicyFrontendError("n_steps must be >= 1 (got %r)" % (n_steps,))

    if kind is not None:
        kind = str(kind).lower()
        if kind not in ("safety", "realizability", "liveness"):
            raise PolicyFrontendError(
                "unknown property kind %r (expected one of "
                "safety, realizability, liveness)" % (kind,))
        if kind == "liveness":
            # Bounded liveness is orthogonal to the policy family: the same
            # Dogwood policy can be checked for safety (dogwood) OR for
            # bounded liveness (agent_step_liveness).  Translate the
            # sibling front-end's error into this package's so callers can
            # catch one exception type.
            from . import agent_step_liveness as _asl
            try:
                return _asl.build_ir(policy_path, tools_path=tools_path,
                                     n=n_steps)
            except _asl.PolicyFrontendError as exc:
                raise PolicyFrontendError(str(exc))
        if kind == "safety":
            from . import dogwood as _dogwood
            return _dogwood.build_ir(policy_path, tools_path=tools_path,
                                     n_steps=n_steps)
        if kind == "realizability":
            from . import cedar as _cedar
            return _cedar.build_ir(policy_path, tools_path=tools_path,
                                   n_steps=n_steps)

    if ext == ".cedar":
        from . import cedar as _cedar
        return _cedar.build_ir(policy_path, tools_path=tools_path,
                               n_steps=n_steps)
    if ext == ".dw":
        # Dogwood (AWS) spend-cap source: pinned *safety* property
        # ``spendcap_within_cap`` (settled + in-flight amount <= cap).
        # ``tools_path`` / ``n_steps`` are accepted for signature
        # compatibility but unused (the policy is self-contained).
        # ``max_inflight`` (K) parameterizes the client-side request-pool
        # bound; ``None`` -> rot.spendcap.MAX_INFLIGHT.
        from . import dw as _dw
        return _dw.build_ir(policy_path, tools_path=tools_path,
                            n_steps=n_steps, max_inflight=max_inflight,
                            amount=amount, cap=cap, window=window)
    if ext == ".json":
        from . import dogwood as _dogwood
        return _dogwood.build_ir(policy_path, tools_path=tools_path,
                                 n_steps=n_steps)
    raise PolicyFrontendError(
        "unknown policy file extension %r for %s "
        "(expected .cedar, .dw or .json)" % (ext, policy_path))