# -*- coding: utf-8 -*-
"""rot.runtime.refusal -- the refusal shape (B2): deterministic, hashable, auditable.

A *refusal* is the runtime plane's answer to a blocked tool call: the exact
shape the agent (and the auditor) needs -- **why** it was blocked, **which
rule** blocked it, and **what to do** to proceed.  It is the runtime twin of
the offline :class:`rot.coach.CoachingArtifact`: where the coach is a
five-step record of *correcting a policy*, a refusal is a single, atomic
*decision on one call*.

The contract (mirrors :mod:`rot.manifest` / :mod:`rot.trace`):

  * **Exact shape.**  A refusal is always the five keys the spec names::

        {"blocked", "rule", "why", "to_proceed", "allowed_now"}

    ``blocked`` is the boolean decision (``True`` when the call was denied).
    ``allowed_now`` is the complementary boolean (``True`` when the call is
    permitted *as-is*).  The two are the *same* decision read two ways --
    ``blocked == (not allowed_now)`` -- so a consumer can read whichever it
    prefers.  ``rule`` is the rule id (which policy/rung decided), ``why`` is
    the plain-English reason, and ``to_proceed`` is the computed enabling
    condition (the condition(s) under which the call would become allowed).

  * **Deterministic.**  A refusal is a *pure function* of (rule, request,
    state): no timestamps, no random ids, stable ordering.  Two decisions on
    the same input produce byte-identical refusals.

  * **Hashable.**  A refusal carries a top-level ``hash`` (SHA-256 of its own
    canonical body) so it can be referenced, compared, and re-verified
    byte-for-byte -- exactly the :mod:`rot.trace` RTF contract.  The hash and
    the canonicalizer are *shared* with the RTF (one source of truth), so a
    runtime refusal and an offline trace hash under the same discipline.

  * **Auditable.**  A refusal records enough to re-derive it: the rule id, the
    rule's ``ProtocolIR`` guard (rendered), the state it was evaluated in, and
    the computed ``to_proceed`` conditions.  A reader can re-run the guard on
    the recorded state and confirm the decision -- no separate proof engine.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

from __future__ import print_function

import rot
import rot.trace as _trace  # one canonicalizer + one hash discipline (RTF)

__all__ = [
    "SCHEMA",
    "FIELDS",
    "REFUSAL_HASH_PREFIX",
    "Refusal",
    "refusal_hash",
    "canonical_json",
    "validate_refusal",
]

#: The refusal schema tag (stable; bump on a breaking change to the body shape).
SCHEMA = "caravel.refusal/v1"

#: The exact five refusal fields (the spec's shape), in canonical order.
#: ``blocked`` and ``allowed_now`` are the same decision read two ways.
FIELDS = ("blocked", "rule", "why", "to_proceed", "allowed_now")

#: The human-stable id prefix (the RTF uses ``"mf-"``; refusals use ``"rf-"``).
REFUSAL_HASH_PREFIX = "rf-"

class Refusal(object):
    """A deterministic, hashable runtime refusal (the exact refusal shape).

    The body is the five-field decision record plus the provenance that lets a
    reader re-derive the decision (the rule's rendered guard, the state, and
    the computed ``to_proceed`` conditions/blockers).  The hash pins the exact
    refusal to a single stable identifier -- the same contract as the RTF.

    Parameters
    ----------
    blocked : bool
        Whether the call was denied (``True``) or allowed (``False``).
    rule : str
        The rule id that decided (e.g. ``"spendcap_within_cap"``).
    why : str
        The plain-English reason the call was blocked.
    to_proceed : str
        The computed enabling condition (what must hold to proceed).
    allowed_now : bool, optional
        The complementary decision (defaults to ``not blocked``).
    schema : str, optional
        The schema tag (defaults to :data:`SCHEMA`).
    action : str, optional
        The tool/action name that was decided.
    guard : str, optional
        The rule's ``ProtocolIR`` guard, rendered (the spec).
    state : dict, optional
        The state the guard was evaluated in (the re-derivation witness).
    conditions : list of str, optional
        The ``to_proceed`` enabling conditions (computed from the guard).
    blockers : list of str, optional
        The negation of the conditions (the conditions currently blocking).
    """

    def __init__(self, blocked, rule, why, to_proceed, allowed_now=None,
                 schema=SCHEMA, action=None, guard=None, state=None,
                 conditions=None, blockers=None):
        self.blocked = bool(blocked)
        self.rule = rule
        self.why = why
        self.to_proceed = to_proceed
        # ``allowed_now`` is the same decision read the other way.  When not
        # given, it is the complement of ``blocked`` (the two never disagree).
        self.allowed_now = (not self.blocked) if allowed_now is None \
            else bool(allowed_now)
        self.schema = schema
        self.action = action
        self.guard = guard
        self.state = state
        self.conditions = list(conditions or [])
        self.blockers = list(blockers or [])
        self.body = self._body()
        self.hash = refusal_hash(self.body)
        self.refusal_id = _refusal_id(self.body)

    # -- construction --------------------------------------------------------
    def _body(self):
        """The refusal body (the five decision fields + provenance, no hash)."""
        body = {
            "schema": self.schema,
            "rot_version": rot.__version__,
            "blocked": self.blocked,
            "rule": self.rule,
            "why": self.why,
            "to_proceed": self.to_proceed,
            "allowed_now": self.allowed_now,
        }
        if self.action is not None:
            body["action"] = self.action
        if self.guard is not None:
            body["guard"] = self.guard
        if self.state is not None:
            body["state"] = dict(self.state)
        if self.conditions:
            body["conditions"] = list(self.conditions)
        if self.blockers:
            body["blockers"] = list(self.blockers)
        return body

    # -- queries -------------------------------------------------------------
    @property
    def decision(self):
        """``"allowed"`` / ``"blocked"`` -- the decision in one word."""
        return "blocked" if self.blocked else "allowed"

    def to_dict(self):
        """The refusal body plus the top-level ``hash`` and ``refusal_id``."""
        d = dict(self.body)
        d["hash"] = self.hash
        d["refusal_id"] = self.refusal_id
        return d

    def to_json(self, indent=2):
        """Deterministic, JSON-serialisable form (stable separators)."""
        return canonical_json(self.to_dict(), indent=indent)

    def verify(self):
        """Recompute the body hash and confirm it matches the stated hash."""
        return refusal_hash(self.body) == self.hash

    def __repr__(self):
        return "Refusal(decision=%r, rule=%r, id=%s)" % (
            self.decision, self.rule, self.refusal_id)

    def __eq__(self, other):
        if not isinstance(other, Refusal):
            return NotImplemented
        return self.body == other.body and self.hash == other.hash

    def __hash__(self):
        return hash(self.hash)


def validate_refusal(d):
    """Validate a refusal *dict* against the exact five-field shape.

    Returns a list of error strings (empty when the dict is a well-formed
    refusal body).  A refusal must carry every field in :data:`FIELDS`; the
    two decision booleans must be present and consistent
    (``blocked == (not allowed_now)``); ``rule`` / ``why`` / ``to_proceed``
    must be strings.
    """
    errs = []
    if not isinstance(d, dict):
        return ["refusal must be a dict (got %r)" % type(d).__name__]
    for f in FIELDS:
        if f not in d:
            errs.append("missing field: %s" % f)
    if not errs:
        if not isinstance(d["blocked"], bool):
            errs.append("'blocked' must be a boolean (got %r)"
                        % type(d["blocked"]).__name__)
        if not isinstance(d["allowed_now"], bool):
            errs.append("'allowed_now' must be a boolean (got %r)"
                        % type(d["allowed_now"]).__name__)
        elif d["blocked"] and d["allowed_now"]:
            errs.append("'blocked' and 'allowed_now' must not both be True")
        elif (not d["blocked"]) and (not d["allowed_now"]):
            errs.append("'blocked' and 'allowed_now' must not both be False")
        for f in ("rule", "why", "to_proceed"):
            if not isinstance(d[f], str):
                errs.append("'%s' must be a string (got %r)"
                            % (f, type(d[f]).__name__))
    return errs


def canonical_json(obj, indent=None):
    """Deterministic JSON (sorted keys, stable separators).

    Delegates to :func:`rot.trace.canonical_json` so the refusal artifact and
    the RTF trace share one canonicaliser (byte-stable for the same input).
    """
    return _trace.canonical_json(obj, indent=indent)


def refusal_hash(body):
    """SHA-256 hex digest of a refusal body's canonical JSON.

    This is the *hashable* part of the refusal: it pins the exact decision
    (every field in the body) to a single stable identifier, under the same
    discipline as the RTF trace hash.
    """
    return _trace.trace_hash(body)


def _refusal_id(body):
    """A human-stable id derived from a refusal body's hash (``rf-<16 hex>``)."""
    return REFUSAL_HASH_PREFIX + refusal_hash(body)[:16]
