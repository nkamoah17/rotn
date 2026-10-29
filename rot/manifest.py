# -*- coding: utf-8 -*-
"""rot.manifest -- deterministic verification reports (manifests).

A manifest is a self-contained, **byte-stable** record of a verification run:
the policy (hash + content), the environment (model family + parameters), the
verdicts (the :mod:`rot.trifecta` facets), and the witness.  It carries a
``manifest_id`` (SHA-256 over the canonical body) so it can be checked for
integrity and compared across re-runs.

Determinism
-----------
The manifest is serialized with **sorted keys**, **compact separators**, and
**stable hashing**.  It contains no timestamps, no absolute paths, and no
environment-dependent values.  Two runs with the same ``(policy, environment)``
produce byte-identical manifests -- re-running ``verify`` must reproduce the
exact same ``manifest_id``.

The manifest is derived from :mod:`rot.trifecta` (the three-facet audit), so
it is the auditable artifact for the agent-step slice.  It is pure stdlib and
Python 3.6 compatible.
"""

import hashlib
import json

__all__ = [
    "SCHEMA",
    "Manifest",
    "build_manifest",
    "verify",
    "verify_manifest",
]

# The manifest schema version. Bump on any breaking change to the body shape.
SCHEMA = "rotn.manifest/v1"


# ---------------------------------------------------------------------------
# canonical serialization + hashing
# ---------------------------------------------------------------------------

def _json_default(obj):
    """JSON fallback: prefer ``to_dict()`` (ROTN objects), else ``repr``."""
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return repr(obj)


def _canonical(obj):
    """Canonical JSON for hashing: sorted keys, compact separators, stable
    fallback for non-JSON values. Deterministic for a given object graph."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=_json_default)


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------

class Manifest(object):
    """A deterministic verification report (schema v1).

    Parameters
    ----------
    policy:
        Dict describing the audited policy: ``{"hash", "allowed", "denied"}``.
    environment:
        Dict describing the audited environment (model family + parameters):
        ``{"family", "buggy", "horizon", "max_states", "n_states"}``.
    verdicts:
        Dict mapping facet name -> facet dict (``safety`` / ``liveness`` /
        ``conformance``), each from ``FacetVerdict.to_dict()``.
    witness:
        The primary witness (first non-None facet witness) or ``None``.
    overall:
        Dict ``{"all_proven", "any_violated", "result"}`` where ``result`` is
        one of ``"proven" | "violated" | "unknown"``.
    advisories:
        Optional list of loud, non-fatal advisory codes (e.g.
        ``MASKED_AT_LOW_K`` from :mod:`rot.verdicts`) recording a *bound* that
        produced the verdict.  They do not change ``overall``; they make the
        bound visible so a bounded ``PROVEN`` is never a silent
        false-negative.  Defaults to ``[]``.
    """

    def __init__(self, policy, environment, verdicts, witness, overall,
                 advisories=None):
        self.policy = policy
        self.environment = environment
        self.verdicts = verdicts
        self.witness = witness
        self.overall = overall
        # Loud, non-fatal advisory codes (e.g. MASKED_AT_LOW_K).  These record
        # a *bound* that produced the verdict (e.g. a K too small to express
        # the minimal overshoot) so a bounded PROVEN is never a *silent*
        # false-negative.  They do not change ``overall`` -- they make the
        # bound visible.  Part of the hashable body so the manifest_id covers
        # them.
        self.advisories = list(advisories or [])
        # The manifest_id is the SHA-256 over the canonical body (everything
        # EXCEPT the manifest_id itself), so it is self-consistent by
        # construction and independent of serialization order.
        self.manifest_id = _sha256(_canonical(self._body()))

    def _body(self):
        """The hashable body (no manifest_id). Key order is irrelevant -- the
        canonical serializer sorts keys."""
        return {
            "schema": SCHEMA,
            "policy": self.policy,
            "environment": self.environment,
            "verdicts": self.verdicts,
            "witness": self.witness,
            "overall": self.overall,
            "advisories": self.advisories,
        }

    def to_dict(self):
        d = self._body()
        d["manifest_id"] = self.manifest_id
        return d

    def to_json(self, indent=None):
        """Deterministic JSON. ``indent=None`` -> compact; ``indent=2`` ->
        pretty. Both are stable for a given manifest (sorted keys)."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent,
                          default=_json_default)

    def verify(self):
        """Return True iff ``manifest_id`` matches the recomputed body hash.

        This is the integrity check: it catches any tampering with the body
        (policy, environment, verdicts, witness, or overall) after the id was
        computed.
        """
        return self.manifest_id == _sha256(_canonical(self._body()))


# ---------------------------------------------------------------------------
# building + verifying
# ---------------------------------------------------------------------------

def _overall_result(result):
    """Fold the trifecta result into a single overall status."""
    if result.any_violated():
        return "violated"
    if result.all_proven():
        return "proven"
    return "unknown"


def _primary_witness(result):
    """The first non-None facet witness (safety -> liveness -> conformance)."""
    for facet in (result.safety, result.liveness, result.conformance):
        if facet.witness is not None:
            return facet.witness
    return None


def build_manifest(policy, buggy=False, horizon=12, max_states=200000,
                   advisories=None):
    """Run the trifecta audit and wrap the result in a deterministic manifest.

    Parameters mirror :func:`rot.trifecta.audit` so the manifest is a pure
    function of ``(policy, buggy, horizon, max_states, advisories)`` -- the
    same inputs always yield the same manifest (and hence the same
    ``manifest_id``).  ``advisories`` is an optional list of loud, non-fatal
    advisory codes (e.g. ``MASKED_AT_LOW_K``) recording a bound that produced
    the verdict; it defaults to ``[]`` (the agent-step audit has no K bound to
    mask, so no advisory fires there).
    """
    from rot import trifecta

    result = trifecta.audit(policy, buggy=buggy, horizon=horizon,
                            max_states=max_states)

    policy_dict = {
        "hash": result.policy_hash,
        "allowed": sorted(policy.allowed),
        "denied": sorted(policy.denied),
    }
    environment = {
        "family": "AGENT_STEP",
        "buggy": bool(buggy),
        "horizon": int(horizon),
        "max_states": int(max_states),
        "n_states": int(result.n_states),
    }
    verdicts = {
        "safety": result.safety.to_dict(),
        "liveness": result.liveness.to_dict(),
        "conformance": result.conformance.to_dict(),
    }
    overall = {
        "all_proven": result.all_proven(),
        "any_violated": result.any_violated(),
        "result": _overall_result(result),
    }

    return Manifest(policy_dict, environment, verdicts,
                    _primary_witness(result), overall, advisories=advisories)


def verify(policy, buggy=False, horizon=12, max_states=200000,
           expected_id=None):
    """Re-derive the manifest for ``(policy, environment)`` and check it.

    This is the ``verify --policy X --env E`` entry point: it re-runs the
    audit, builds the manifest, and confirms (a) internal consistency
    (``manifest_id`` matches the body hash) and (b) -- when ``expected_id`` is
    given -- that the re-derived id matches the recorded one (reproducibility).

    Returns a tuple ``(ok, manifest, note)``.
    """
    m = build_manifest(policy, buggy=buggy, horizon=horizon,
                       max_states=max_states)
    if not m.verify():
        return False, m, "manifest_id does not match the body hash"
    if expected_id is not None and m.manifest_id != expected_id:
        return (False, m,
                "manifest_id %s does not match expected %s"
                % (m.manifest_id, expected_id))
    return True, m, "ok"


def verify_manifest(manifest_dict, expected_id=None):
    """Low-level integrity check on a manifest dict (no re-derivation).

    Recomputes the body hash from ``manifest_dict`` (ignoring its
    ``manifest_id``) and compares it against the stated id -- and, when
    ``expected_id`` is given, against that too.

    Returns a tuple ``(ok, manifest_id, note)``.
    """
    body = {k: v for k, v in manifest_dict.items() if k != "manifest_id"}
    computed = _sha256(_canonical(body))
    stated = manifest_dict.get("manifest_id")
    if stated != computed:
        return False, computed, "manifest_id does not match the body hash"
    if expected_id is not None and computed != expected_id:
        return False, computed, "manifest_id does not match expected id"
    return True, computed, "ok"
