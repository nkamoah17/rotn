# -*- coding: utf-8 -*-
"""cpg_crosscheck.py -- the static <-> formal soundness cross-check (CPG-3).

The CPG is the ground truth (``G``); the lowered ``ProtocolIR`` is the
abstraction (``A(G)``); the engine verdict is the formal claim.  This module
checks that the verdict is *compatible with the ground truth* -- the
abstraction soundness condition (S), the counter-monotonicity of taint:

    taintPath(G, P)  =>  not Proven(M(A(G)), P)

i.e. if the ground-truth program carries a taint-critical path that threatens
the pinned property ``P``, the abstract model must NOT prove ``P``.  The
abstraction ``A`` may add existential freedom (over-approximate the state
space) but must never drop a taint-critical dataflow edge -- a proof built on
a dropped edge is a silent false negative, and this check exists to make it
impossible.

``taintPath(G, P)`` is shape-specific -- the path that *threatens* ``P``:

* **label_flow** (``NoExfiltration``): a classified private source reaches a
  classified egress sink over a dataflow path AND the egress is *unguarded*
  (no mutable boolean gate) -- a leak path the IR must model as an open
  egress.  (A guarded egress is a controlled channel, not a threat.)
* **budget** (``SpendCap``): the in-flight quantity does NOT reach the
  decision sum (settled-only accounting) -- a parallel-fire bypass path the IR
  must model as an in-flight-charging sum.

The 2x2 (static producer x formal checker) and the verdict action:

================================  ==========================================
``taintPath(G, P)``               verdict -> action
================================  ==========================================
threat present                    PROVEN -> UNSOUND: downgrade to UNKNOWN +
                                  advisory ``unsound_abstraction`` + the
                                  dropped edge named (fail-closed; (S) is the
                                  only cell it forbids)
                                  VIOLATED -> AGREEMENT: the static producer
                                  sees the threat, the formal checker confirms
                                  it with an exact witness
threat absent                     PROVEN -> AGREEMENT: the static producer
                                  sees the control, the formal checker proves
                                  it (the common case)
                                  VIOLATED -> CONCURRENCY_ONLY: the checker
                                  found a witness the static single-path
                                  analysis cannot see (e.g. a parallel-fire
                                  race that slips past even an in-flight-
                                  charging sum); the VIOLATED verdict stands,
                                  tagged (the model checker's value-add)
================================  ==========================================

Undecided verdicts (``UNKNOWN`` / ``UNSOUND`` / ``ERROR`` / ``OUT_OF_SCOPE``)
are not constrained by (S); the cross-check records itself as
``not_applicable`` and leaves the verdict untouched.

This is a **pure function of its inputs** (unit-testable without the engine):
:func:`check_abstraction_soundness(cpg, ir, verdict, shape)` returns a
:class:`SoundnessResult`; :func:`apply_soundness(verdict, result)` applies it
fail-closed (returns the verdict, possibly replaced).  ``rot.cegar.
verify_candidate`` wires both in -- when the caller passes the ground-truth
scrape (``cpg=``), every CPG-derived verdict carries the result on its
evidence (``evidence["abstraction_soundness"]``).

The threat queries reuse the CPG-2 structural recognizers
(``rot.frontends.cpg.extractor``) so the cross-check and the producer agree
on what a control is -- one structural vocabulary, no second heuristic.
Core (Verify-plane) module; pure stdlib, Python 3.6 compatible.
"""

import rot.verdicts as verdicts
from rot.frontends.cpg.extractor import (
    _INFLIGHT_NAMES, _detect_budget, _detect_label_flow, _egress_guard,
)
from rot.frontends.cpg_model import CpgModel

__all__ = [
    "AGREEMENT", "UNSOUND", "CONCURRENCY_ONLY", "NOT_APPLICABLE",
    "SoundnessResult", "check_abstraction_soundness", "apply_soundness",
]

# The four outcome cells (the 2x2 above) plus the not-applicable record.
AGREEMENT = "agreement"
UNSOUND = "unsound"
CONCURRENCY_ONLY = "concurrency_only"
NOT_APPLICABLE = "not_applicable"

_SHAPE_BUDGET = "budget"
_SHAPE_LABEL_FLOW = "label_flow"
_SHAPES = (_SHAPE_BUDGET, _SHAPE_LABEL_FLOW)


class SoundnessResult(object):
    """The outcome of one (S) cross-check -- a pure, serializable record.

    * ``status``       -- one of ``AGREEMENT`` / ``UNSOUND`` /
                          ``CONCURRENCY_ONLY`` / ``NOT_APPLICABLE``.
    * ``shape``        -- the P1 shape checked (``"budget"`` / ``"label_flow"``).
    * ``threat``       -- ``True`` / ``False``: does ``taintPath(G, P)`` hold
                          in the ground-truth CPG?  ``None``: the shape's
                          control is not in ``G`` at all (cannot judge).
    * ``dropped_edge`` -- (UNSOUND only) the taint-critical dataflow edge the
                          abstraction dropped, named (``"src -> dst"``);
                          ``None`` otherwise.
    * ``detail``       -- the structural evidence (path / sum / guard / ...).
    * ``note``         -- a one-line human statement of the outcome.
    """

    def __init__(self, status, shape=None, threat=None, dropped_edge=None,
                 detail=None, note=""):
        self.status = status
        self.shape = shape
        self.threat = threat
        self.dropped_edge = dropped_edge
        self.detail = dict(detail or {})
        self.note = note

    def to_dict(self):
        return {
            "status": self.status,
            "shape": self.shape,
            "threat": self.threat,
            "dropped_edge": self.dropped_edge,
            "detail": self.detail,
            "note": self.note,
        }


# ---------------------------------------------------------------------------
# the taintPath(G, P) query (over the ground-truth CPG)
# ---------------------------------------------------------------------------
def _label_flow_threat(model):
    """``(threat, detail)`` for ``NoExfiltration``.

    ``taintPath(G, P)`` = a classified private source reaches a classified
    egress sink over a dataflow path AND the egress is unguarded (no mutable
    boolean gate).  Returns ``(None, detail)`` when ``G`` has no label/flow
    control at all (the cross-check does not apply).
    """
    found = _detect_label_flow(model)
    if found is None:
        return None, {"reason": "no private->sink structure in G"}
    caller, sink_method, src, path = found
    guard = _egress_guard(model, caller)
    detail = {
        "private_source": src.node_id,
        "sink": sink_method.full_name,
        "path": list(path),
        "guard": guard,
    }
    if guard is not None:
        # The egress is a controlled channel (a mutable gate the caller
        # reads): the path is present but *not* a leak threat.
        return False, detail
    # Unguarded private -> sink dataflow: the leak threat is in G, and this
    # is the edge an IR that proves NoExfiltration must not have dropped.
    detail["dropped_edge"] = "%s -> %s" % (src.node_id,
                                           sink_method.full_name)
    return True, detail


def _inflight_quantity(model, m):
    """Name the in-flight quantity for edge naming: an in-flight-named field
    of the model, else an in-flight-named parameter of the decision, else the
    canonical ``inflight`` (the lighthouse SpendCap state variable)."""
    for f in model.fields:
        if f.name in _INFLIGHT_NAMES:
            return f.name
    for a in m.args:
        if a in _INFLIGHT_NAMES:
            return a
    return "inflight"


def _budget_threat(model):
    """``(threat, detail)`` for ``SpendCap``.

    ``taintPath(G, P)`` = a structural bypass threat: the in-flight quantity
    does NOT reach the decision sum (settled-only accounting -- a parallel
    fire is invisible to the decision).  Returns ``(None, detail)`` when
    ``G`` has no budget decision at all (the cross-check does not apply).
    """
    found = _detect_budget(model)
    if found is None:
        return None, {"reason": "no budget decision in G"}
    m, local, cap, sum_fields, enforced = found
    detail = {
        "method": m.full_name,
        "sum_local": local,
        "cap": cap,
        "sum_over": list(sum_fields),
    }
    if enforced:
        # In-flight is in the sum: the cap is accounted for in G -- no
        # bypass threat.
        return False, detail
    # Settled-only sum: the in-flight -> sum dataflow edge is absent from G;
    # a model that proves the cap on top of it dropped (or over-invented) a
    # taint-critical edge.
    detail["dropped_edge"] = "%s -> %s#%s" % (
        _inflight_quantity(model, m), m.full_name, local)
    return True, detail


def _shape_of(ir, shape):
    """Resolve the P1 shape: the explicit argument, else the IR metadata's
    ``pattern``.  Strict: a CPG cross-check on a non-P1 IR is a wiring bug."""
    if shape is not None:
        if shape not in _SHAPES:
            raise ValueError("unknown P1 shape: %r" % (shape,))
        return shape
    meta = dict(getattr(ir, "metadata", {}) or {})
    pat = meta.get("pattern")
    if pat in _SHAPES:
        return pat
    raise ValueError("cannot determine the P1 shape for the cross-check "
                     "(ir.metadata['pattern'] = %r)" % (pat,))


# ---------------------------------------------------------------------------
# (S): the check + the fail-closed application
# ---------------------------------------------------------------------------
def check_abstraction_soundness(cpg, ir, verdict, shape=None):
    """Implement (S): ``taintPath(G, P) => not Proven(M(A(G)), P)``.

    A **pure function** of its inputs (no engine, no I/O):

    * ``cpg``     -- the ground-truth :class:`rot.frontends.cpg_model.CpgModel`
                     scrape ``G`` (the code as scraped, not source text).
    * ``ir``      -- the lowered :class:`rot.ir.ProtocolIR` ``A(G)`` (used for
                     the shape when ``shape`` is not given).
    * ``verdict`` -- the engine's :class:`rot.verdicts.Verdict`.
    * ``shape``   -- ``"budget"`` / ``"label_flow"`` (default: read from
                     ``ir.metadata["pattern"]``).

    Returns a :class:`SoundnessResult` (one of ``AGREEMENT`` / ``UNSOUND`` /
    ``CONCURRENCY_ONLY`` / ``NOT_APPLICABLE``).
    """
    if not isinstance(cpg, CpgModel):
        raise TypeError("check_abstraction_soundness expects a CpgModel, "
                        "got %r" % type(cpg).__name__)
    if not isinstance(verdict, verdicts.Verdict):
        raise TypeError("check_abstraction_soundness expects a Verdict, "
                        "got %r" % type(verdict).__name__)
    shp = _shape_of(ir, shape)

    if shp == _SHAPE_LABEL_FLOW:
        threat, detail = _label_flow_threat(cpg)
    else:
        threat, detail = _budget_threat(cpg)

    status = verdict.status
    if status not in (verdicts.PROVEN, verdicts.VIOLATED):
        # (S) constrains only decided verdicts; record the threat for context
        # and leave the verdict untouched.
        return SoundnessResult(
            NOT_APPLICABLE, shape=shp, threat=threat, detail=detail,
            note=("verdict %r is not a decided PROVEN/VIOLATED: (S) not "
                  "applied (threat=%s)" % (status, threat)))

    if threat is None:
        return SoundnessResult(
            NOT_APPLICABLE, shape=shp, threat=None, detail=detail,
            note="no %s control in the ground-truth CPG: the cross-check "
                 "does not apply" % shp)

    if status == verdicts.PROVEN:
        if threat:
            # (S) violated: G threatens P yet the model proved P -- the
            # abstraction dropped a taint-critical dataflow edge.  Fail
            # closed: never a silent PROVEN.
            return SoundnessResult(
                UNSOUND, shape=shp, threat=True,
                dropped_edge=detail.get("dropped_edge"), detail=detail,
                note=("taintPath(G, P) holds in the ground truth yet the "
                      "model proved P: the abstraction dropped a "
                      "taint-critical dataflow edge"))
        return SoundnessResult(
            AGREEMENT, shape=shp, threat=False, detail=detail,
            note="static and formal agree: the control is present in G "
                 "(no taint-critical threat) and the model proves it")

    # status == VIOLATED
    if threat:
        return SoundnessResult(
            AGREEMENT, shape=shp, threat=True, detail=detail,
            note="static and formal agree: the threat is in G and the "
                 "model confirms it with an exact witness")
    return SoundnessResult(
        CONCURRENCY_ONLY, shape=shp, threat=False, detail=detail,
        note=("the model checker found a violation the static single-path "
              "analysis does not see (a concurrency-only witness)"))


def _copy_verdict(verdict, **overrides):
    """A fresh :class:`Verdict` carrying every field of ``verdict`` with
    ``overrides`` applied (the apply step never mutates in place)."""
    # ``status`` is the first positional arg of Verdict.__init__; pull it out
    # of the overrides so it is never passed twice (positional + **kwargs).
    status = overrides.pop("status", verdict.status)
    kwargs = {
        "counterexample": verdict.counterexample,
        "assumptions": list(verdict.assumptions),
        "soundness": list(verdict.soundness),
        "evidence": dict(verdict.evidence),
        "cegar_iterations": verdict.cegar_iterations,
        "n_states": verdict.n_states,
        "note": verdict.note,
        "property_kind": verdict.property_kind,
        "violation_code": verdict.violation_code,
        "trace": list(verdict.trace) if verdict.trace is not None else None,
        "advisories": list(verdict.advisories),
        "discharge": verdict.discharge,
        "fairness_label": verdict.fairness_label,
    }
    kwargs.update(overrides)
    return verdicts.Verdict(status, verdict.property_name,
                            verdict.engine, **kwargs)


def _downgrade_proven(verdict, result):
    """Fail-closed: ``PROVEN -> UNKNOWN`` (the (S) cell it forbids).

    The advisory ``unsound_abstraction`` is attached (loud, non-fatal) and
    the dropped edge is *named* -- on the note, in the soundness notes, and
    (via the evidence stamp in ``verify_candidate``) on
    ``evidence["abstraction_soundness"].dropped_edge``.
    """
    edge = result.dropped_edge or "(see evidence[\"abstraction_soundness\"])"
    note = ("downgraded PROVEN -> UNKNOWN by the CPG-3 soundness cross-check "
            "(S): taintPath(G, P) holds in the ground-truth CPG (%s) yet the "
            "model proved P -- the abstraction dropped a taint-critical "
            "dataflow edge.  Dropped edge: %s.  %s"
            % (result.shape, edge, result.note))
    soundness = list(verdict.soundness)
    soundness.append("CPG-3 (S): dropped taint-critical edge %s" % edge)
    return _copy_verdict(
        verdict,
        status=verdicts.UNKNOWN,
        counterexample=None,
        trace=None,
        violation_code=None,
        soundness=soundness,
        note=note,
        advisories=list(verdict.advisories) + [verdicts.UNSOUND_ABSTRACTION],
    )


def _tag(verdict, code):
    """Attach an advisory code (the ``concurrency_only`` tag) without
    changing the verdict status -- the tag never hides the violation."""
    return _copy_verdict(verdict, advisories=list(verdict.advisories) + [code])


def apply_soundness(verdict, result):
    """Apply a :class:`SoundnessResult` to a :class:`Verdict` (fail-closed).

    * ``UNSOUND`` on a PROVEN verdict   -> a new UNKNOWN verdict: advisory
      ``unsound_abstraction``, the dropped edge named, no counterexample.
    * ``CONCURRENCY_ONLY`` on a VIOLATED verdict -> the same verdict tagged
      with the advisory ``concurrency_only`` (witness preserved).
    * ``AGREEMENT`` / ``NOT_APPLICABLE`` -> the verdict, unchanged.

    Returns the verdict (possibly a fresh object); never raises on valid
    input.
    """
    if result.status == UNSOUND and verdict.status == verdicts.PROVEN:
        return _downgrade_proven(verdict, result)
    if (result.status == CONCURRENCY_ONLY
            and verdict.status == verdicts.VIOLATED):
        return _tag(verdict, verdicts.CONCURRENCY_ONLY)
    return verdict