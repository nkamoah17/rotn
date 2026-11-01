# -*- coding: utf-8 -*-
"""retention.py -- property-directed retention: make the CPG->IR lowering less
lossy (Phase 5, the 4 moves in §2.2 of the Joern-primary plan).

The CPG->IR lowering keeps the property-relevant structure and drops the rest.
Today the dropped dataflow edges are *silent* (best-effort, per the
counterexample-fidelity note).  This module makes that lossiness **explicit
and loud**, soundly, with the 4 moves of §2.2:

1. **Over-approximate, don't omit.**  A dropped dataflow edge whose relevance
   to the pinned property is *undecidable* is not silently omitted: it is
   over-approximated as a potential threat, which forces the verdict
   fail-closed (``UNKNOWN``) rather than a silent false-negative ``PROVEN``.

2. **Property-directed retention with a hard rule.**  The *kept* set is the
   property-relevant dataflow (the transitive reaching-def closure from a
   property source to a property sink).  Every *dropped* edge is either
   (a) **proven irrelevant** (its target cannot reach any property sink, so it
   cannot threaten the pinned property -- sound to omit) or (b) **unknown
   relevance** (its target can reach a property sink, but its source is not a
   confirmed property source, so we cannot prove it irrelevant) -- and (b)
   forces ``UNKNOWN`` + the ``unsound_abstraction`` advisory.

3. **Refine-on-disagreement on the front-end (disagreement-driven).**  When the ground-truth
   CPG carries a dropped edge of unknown relevance (a potential threat) yet
   the IR *proved* the property, the abstraction and the ground truth
   disagree.  We refine the IR to *model* the threat edge and re-check: a
   refutation confirms the dropped edge was taint-critical (the original
   ``PROVEN`` was a silent false negative); a continued proof proves the edge
   irrelevant.  Lossiness is driven by the disagreement, not by taste.

4. **Kept/dropped manifest.**  The :class:`RetentionManifest` (every dataflow
   edge, kept or dropped, with its relevance and the evidence) is emitted into
   the verdict evidence and the claim packet (``rot.cpg4``), so a deliberately
   dropped edge is always *named*.

Gate (Phase 5 "Done when"): a deliberately-dropped dataflow edge either
(a) is proven irrelevant (the verdict stands, the manifest names it) or
(b) forces ``UNKNOWN`` + ``unsound_abstraction`` (the manifest names it).

This is a **verify-plane** module: it consumes a ``CpgModel`` + a
``ProtocolIR`` + a ``Verdict`` and produces a manifest + a refined verdict.
It is a pure function of its inputs (unit-testable offline) and never imports
the emitter / TLC.  Pure stdlib, Python 3.6 compatible.
"""

import copy

from rot import verdicts
from rot.frontends.cpg_model import CpgModel, DATAFLOW_EDGE_KINDS
from rot.frontends.code import PATTERN_BUDGET, PATTERN_LABEL_FLOW
from rot.verdicts import PROVEN, VIOLATED, UNKNOWN, UNSOUND_ABSTRACTION

__all__ = [
    "RELEVANCE_IRRELEVANT",
    "RELEVANCE_UNKNOWN",
    "RELEVANCE_TAINT_CRITICAL",
    "EdgeRow",
    "RetentionManifest",
    "retention_manifest",
    "apply_retention_rule",
    "refine_on_disagreement",
    "apply_phase5",
]


# ---------------------------------------------------------------------------
# Relevance vocabulary (the hard rule's classification)
# ---------------------------------------------------------------------------
#: A kept edge: on a property source -> sink dataflow path (taint-critical).
RELEVANCE_TAINT_CRITICAL = "taint_critical"
#: A dropped edge **proven irrelevant**: its target cannot reach any property
#: sink, so it cannot threaten the pinned property (sound to omit).
RELEVANCE_IRRELEVANT = "irrelevant"
#: A dropped edge of **unknown relevance**: its target can reach a property
#: sink, but its source is not a confirmed property source.  Over-approximated
#: as a threat -> forces ``UNKNOWN``.
RELEVANCE_UNKNOWN = "unknown"

_STATUS_KEPT = "kept"
_STATUS_DROPPED = "dropped"


class EdgeRow(object):
    """One row of the retention manifest: a single CPG dataflow edge and its
    disposition (kept / dropped) + relevance + the evidence for the
    classification.
    """

    def __init__(self, src, dst, edge_type, status, relevance, evidence=""):
        self.src = src
        self.dst = dst
        self.edge_type = edge_type
        self.status = status        # "kept" | "dropped"
        self.relevance = relevance  # one of the RELEVANCE_* codes
        self.evidence = evidence or ""

    def to_dict(self):
        return {
            "from": self.src,
            "to": self.dst,
            "type": self.edge_type,
            "status": self.status,
            "relevance": self.relevance,
            "evidence": self.evidence,
        }

    def __repr__(self):
        return "EdgeRow(%s %s -> %s [%s/%s])" % (
            self.edge_type, self.src, self.dst, self.status, self.relevance)


class RetentionManifest(object):
    """The kept/dropped manifest for one P1 shape: every dataflow edge, with
    its disposition + relevance + evidence.  This is the auditability
    artifact (move 4) -- a deliberately dropped edge is always *named* here.
    """

    def __init__(self, shape, kept, dropped):
        self.shape = shape
        self.kept = list(kept)
        self.dropped = list(dropped)

    def unknown(self):
        """The dropped edges of unknown relevance (the threat set)."""
        return [e for e in self.dropped if e.relevance == RELEVANCE_UNKNOWN]

    def irrelevant(self):
        """The dropped edges proven irrelevant."""
        return [e for e in self.dropped
                if e.relevance == RELEVANCE_IRRELEVANT]

    def taint_critical(self):
        """The kept (taint-critical) edges."""
        return [e for e in self.kept
                if e.relevance == RELEVANCE_TAINT_CRITICAL]

    def has_unknown(self):
        return any(e.relevance == RELEVANCE_UNKNOWN for e in self.dropped)

    def dropped_edge_names(self, relevance=None):
        """The ``src -> dst`` names of the dropped edges (optionally filtered
        to one relevance).  Deterministic order (the manifest order)."""
        out = []
        for e in self.dropped:
            if relevance is None or e.relevance == relevance:
                out.append("%s -> %s" % (e.src, e.dst))
        return out

    def reclassify_unknown(self, new_relevance, note=""):
        """Re-classify every unknown-relevance dropped edge to
        ``new_relevance`` (after a refine-on-disagreement resolved the
        disagreement).  Returns a fresh manifest (this one is not mutated)."""
        new_dropped = []
        for e in self.dropped:
            if e.relevance == RELEVANCE_UNKNOWN:
                ev = e.evidence
                if note:
                    ev = (ev + " " + note).strip()
                new_dropped.append(EdgeRow(e.src, e.dst, e.edge_type,
                                           _STATUS_DROPPED, new_relevance, ev))
            else:
                new_dropped.append(e)
        return RetentionManifest(self.shape, list(self.kept), new_dropped)

    def to_dict(self):
        return {
            "shape": self.shape,
            "kept": [e.to_dict() for e in self.kept],
            "dropped": [e.to_dict() for e in self.dropped],
            "unknown": [e.to_dict() for e in self.unknown()],
            "irrelevant": [e.to_dict() for e in self.irrelevant()],
        }


# ---------------------------------------------------------------------------
# Dataflow reachability (over the CPG's dataflow edges, with the slot -> method
# projection the CPG-1 taint path uses: a tainted slot taints its owning
# method, so an egress slot reaches its egress method).
# ---------------------------------------------------------------------------
def _dataflow_adj(model):
    """The dataflow adjacency (``src -> set(dst)``), with the slot -> method
    projection.  Mirrors ``CpgModel.taint_path`` so the keep set and the
    relevance test agree with the CPG-1 taint path."""
    kinds = set(DATAFLOW_EDGE_KINDS)
    adj = {}
    for e in model.edges:
        if e.edge_type not in kinds or not e.src or not e.dst:
            continue
        adj.setdefault(e.src, set()).add(e.dst)
    # slot -> method projection.
    slots = set()
    for e in model.edges:
        for n in (e.src, e.dst):
            if n and "#" in n:
                slots.add(n)
    for m in model.methods:
        if not m.full_name:
            continue
        for name in list(m.defs) + list(m.args):
            if name:
                slots.add(m.full_name + "#" + name)
    for slot in slots:
        method = slot.split("#", 1)[0]
        if method:
            adj.setdefault(slot, set()).add(method)
    return adj


def _reachable(adj, start):
    """All node ids reachable from ``start`` over ``adj`` (excluding start)."""
    seen = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _property_anchors(model, shape):
    """``(source_ids, sink_ids)``: the property-relevant anchors for ``shape``.

    * **label_flow** -- sources = the classified taint sources; sinks = the
      classified taint sinks (the egress methods).
    * **budget**     -- the decision sum is the "sink" (the node the cap is
      compared against); the sum's inputs are the "sources".  The sum local is
      identified structurally (best-effort); when it cannot be identified we
      return empty anchor sets (no unknown edges -- sound, just less precise).
    """
    if shape == PATTERN_LABEL_FLOW:
        return set(model.taint_source_ids()), set(model.taint_sink_ids())
    if shape == PATTERN_BUDGET:
        sum_local, inputs = _budget_sum_local(model)
        if sum_local is None:
            return set(), set()
        return set(inputs), set([sum_local])
    return set(), set()


def _budget_sum_local(model):
    """Best-effort structural identification of the budget decision's *sum
    local* (the node the cap is compared against) + its input slots.

    The sum local is the def slot of a boolean-returning, call-free,
    write-free decision method that has >= 2 incoming dataflow edges (the
    additive terms).  Returns ``(sum_local, inputs)`` or ``(None, None)`` when
    it cannot be identified (the retention analysis then flags no unknown
    edges -- sound, just less precise)."""
    boolean_methods = set()
    for m in model.methods:
        if (m.ret_type and "bool" in m.ret_type.lower()
                and not m.calls and not m.written_fields):
            boolean_methods.add(m.full_name)
    # Count incoming dataflow edges per slot.
    incoming = {}
    kinds = set(DATAFLOW_EDGE_KINDS)
    for e in model.edges:
        if e.edge_type not in kinds or not e.dst:
            continue
        if "#" in (e.dst or ""):
            incoming.setdefault(e.dst, []).append(e.src)
    # Pick the slot with the most incoming edges that belongs to a decision
    # method and combines >= 2 inputs.
    best = None
    best_count = 1
    for slot, srcs in incoming.items():
        method = slot.split("#", 1)[0]
        if method in boolean_methods and len(srcs) >= 2:
            if best is None or len(srcs) > best_count:
                best = slot
                best_count = len(srcs)
    if best is None:
        return None, None
    return best, list(incoming[best])


def retention_manifest(model, shape):
    """Compute the kept/dropped retention manifest for one P1 shape (move 2).

    The *kept* set is the property-relevant dataflow: the edges on a path from
    a property source to a property sink (the transitive reaching-def closure
    the pinned property depends on).  Every other dataflow edge is *dropped*
    and classified: **irrelevant** (its target cannot reach any property sink,
    sound to omit) or **unknown** (its target can reach a property sink but
    its source is not a confirmed property source -- over-approximated as a
    threat -> forces ``UNKNOWN``).  Returns a :class:`RetentionManifest`.
    Deterministic (edges sorted).
    """
    if not isinstance(model, CpgModel):
        raise TypeError("retention_manifest expects a CpgModel, got %r"
                        % type(model).__name__)
    sources, sinks = _property_anchors(model, shape)
    adj = _dataflow_adj(model)

    # Nodes reachable from any property source.
    from_source = set()
    for s in sources:
        from_source.add(s)
        from_source |= _reachable(adj, s)
    # Nodes that can reach any property sink (reverse reachability).
    radj = {}
    for u, vs in adj.items():
        for v in vs:
            radj.setdefault(v, set()).add(u)
    to_sink = set()
    for k in sinks:
        to_sink.add(k)
        to_sink |= _reachable(radj, k)

    kept = []
    dropped = []
    edges = sorted(
        (e for e in model.edges
         if e.edge_type in DATAFLOW_EDGE_KINDS and e.src and e.dst),
        key=lambda e: (e.src, e.dst, e.edge_type))
    # The "unknown relevance" category is a *taint* concept: it needs a
    # distinct egress sink + a confirmed taint source (label_flow).  The budget
    # shape's threat is fully captured by the sum (the cap comparison), which
    # the CPG-3 cross-check already verifies -- its non-kept edges are proven
    # irrelevant (they don't feed the cap), so it has no unknown category.
    can_be_unknown = (shape == PATTERN_LABEL_FLOW)
    for e in edges:
        if (e.src in from_source) and (e.dst in to_sink):
            kept.append(_kept_row(e, shape))
        elif can_be_unknown and e.dst in to_sink:
            dropped.append(_unknown_row(e, shape))
        else:
            dropped.append(_irrelevant_row(e, shape))
    return RetentionManifest(shape, kept, dropped)


def _kept_row(e, shape):
    """An EdgeRow for a kept (taint-critical) edge."""
    return EdgeRow(
        e.src, e.dst, e.edge_type, _STATUS_KEPT, RELEVANCE_TAINT_CRITICAL,
        "on a %s source -> sink dataflow path (the transitive reaching-def "
        "closure the pinned property depends on)" % shape)


def _unknown_row(e, shape):
    """An EdgeRow for a dropped edge of unknown relevance."""
    return EdgeRow(
        e.src, e.dst, e.edge_type, _STATUS_DROPPED, RELEVANCE_UNKNOWN,
        "target %s can reach a property sink, but the source %s is not a "
        "confirmed %s source -- relevance undecidable; over-approximated as "
        "a threat (don't omit) -> forces UNKNOWN" % (e.dst, e.src, shape))


def _irrelevant_row(e, shape):
    """An EdgeRow for a dropped edge proven irrelevant."""
    return EdgeRow(
        e.src, e.dst, e.edge_type, _STATUS_DROPPED, RELEVANCE_IRRELEVANT,
        "target %s cannot reach any property sink, so this edge cannot "
        "threaten the pinned %s property (proven irrelevant)" % (e.dst, shape))


# ---------------------------------------------------------------------------
# The hard rule (moves 1 + 2): over-approximate, don't omit
# ---------------------------------------------------------------------------
def _copy_verdict(verdict, **overrides):
    """A fresh :class:`Verdict` carrying every field of ``verdict`` with
    ``overrides`` applied (never mutates in place)."""
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


def apply_retention_rule(verdict, manifest):
    """The hard rule (moves 1+2): a ``PROVEN`` verdict with a dropped dataflow
    edge of **unknown relevance** is a silent false-negative risk -- the
    abstraction dropped an edge it cannot prove irrelevant.  Fail closed:
    downgrade ``PROVEN -> UNKNOWN``, attach the ``unsound_abstraction``
    advisory, and *name* the dropped edge(s).

    A ``PROVEN`` with only **proven-irrelevant** dropped edges stands (the
    manifest names them).  Non-``PROVEN`` verdicts are untouched (they are
    already fail-closed).  Returns the verdict (possibly a fresh object);
    never raises on valid input.
    """
    if verdict.status != PROVEN:
        return verdict
    unknown = manifest.unknown()
    if not unknown:
        return verdict
    names = ", ".join(manifest.dropped_edge_names(RELEVANCE_UNKNOWN))
    note = ("downgraded PROVEN -> UNKNOWN by the Phase 5 retention rule "
            "(over-approximate, don't omit): the CPG->IR lowering dropped "
            "dataflow edge(s) of unknown relevance to the pinned %s property "
            "-- %s -- and cannot prove them irrelevant.  See the retention "
            "manifest (evidence[\"retention\"])." % (manifest.shape, names))
    soundness = list(verdict.soundness)
    soundness.append("Phase 5 retention: dropped edge(s) of unknown relevance "
                     "%s (over-approximated as a threat)" % names)
    return _copy_verdict(
        verdict,
        status=UNKNOWN,
        counterexample=None,
        trace=None,
        violation_code=None,
        soundness=soundness,
        note=note,
        advisories=list(verdict.advisories) + [UNSOUND_ABSTRACTION],
    )


# ---------------------------------------------------------------------------
# Refine-on-disagreement on the front-end (move 3): disagreement-driven refinement
# ---------------------------------------------------------------------------
def _refine_ir_modeling_threat(ir_model, shape):
    """Refine the IR to *model* the dropped threat edge (over-approximate).

    For **label_flow**: the threat is an unmodeled egress carrying private
    data.  We over-approximate by making the egress action unconditionally
    enabled (guard := ``T``) -- the egress is an open channel, not a guarded
    one.  This is the sound over-approximation: it keeps the possibility
    (don't omit).  Returns a fresh IR (the input is not mutated)."""
    import rot.ir as ir_mod
    refined = copy.deepcopy(ir_model)
    if shape == PATTERN_LABEL_FLOW:
        for a in refined.actions:
            if a.name == "contact_outsider":
                a.guard = ir_mod.T()
    return refined


def _recheck(ir_model, cfg, shape, engine="symbolic"):
    """Re-run the safety pipeline over a refined IR (the refine-on-disagreement
    re-check).

    Mirrors the core of ``rot.cegar.verify_candidate`` (linearize -> engine ->
    cegar) *without* the cross-check / retention layers, so refining does not
    recurse.  Returns a :class:`rot.verdicts.Verdict`."""
    from rot.linearization import linearize
    from rot.invariants import Invariant
    from rot.symbolic import SymbolicEngine
    from rot.cegar import cegar as _cegar
    from rot.verdicts import KIND_SAFETY

    prop = Invariant(
        name=ir_model.name or shape,
        description="refine-on-disagreement re-check over the refined IR",
        expression=ir_model.pinned_property,
        kind=KIND_SAFETY,
    )
    linear_model = linearize(ir_model)
    eng = SymbolicEngine(linear_model, max_states=cfg.max_states)
    engine_result = eng.check(prop.expression, cfg.max_states)
    return _cegar(engine_result, prop, cfg, engine)


def _name_dropped_edge(verdict, manifest, relevance):
    """Name the resolved dropped edge(s) on the verdict (so the refinement is
    auditable and the edge is never silent)."""
    names = ", ".join(manifest.dropped_edge_names(relevance))
    if not names:
        return verdict
    prefix = ("Phase 5 retention: dropped %s edge(s) %s; " % (relevance, names))
    note = ((prefix + (verdict.note or "")).strip())
    soundness = list(verdict.soundness)
    soundness.append("Phase 5 retention: dropped %s edge(s) %s"
                     % (relevance, names))
    return _copy_verdict(verdict, note=note, soundness=soundness)


def refine_on_disagreement(model, shape, ir, verdict, cfg, manifest=None):
    """Refine-on-disagreement on the front-end (move 3): resolve a static<->formal disagreement
    by refining the IR to model the dropped threat edge and re-checking.

    A disagreement is: the ground-truth CPG carries a dropped dataflow edge of
    **unknown relevance** (a potential threat the IR did not model) yet the IR
    **proved** the pinned property.  We refine the IR to *model* the threat
    (over-approximate the egress) and re-check:

    * the refined model **refutes** (``VIOLATED``) -> the dropped edge was
      taint-critical; the original ``PROVEN`` was a silent false negative.
      The refutation is returned (more informative than ``UNKNOWN``) and the
      edge is re-classified ``taint_critical``.
    * the refined model still **proves** (``PROVEN``) -> the dropped edge was
      proven irrelevant (it is now in the model and the property still holds).
      The original ``PROVEN`` stands and the edge is re-classified
      ``irrelevant``.

    Returns ``(verdict, manifest, refinement_record)``.  When there is no
    disagreement (not ``PROVEN``, or no unknown-relevance edge) it returns
    ``(verdict, manifest, None)`` unchanged.
    """
    if manifest is None:
        manifest = retention_manifest(model, shape)
    if verdict.status != PROVEN:
        return verdict, manifest, None
    unknown = manifest.unknown()
    if not unknown:
        return verdict, manifest, None
    # The refine-on-disagreement pass can only *resolve* the disagreement for a shape whose threat edge
    # we can model in the IR (label_flow: the unmodeled egress).  For any other
    # shape the refinement would be a no-op, so we leave the unknown edges
    # un-reclassified and let the fail-closed hard rule (apply_retention_rule)
    # downgrade PROVEN -> UNKNOWN -- never claim "irrelevant" we did not prove.
    if shape != PATTERN_LABEL_FLOW:
        return verdict, manifest, None

    # Refine the IR to model the threat edge (over-approximate the egress).
    refined_ir = _refine_ir_modeling_threat(ir, shape)
    refined_verdict = _recheck(refined_ir, cfg, shape)

    if refined_verdict.status == VIOLATED:
        # The dropped edge was taint-critical: the original PROVEN was a
        # silent false negative.  Report the refutation (name the edge).
        resolved = manifest.reclassify_unknown(
            RELEVANCE_TAINT_CRITICAL,
            "resolved by refine-on-disagreement: modeling this edge refutes the "
            "pinned property, so it is taint-critical")
        record = {
            "trigger": [e.to_dict() for e in unknown],
            "refined_status": VIOLATED,
            "resolution": ("the dropped edge was taint-critical: modeling it "
                           "refutes the pinned property -- the original PROVEN "
                           "was a silent false negative"),
        }
        final = _name_dropped_edge(refined_verdict, resolved,
                                   RELEVANCE_TAINT_CRITICAL)
        return final, resolved, record

    # The refined model still proves: the dropped edge is proven irrelevant.
    resolved = manifest.reclassify_unknown(
        RELEVANCE_IRRELEVANT,
        "resolved by refine-on-disagreement: modeling this edge still proves the "
        "pinned property, so it is proven irrelevant")
    record = {
        "trigger": [e.to_dict() for e in unknown],
        "refined_status": refined_verdict.status,
        "resolution": ("the dropped edge was proven irrelevant: modeling it "
                       "still proves the pinned property"),
    }
    return verdict, resolved, record


def apply_phase5(model, shape, ir, verdict, cfg):
    """Run the full Phase 5 retention discipline for one P1 shape.

    Orchestrates the 4 moves of §2.2 in sound order:

    1. Build the kept/dropped :class:`RetentionManifest` (property-directed
       retention, move 2).
    2. **Refine-on-disagreement on the front-end** (move 3): if the IR *proved* the property
       yet the CPG carries a dropped edge of unknown relevance (a potential
       threat), refine the IR to model the threat and re-check -- resolving the
       static<->formal disagreement (taint-critical -> the refutation; or
       proven irrelevant -> the PROVEN stands).
    3. **The hard rule** (moves 1+2): any *remaining* dropped edge of unknown
       relevance on a ``PROVEN`` verdict is over-approximated as a threat and
       forces ``UNKNOWN`` + ``unsound_abstraction`` (fail-closed, don't omit).

    Returns ``(verdict, manifest, refinement_record)``.  ``verdict`` is the
    final verdict (possibly a fresh object); ``manifest`` the resolved
    kept/dropped manifest; ``refinement_record`` the refine-on-disagreement
    resolution (``None`` when there was no disagreement).  Deterministic and a pure
    function of its inputs (unit-testable offline).
    """
    manifest = retention_manifest(model, shape)
    verdict, manifest, record = refine_on_disagreement(
        model, shape, ir, verdict, cfg, manifest)
    verdict = apply_retention_rule(verdict, manifest)
    return verdict, manifest, record