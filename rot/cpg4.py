# -*- coding: utf-8 -*-
"""cpg4.py -- CPG-4: Product 1 (verifier) + Product 2 (coach) + the CPG-aware
claim packet.

This is the convergence of the CPG integration plan and the emblematic plan
(spec CPG-4): it lands **Product 1** (the verifier over a code-grounded
control) and **Product 2** (the coach: a computed ``to_proceed`` that cites
the guard's *source line*), and it produces the **claim packet** -- the
CPG->IR mapping as an auditable, deterministic, hashable artifact.

Phase 7 (evidence): the claim packet also carries the three evidence
layers -- ``two_layer`` (the static<->formal agreement, fail-closed),
``ab`` (the A/B winner table: the default frontend chosen by measurement,
not assertion), and ``wedge`` (Product 1's proof: the A/B winner
frontend + the two-layer verdict + the source-pinned counterexample).

The single-Candidate contract (one extraction, two sinks) is the
verifier/coach divergence mitigation (spec §7 risk table): the CPG is
extracted ONCE, lowered ONCE, and both the verifier and the coach consume the
*same* ``ProtocolIR``.  There is no re-derivation: the same scrape feeds the
N verticals, so the verifier and the coach can never disagree about what the
code enforces.

Gate (stop/go), exercised by ``tests/test_cpg4.py``:
  * one CPG -> N verticals (no re-derivation);
  * claim packet complete (non-claims + ledger + cross-check) and byte-stable;
  * the coach's ``to_proceed`` cites a real source line;
  * the manifest reproduces (same inputs -> same ``manifest_id``).

Honest boundaries (spec §6) are stated verbatim in every claim packet's
``non_claims``:
  * the CPG is static, single-iteration, per-path -- it grounds the *safety*
    IR + deadlock *evidence*, not liveness or concurrency bypass;
  * the CPG->IR translation is lossy; the counterexample->source mapping is
    best-effort, not a one-to-one guarantee;
  * Java-first, but the ``CpgModel`` JSON is language-agnostic;
  * the cross-check is one-directional for soundness (PROVEN implies no taint
    path), bidirectional for reporting;
  * the enhancement is upstream of the emitter (it changes the *input* to
    ``rot/emitter.py``, never the TLA+ it generates).

This is a **core** module (not a front-end): it orchestrates the front-end
producers (``rot.frontends.cpg``), the lowering (``rot.lower``), the verifier
(``rot.cegar``), and the coach (``rot.to_proceed``).  Pure stdlib, Python 3.6
compatible (no f-strings / dataclasses).
"""

import hashlib
import json

import rot.ir as ir
from rot.frontends.cpg import extract_cpg
from rot.frontends.cpg_model import CpgModel
from rot.lower import lower_candidate
from rot.cegar import verify_candidate
from rot.to_proceed import compute_to_proceed
from rot.verdicts import Verdict, VIOLATED
from rot.crosscheck import two_layer_agreement, TWO_LAYER_RULE
from rot.design_view import expr_to_str

__all__ = [
    "SCHEMA",
    "P1_SHAPES",
    "NON_CLAIMS",
    "manifest_id",
    "extract_all",
    "lower_all",
    "vertical",
    "verticals",
    "source_pin",
    "witness_lines",
    "allowed_channels",
    "coach_vertical",
    "abstraction_entries",
    "two_layer_section",
    "build_claim_packet",
    "claim_packet_for_cpg",
]

#: The claim-packet schema version (bump on any body-shape change).
SCHEMA = "rotn.claimpacket/v1"

#: The P1 shapes a CPG can carry (the two lighthouse verticals).
P1_SHAPES = ("budget", "label_flow")

#: The blocked (decision) action per shape in the lowered IR -- the action
#: whose guard is the pinned decision the coach reads ``to_proceed`` from.
_BLOCKED_ACTION = {
    "budget": "spend_ok",
    "label_flow": "contact_outsider",
}

#: The deny branch per shape (the *other* branch of the same policy decision):
#: enabled exactly where the allow-guard rejects.  Product 2 (P2): the coach
#: reads both branches from the one extraction -- ``to_proceed`` /
#: ``allowed_now`` off the allow-guard, ``contact_deny`` / ``spend_deny`` the
#: named deny action (one extraction, two sinks).
_DENY_ACTION = {
    "budget": "spend_deny",
    "label_flow": "contact_deny",
}

#: The honest boundaries (spec §6), stated verbatim in every claim packet's
#: ``non_claims``.  Locked -- edit only on a spec change.
NON_CLAIMS = [
    "the CPG is static, single-iteration, per-path: it grounds the safety IR "
    "(NoExfiltration, SpendCap, TypeInvariant) + deadlock evidence; it does "
    "NOT discharge liveness or concurrency bypass -- those still need the "
    "model checker (the CPG feeds it, it does not replace it)",
    "the CPG->IR translation is lossy (keeps security-relevant structure, "
    "drops the rest); the counterexample->source mapping is best-effort, "
    "not a one-to-one guarantee",
    "Java-first (Joern's strongest front-end), but the CpgModel JSON is "
    "language-agnostic -- a C#/Go/Python CPG tool can emit the same JSON "
    "later; the front-end is written against the CpgModel, not the scrape",
    "the cross-check is one-directional for soundness (PROVEN implies no "
    "taint path) and bidirectional for reporting (concurrency-only witnesses "
    "are the model checker's value-add, tagged, not errors)",
    "the enhancement is upstream of the emitter: the CPG changes the input "
    "to rot/emitter.py, never the TLA+ it generates",
]


# ---------------------------------------------------------------------------
# canonical hashing (deterministic; same discipline as rot.manifest)
# ---------------------------------------------------------------------------
def _json_default(o):
    # last-resort serializer: anything exposing to_dict() round-trips
    to_dict = getattr(o, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return repr(o)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=_json_default)


def manifest_id(body):
    """The SHA-256 identity of a claim-packet body (everything except the
    ``manifest_id`` field itself).  The manifest *reproduces*: the same
    inputs yield the same canonical body and hence the same ``manifest_id``.
    """
    return "sha256:" + hashlib.sha256(
        _canonical(body).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# one CPG -> N verticals (no re-derivation)
# ---------------------------------------------------------------------------
def _as_model(model):
    if not isinstance(model, CpgModel):
        raise TypeError("expected a CpgModel, got %r" % type(model).__name__)
    return model


def extract_all(model, shapes=None):
    """Extract the P1 controls in ``model`` (one CPG -> N candidates).

    The CPG scrape (``model``) is consumed once; each shape is extracted
    independently from the *same* model (no re-derivation of the scrape).
    Returns ``{shape: Candidate}`` for the shapes that carry a control
    (out-of-scope shapes are omitted -- they are reported, not claimed).
    """
    _as_model(model)
    shapes = list(shapes) if shapes is not None else list(P1_SHAPES)
    out = {}
    for shape in shapes:
        c = extract_cpg(model, shape=shape)
        if c.is_control:
            out[shape] = c
    return out


def lower_all(candidates):
    """Lower each candidate to a ``ProtocolIR`` (one lowering per control).

    Returns ``{shape: ProtocolIR}``.  A candidate that is not a control
    (out-of-scope) raises the honest ``ValueError`` from
    :func:`rot.lower.lower_candidate` (fail-closed, never a silent UNKNOWN).
    """
    return dict((shape, lower_candidate(c))
                for shape, c in sorted(candidates.items()))


def vertical(model, shape, cfg, cpg=None):
    """One vertical: extract -> lower -> verify (with the CPG-3 cross-check).

    Returns ``{"candidate": Candidate, "ir": ProtocolIR, "verdict": Verdict}``.
    ``cpg`` is the ``CpgModel`` passed to the verifier for the static<->formal
    soundness cross-check (CPG-3); when omitted it defaults to ``model`` (the
    same scrape -- no re-derivation).  An out-of-scope shape lowers to the
    honest ``OUT_OF_SCOPE`` verdict (never dropped, never a silent UNKNOWN).
    """
    _as_model(model)
    c = extract_cpg(model, shape=shape)
    if c.out_of_scope:
        # E2: an honest OUT_OF_SCOPE -- the engine never runs, no IR is built.
        verdict = Verdict.out_of_scope(shape, "symbolic", reason=c.reason)
        return {"candidate": c, "ir": None, "verdict": verdict}
    ir_model = lower_candidate(c)
    verdict = verify_candidate(ir_model, cfg, engine="symbolic",
                               cpg=(cpg if cpg is not None else model))
    return {"candidate": c, "ir": ir_model, "verdict": verdict}


def verticals(model, cfg, shapes=None):
    """N verticals from one CPG (no re-derivation).

    The CPG scrape is consumed once; each vertical (shape) extracts, lowers,
    and verifies from the *same* model.  Returns ``{shape: vertical}`` where
    each vertical is ``{"candidate", "ir", "verdict"}``.  Out-of-scope shapes
    are included with their honest ``OUT_OF_SCOPE`` verdict -- never dropped.
    """
    out = {}
    for shape in (list(shapes) if shapes is not None else list(P1_SHAPES)):
        out[shape] = vertical(model, shape, cfg)
    return out


# ---------------------------------------------------------------------------
# source pinning (the citable source line)
# ---------------------------------------------------------------------------
def source_pin(candidate):
    """The guard's source line (citable), from the candidate's provenance.

    Returns a dict with the function, its ``fullName``, the ``filename``, and
    the ``start_line``/``end_line`` range -- the line an auditor opens.  ``{}``
    when the candidate carries no source line (e.g. an out-of-scope
    candidate).  Deterministic.
    """
    p = getattr(candidate, "provenance", None) or {}
    out = {}
    for k in ("function", "fullName", "filename", "source"):
        if p.get(k) is not None:
            out[k] = p[k]
    if p.get("start_line") is not None:
        out["start_line"] = p["start_line"]
    if p.get("end_line") is not None:
        out["end_line"] = p["end_line"]
    return out


def _where(pin):
    if pin.get("filename") and pin.get("start_line") is not None:
        return "%s:%s" % (pin["filename"], pin["start_line"])
    return pin.get("fullName") or ""


def witness_lines(candidate, witness):
    """Map a violation ``witness`` (a state dict) to the source lines that
    ground it (best-effort, per spec §6 -- not a one-to-one guarantee).

    Each witness variable is tied to the decision method's line range (the
    ``source_pin``) and tagged with its role (a budget sum field / a
    label-flow private datum).  Returns a deterministic list of
    ``{"variable", "line", "filename", "role"}`` rows; ``[]`` when there is no
    witness or no source line.
    """
    if not witness:
        return []
    p = getattr(candidate, "provenance", None) or {}
    pin = source_pin(candidate)
    line = pin.get("start_line")
    filename = pin.get("filename")
    pattern = getattr(candidate, "pattern", None)
    sum_over = set(p.get("sum_over") or []) if pattern == "budget" else set()
    rows = []
    for var in sorted(witness):
        if pattern == "budget" and var in sum_over:
            role = "budget sum field"
        elif pattern == "label_flow" and var == "holding_private":
            role = "private (labeled) datum"
        elif pattern == "label_flow" and var == "exfiltrated":
            role = "egress outcome"
        else:
            role = "state"
        rows.append({"variable": var, "line": line, "filename": filename,
                     "role": role})
    return rows


def allowed_channels(candidate):
    """The **derived** allowed-channel set for a label_flow control (CPG-2):
    the CPG's classified egresses (taint sinks) and whether each is guarded.

    For a budget control this is ``[]`` (channels are not part of that shape).
    Deterministic; empty when the candidate is not a label_flow control or
    carries no classified sink.
    """
    p = getattr(candidate, "provenance", None) or {}
    if getattr(candidate, "pattern", None) != "label_flow":
        return []
    sink = p.get("sink")
    if sink is None:
        return []
    pin = source_pin(candidate)
    guard = p.get("guard")
    return [{
        "sink": sink,
        "line": pin.get("start_line"),
        "filename": pin.get("filename"),
        "guarded": bool(guard),
        "guard": guard,
        "status": "controlled" if guard else "bypassable",
    }]


# ---------------------------------------------------------------------------
# Product 2: the coach (to_proceed + why, source-pinned)
# ---------------------------------------------------------------------------
def coach_vertical(model, shape, cfg, cpg=None):
    """The P2 coach on a CPG-derived vertical (one extraction, two sinks).

    Runs :func:`rot.to_proceed.compute_to_proceed` on the CPG-derived IR and
    pins the refusal's ``why`` / ``to_proceed`` to the guard's **source line**
    (citable).  For the label_flow shape, the allowed-channel set is the
    **derived** label flow (the CPG's classified egresses + their guards).

    Returns a deterministic dict::

        {
          "shape":            "budget" | "label_flow",
          "action":           the blocked (decision) action name,
          "verdict":          the vertical's verdict status,
          "to_proceed":       compute_to_proceed(...) + {"source": <pin>},
          "allowed_now":      not to_proceed["blocked"] (the same guard read
                              now: the two readings never disagree),
          "deny_branch":      {"action": "contact_deny" | "spend_deny",
                               "guard": ...}  (the other branch of the same
                              decision, from the same IR),
          "why":              a plain-English refusal citing the source line,
          "source":           the guard's source line (citable),
          "allowed_channels": [ ... ]   # label_flow only (derived label flow)
        }
    """
    _as_model(model)
    v = vertical(model, shape, cfg, cpg=cpg)
    candidate = v["candidate"]
    ir_model = v["ir"]
    verdict = v["verdict"]
    pin = source_pin(candidate)
    action_names = ([a.name for a in ir_model.actions]
                    if ir_model is not None else [])
    action = _BLOCKED_ACTION.get(shape)
    if action is not None and action not in action_names:
        action = None

    if action is not None:
        tp = compute_to_proceed(ir_model, action, verdict.counterexample)
        tp = dict(tp)
        tp["source"] = pin          # the guard's source line (citable)
    else:
        tp = {"action": None, "blocked": False, "source": pin,
              "note": "no decision action recognized for this shape"}

    where = _where(pin)
    if candidate.is_control and verdict.status == VIOLATED:
        if shape == "budget":
            why = ("the '%s' decision (line %s) admits the spend: the sum it "
                   "charges is settled-only, so a parallel in-flight fire is "
                   "invisible to it -- the cap is bypassable"
                   % (pin.get("function") or "decision", where))
        else:
            why = ("the '%s' egress (line %s) is unguarded: the private datum "
                   "reaches the classified sink %s -- an exfiltration is "
                   "reachable" % (pin.get("function") or "egress", where,
                                  (candidate.provenance or {}).get("sink")))
    elif candidate.is_control:
        why = ("the '%s' control (line %s) is enforced as extracted; the "
               "verifier confirms it" % (pin.get("function") or "control",
                                         where))
    else:
        why = ("no P1 %s control was extracted (out of scope) -- nothing to "
               "coach" % shape)

    out = {
        "shape": shape,
        "action": action,
        "verdict": verdict.status,
        "to_proceed": tp,
        # Product 2 (P2): ``allowed_now`` is the complement of the computed
        # ``blocked`` reading of the SAME guard -- the two readings of one
        # extraction never disagree (blocked XOR allowed_now).
        "allowed_now": (not tp.get("blocked", False)),
        "why": why,
        "source": pin,
    }
    # Product 2 (P2): the deny branch -- the *other* branch of the same
    # policy decision (``contact_deny`` / ``spend_deny``), read from the
    # SAME IR (one extraction, two sinks): the allow-guard's enabling
    # condition (to_proceed) and the named deny action are two readings of
    # the one extracted control.
    deny_name = _DENY_ACTION.get(shape)
    if ir_model is not None and deny_name is not None:
        for a in ir_model.actions:
            if a.name == deny_name:
                out["deny_branch"] = {
                    "action": a.name,
                    "guard": expr_to_str(a.guard),
                }
                break
    if shape == "label_flow":
        out["allowed_channels"] = allowed_channels(candidate)
    return out


# ---------------------------------------------------------------------------
# the claim packet (the CPG->IR mapping as an auditable artifact)
# ---------------------------------------------------------------------------
def _entry(feature, status, evidence, abstraction, risk):
    return ir.AbstractionEntry(feature, status, evidence, abstraction,
                               risk).to_dict()


def abstraction_entries(candidate):
    """The CPG->IR mapping for one control, as ``AbstractionEntry`` rows (the
    auditable abstraction manifest).

    Each row is a ``(feature, status, evidence, abstraction, risk)``
    quadruple grounded in the candidate's provenance (the code-level
    kept/dropped detail).  ``status`` is one of
    ``covered | assumed | unverified``.  Deterministic.
    """
    p = getattr(candidate, "provenance", None) or {}
    pin = source_pin(candidate)
    where = _where(pin)
    enforced = bool(getattr(candidate, "enforced", False))
    pattern = getattr(candidate, "pattern", None)
    entries = []
    if pattern == "budget":
        sum_over = p.get("sum_over") or []
        cap = p.get("cap")
        entries.append(_entry(
            feature="cap enforcement (in-flight charging)",
            status="covered" if enforced else "unverified",
            evidence="decision %s at %s: sum over [%s] checked against cap %s"
                     % (p.get("function"), where, ", ".join(sum_over), cap),
            abstraction="settled + in-flight + this request <= cap (a "
                        "temporal sum over request events)",
            risk="none (the sum charges in-flight)" if enforced
                 else "the sum is settled-only: a parallel in-flight fire is "
                      "invisible to the decision (bypassable)"))
        entries.append(_entry(
            feature="cap constant",
            status="assumed",
            evidence="cap=%s (lighthouse default; the CPG scrape carries no "
                     "literals)" % (getattr(candidate, "params", {})
                                   .get("cap")),
            abstraction="the numeric cap is fixed to the lighthouse default "
                        "(100/200), not read from the CPG",
            risk="a different true cap would change the verdict; the cap is "
                 "an assumption, not a claim"))
    elif pattern == "label_flow":
        guard = p.get("guard")
        sink = p.get("sink")
        src = p.get("private_source")
        reason = p.get("source_reason")
        entries.append(_entry(
            feature="egress guard",
            status="covered" if enforced else "unverified",
            evidence="egress %s at %s: %s" % (sink, where,
                                              ("guarded by %r" % guard)
                                              if guard else "unguarded"),
            abstraction="egress gated by a mutable boolean (a controlled "
                        "channel)" if enforced
            else "egress unguarded (an exfiltration is reachable)",
            risk="none (the egress is gated)" if enforced
                 else "a private->sink dataflow is a leak (bypassable)"))
        entries.append(_entry(
            feature="private source / sink classification",
            status="assumed",
            evidence="source %s (reason: %s); sink %s" % (src, reason, sink),
            abstraction="conservative name-based source/sink classifier "
                        "(not full taint-tracking)",
            risk="a source/sink that evades the name heuristic is not "
                 "classified (out_of_scope, never silent)"))
    return entries


def two_layer_section(verticals_dict):
    """The **two-layer agreement** per shape (Phase 7, Product 1).

    Layer A (formal): the engine verdict.  Layer B (static<->formal): the
    CPG-3 soundness record (``evidence["abstraction_soundness"]``; ``None``
    when the vertical has no CPG ground truth -- the static layer does not
    apply).  The join (``rot.crosscheck.two_layer_agreement``) is
    fail-closed (``TWO_LAYER_RULE``): PROVEN requires **both** layers -- the
    formal layer proves AND the static ground truth carries no
    taint-critical threat to the pinned property; a static threat to a
    PROVEN blocks the proof (UNKNOWN + the NAMED disagreement); a VIOLATED
    stands (never upgraded, never mended by the static layer).

    A **pure function** of the verticals' verdicts (no mutation, no I/O) --
    deterministic, so it is safe inside the claim-packet body.  Returns
    ``{shape: {formal, static, status, agreement, disagreement, rule}}``.
    """
    out = {}
    for shape in sorted(verticals_dict):
        v = verticals_dict.get(shape)
        if not isinstance(v, dict):
            continue
        verdict = v.get("verdict")
        if verdict is None or not hasattr(verdict, "status"):
            continue
        static = (verdict.evidence or {}).get("abstraction_soundness")
        if not isinstance(static, dict):
            static = None
        tl = two_layer_agreement(verdict.status, static)
        out[shape] = {
            "formal": verdict.status,
            "static": (static or {}).get("status"),
            "status": tl.status,
            "agreement": (tl.disagreement == ""),
            "disagreement": tl.disagreement,
            "rule": TWO_LAYER_RULE,
        }
    return out


def build_claim_packet(model, verticals_dict, coach_dict, shapes=None, ab=None):
    """Assemble the CPG-4 claim packet (the CPG->IR mapping as an auditable,
    deterministic, hashable artifact).

    Parameters
    ----------
    model : CpgModel
        The CPG scrape (the source of provenance).
    verticals_dict : dict
        ``{shape: {"candidate", "ir", "verdict"}}`` from :func:`verticals`.
    coach_dict : dict
        ``{shape: coach record}`` from :func:`coach_vertical`.
    shapes : list, optional
        The vertical order; defaults to the sorted keys of ``verticals_dict``.
    ab : dict, optional
        The A/B winner table (``rot.ab.winner_table``; the default frontend,
        chosen by measurement).  Included in the body when given (the
        ``ab`` section + the ``wedge`` frontend pointer).

    Returns
    -------
    dict
        A JSON-serialisable, deterministic claim packet with: ``schema``,
        ``source``, ``shapes``, ``verticals`` (candidate + verdict + citable
        source + witness-lines), ``abstraction_manifest`` (the
        ``AbstractionEntry`` rows), ``retention`` (the lossiness manifest),
        ``two_layer`` (the two-layer agreement per shape, fail-closed),
        ``ab`` (the A/B winner table, when given), ``wedge`` (Product 1: the
        A/B winner frontend + the two-layer verdict + the source-pinned
        counterexample -- the open-source wedge's proof), ``non_claims`` (the
        spec §6 honest boundaries), ``coach`` (the source-pinned
        ``to_proceed``), ``ledger`` (the ordered derivation trail), and
        ``manifest_id`` (SHA-256 over the canonical body -- the manifest
        reproduces).
    """
    _as_model(model)
    if shapes is None:
        shapes = sorted(verticals_dict)
    meta = dict(getattr(model, "meta", None) or {})
    verticals_out = {}
    retention_out = {}
    counterexample_out = {}
    two_layer_out = two_layer_section(verticals_dict)
    ledger = []
    abstraction = []

    for shape in list(shapes):
        v = verticals_dict.get(shape)
        if v is None:
            continue
        candidate = v["candidate"]
        ir_model = v["ir"]
        verdict = v["verdict"]
        pin = source_pin(candidate)

        # -- the ledger (the ordered derivation trail) --------------------
        ledger.append({
            "step": "extract", "shape": shape,
            "status": "control" if candidate.is_control else "out_of_scope",
            "pattern": candidate.pattern,
            "enforced": candidate.enforced,
            "reason": candidate.reason,
        })
        ledger.append({
            "step": "lower", "shape": shape,
            "ir": ir_model.name if ir_model is not None else None,
            "actions": (sorted(a.name for a in ir_model.actions)
                        if ir_model is not None else []),
            "pinned": (ir_model.pinned_property.to_dict()
                       if ir_model is not None else None),
        })
        ledger.append({
            "step": "verify", "shape": shape,
            "verdict": verdict.status,
            "witness": verdict.counterexample,
            "engine": verdict.engine,
        })
        xc = verdict.evidence.get("abstraction_soundness")
        ledger.append({
            "step": "crosscheck", "shape": shape,
            "result": (xc.get("result") if isinstance(xc, dict) else None),
            "advisories": verdict.advisories,
        })
        # Phase 5 (move 4): the retention manifest is part of the claim packet
        # -- a deliberately-dropped dataflow edge is *named* here (kept vs
        # dropped, each dropped edge classified irrelevant / unknown /
        # taint-critical), plus the refine-on-disagreement resolution.
        rt = verdict.evidence.get("retention")
        if isinstance(rt, dict):
            retention_out[shape] = dict(rt)
            rr = verdict.evidence.get("retention_refinement")
            if rr is not None:
                retention_out[shape]["refinement"] = rr
            ledger.append({
                "step": "retention", "shape": shape,
                "kept": len(rt.get("kept", [])),
                "dropped_irrelevant": len(rt.get("irrelevant", [])),
                "dropped_unknown": len(rt.get("unknown", [])),
            })
        c = coach_dict.get(shape)
        if c is not None:
            ledger.append({
                "step": "coach", "shape": shape,
                "action": c.get("action"),
                "source_line": (c.get("source") or {}).get("start_line"),
                "blocked": (c.get("to_proceed") or {}).get("blocked"),
            })

        # -- the vertical (candidate + verdict + citable source) ---------
        wl = witness_lines(candidate, verdict.counterexample)
        verticals_out[shape] = {
            "candidate": candidate.to_dict(),
            "ir": ir_model.name if ir_model is not None else None,
            "verdict": verdict.to_dict(),
            "source": pin,
            "witness_lines": wl,
        }
        # Product 1 (Phase 7): the source-pinned counterexample -- the
        # witness tied to the decision method's source line (a VIOLATED
        # names the line; a PROVEN carries no witness).
        counterexample_out[shape] = {
            "status": verdict.status,
            "witness": verdict.counterexample,
            "source": pin,
            "witness_lines": wl,
        }

        # -- the abstraction manifest (the CPG->IR mapping) --------------
        if candidate.is_control:
            abstraction.extend(abstraction_entries(candidate))

    # Product 1 (Phase 7): the wedge -- the open-source wedge's proof,
    # assembled from the packet's own sections (the A/B winner frontend +
    # the two-layer verdict + the source-pinned counterexample).
    wedge_out = {
        "product": "Product 1 (verifier)",
        "statement": ("A/B winner frontend + the two-layer verdict "
                      "(static<->formal, fail-closed) + the source-pinned "
                      "counterexample = the open-source wedge's proof"),
        "frontend": (ab.get("winner") if isinstance(ab, dict) else None),
        "two_layer": dict((s, two_layer_out[s]["status"])
                          for s in sorted(two_layer_out)),
        "counterexample": counterexample_out,
    }
    body = {
        "schema": SCHEMA,
        "source": {
            "cpg": meta.get("source", ""),
            "generated_by": meta.get("generatedBy", ""),
        },
        "shapes": list(shapes),
        "verticals": verticals_out,
        "abstraction_manifest": abstraction,
        "retention": retention_out,
        "two_layer": two_layer_out,
        "wedge": wedge_out,
        "non_claims": list(NON_CLAIMS),
        "coach": dict((k, coach_dict[k]) for k in sorted(coach_dict)),
        "ledger": ledger,
    }
    if isinstance(ab, dict):
        body["ab"] = ab
    out = dict(body)
    out["manifest_id"] = manifest_id(body)
    return out


def claim_packet_for_cpg(model, cfg, shapes=None, cpg=None, ab=None):
    """End-to-end CPG-4: one CPG -> N verticals -> the claim packet.

    Extracts, lowers, verifies (with the CPG-3 cross-check), coaches
    (source-pinned), and assembles the claim packet -- all over the *same*
    scrape (no re-derivation).  Returns the claim-packet dict (see
    :func:`build_claim_packet`).  The manifest reproduces: the same
    ``model`` + ``cfg`` yield the same ``manifest_id``.

    Phase 7 (evidence): the packet carries the three evidence layers --
    ``two_layer`` (the two-layer agreement, fail-closed), ``ab`` (the A/B
    winner table: the default frontend chosen by measurement, not
    assertion), and ``retention`` (the lossiness manifest).  ``ab``
    defaults to :func:`rotn_research.ab.winner_table` (``None`` when the
    research plane or the bench corpus is unavailable -- honest, never a loss).
    """
    _as_model(model)
    shapes = list(shapes) if shapes is not None else list(P1_SHAPES)
    if ab is None:
        # The A/B winner table lives in the research plane (the rotn-research
        # repo).  The product degrades honestly (ab=None) when the research
        # package is not installed -- never a loss, never a hard dependency.
        try:
            from rotn_research.ab import winner_table
        except ImportError:
            winner_table = None
        if winner_table is not None:
            try:
                ab = winner_table()
            except Exception:
                ab = None  # the bench corpus is unavailable: honest, not a loss.
    vdict = verticals(model, cfg, shapes=shapes)
    cdict = dict((s, coach_vertical(model, s, cfg, cpg=cpg)) for s in shapes)
    return build_claim_packet(model, vdict, cdict, shapes=shapes, ab=ab)