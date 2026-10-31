# -*- coding: utf-8 -*-
"""verdicts.py -- the final verdict layer and human-readable report.

Everything upstream (abstraction, engine, CEGAR) flows into a single
:class:`Verdict`: the auditable answer to "does this protocol satisfy the
pinned safety property, and under what recorded assumptions?"

Statuses:
  PROVEN    -- invariant holds.
  VIOLATED  -- a concrete, IR-feasible counterexample exists (a real bug).
  UNKNOWN   -- bounded/incomplete, or a counterexample could not be decided.
  UNSOUND   -- a counterexample in an over-approximation that CEGAR could not
               confirm concrete-feasible (do not trust).
  ERROR     -- a tool (TLC/Java) failed to run.

The five statuses stay fixed (Phase 6).  What differentiates the outcomes in
the auditable report is the *property kind* plus, on violations, a
*violation code*:

  property_kind -- the plane of the pinned property
                    (``safety``   : predicate must hold in every reachable state
                     ``liveness`` : a goal must be reachable within a bound),
                  mirroring ``rot.invariants.KIND_SAFETY`` / ``KIND_LIVENESS``.
  violation_code -- set on VIOLATED verdicts to name the class of failure:
                    ``POLICY_DENIAL``          a forbidden / over-privileged
                                               action was taken (safety).
                    ``LIVENESS_BOUND_EXCEEDED`` the goal was not reached within
                                               the recorded bound.
                    ``DEADLOCK``               the system stalled and cannot
                                               make further progress (set by
                                               the caller when the witness
                                               shows stagnation).

A Verdict is fully serialisable (to_dict / to_markdown / to_json) so it can be
dropped straight into ``out/`` as the deliverable. Pure stdlib, Python 3.6.
"""

import json

PROVEN = "proven"
VIOLATED = "violated"
UNKNOWN = "unknown"
UNSOUND = "unsound"
ERROR = "error"
# E2 (spec §7): a code-extraction claim that falls OUTSIDE the declared pattern
# class (P1: budget + label/flow) is reported OUT_OF_SCOPE -- an honest "this is
# not the kind of control I extract", never a silent UNKNOWN and never claimed.
# It is distinct from UNKNOWN: UNKNOWN means "I could not decide"; OUT_OF_SCOPE
# means "this is outside the scope I claim at all".
OUT_OF_SCOPE = "out_of_scope"

_STATUSES = (PROVEN, VIOLATED, UNKNOWN, UNSOUND, ERROR, OUT_OF_SCOPE)

# Property kinds (mirror rot.invariants.KIND_SAFETY / KIND_LIVENESS).
KIND_SAFETY = "safety"
KIND_LIVENESS = "liveness"
_PROPERTY_KINDS = (KIND_SAFETY, KIND_LIVENESS)

# Violation codes (meaningful on VIOLATED verdicts; name the failure class).
POLICY_DENIAL = "POLICY_DENIAL"
LIVENESS_BOUND_EXCEEDED = "LIVENESS_BOUND_EXCEEDED"
DEADLOCK = "DEADLOCK"
_VIOLATION_CODES = (POLICY_DENIAL, LIVENESS_BOUND_EXCEEDED, DEADLOCK)

# Advisory codes -- loud, non-fatal warnings attached to a verdict so a bounded
# PROVEN is never a *silent* false-negative.  An advisory does NOT change the
# verdict status or the process exit code; it makes the bound that produced the
# verdict visible to a human (and to the manifest):
#   MASKED_AT_LOW_K -- a cap/budget property was checked at a concurrency pool
#                      bound K smaller than the minimal overshoot count, so a
#                      settled-only (parallel-fire) race is not expressible in
#                      the state space.  A PROVEN at that K is technically
#                      correct *within the bound* but does not rule out the
#                      race -- re-check at K >= the minimal overshoot count
#                      (the K=1 trap).
MASKED_AT_LOW_K = "MASKED_AT_LOW_K"
# CPG-3 (the static <-> formal soundness cross-check, condition (S)):
#   unsound_abstraction -- the ground-truth CPG carries a taint-critical
#                          path that threatens the pinned property
#                          (taintPath(G, P)) yet the abstract model proved P:
#                          the abstraction A dropped a taint-critical
#                          dataflow edge.  The PROVEN verdict is downgraded
#                          to UNKNOWN (fail-closed, never a silent false
#                          negative) and this advisory names why; the dropped
#                          edge is named on the verdict (note / soundness /
#                          evidence["abstraction_soundness"].dropped_edge).
#   concurrency_only -- the model checker found a VIOLATION the static
#                       single-path analysis does not see (e.g. a parallel-
#                       fire spend-cap bypass): a concurrency-only witness.
#                       The VIOLATED verdict stands; the tag records that the
#                       static producer could not see it (the model checker's
#                       value-add: "Joern is the smell test; ROTN is the
#                       proof").
UNSOUND_ABSTRACTION = "unsound_abstraction"
CONCURRENCY_ONLY = "concurrency_only"
_ADVISORY_CODES = (MASKED_AT_LOW_K, UNSOUND_ABSTRACTION, CONCURRENCY_ONLY)


def _strip(d, *keys):
    return {k: v for k, v in d.items() if k not in keys}


def _fmt_state(d):
    """Render a state/delta dict as a compact ``k=v, ...`` string."""
    if not d:
        return "{}"
    return ", ".join("%s=%s" % (k, d[k]) for k in sorted(d))


def minimal_overshoot_count(amount, cap):
    """The smallest number of concurrent in-flight requests whose total
    amount, added to the settled amount a settled-only decision rule would
    still admit, exceeds the cap.

    This is the spend-cap "minimal overshoot count": the fewest in-flight
    requests that can push ``completed + inflight * amount`` past ``cap``.  It
    is what the concurrency pool bound ``K`` (``max_inflight``) must be at
    least as large as for a settled-only (``response``-triggered) policy's
    parallel-fire race to be *expressible* in the state space.

    The settled-only guard admits a request while ``completed + amount <= cap``
    (i.e. ``completed <= cap - amount``), so the maximum settled amount that
    coexists with an admitted in-flight request is ``c_max = max(0, cap -
    amount)``.  A violation needs ``c_max + m * amount > cap``, i.e.
    ``m * amount > cap - c_max``; the smallest such ``m`` is
    ``(cap - c_max) // amount + 1``.

    For the canonical spend-cap (``amount = 100``, ``cap = 200``) this is
    ``2`` -- exactly why ``K = 1`` (inflight bounded to 1) *masks* the
    parallel-fire race while ``K >= 2`` exposes it.
    """
    amount = int(amount)
    cap = int(cap)
    if amount <= 0:
        return 1
    c_max = max(0, cap - amount)
    need = cap - c_max  # the amount of overshoot still required
    if need <= 0:
        return 1
    return need // amount + 1


def _is_cap_budget(metadata):
    """True if the IR metadata names a cap/budget (within-cap) property."""
    if not metadata:
        return False
    if metadata.get("family") == "SPENDCAP":
        return True
    if metadata.get("property_name") == "spendcap_within_cap":
        return True
    return metadata.get("protocol") in (
        "SPENDCAP", "COUNT_WINDOW", "EXISTS_SUM", "REFUND_BUDGET")


def k_masking_advisory(metadata, status):
    """Return ``(code, message)`` if a cap/budget property is PROVEN at a
    concurrency pool bound ``K`` that cannot express the minimal overshoot,
    else ``(None, None)``.

    This is the **loud K-masking advisory** (Phase A, A1): a settled-only
    (``response``-triggered) spend-cap policy checked at ``K`` below the
    minimal overshoot count returns ``PROVEN`` because the parallel-fire race
    is not expressible in the state space -- a *silent false-negative*.  The
    advisory makes that bound visible (in the manifest and as a human warning)
    without changing the verdict or the exit code.

    ``metadata`` is the IR metadata dict; ``status`` is the verdict status
    string (``"proven"`` / ``"violated"`` / ``"unknown"``).  The advisory
    fires only on a positive (``proven``) verdict for a settled-only cap/budget
    policy whose ``max_inflight`` (``K``) is below :func:`minimal_overshoot_count`.
    """
    if status != "proven":
        return None, None
    if not _is_cap_budget(metadata):
        return None, None
    # The advisory is about the *settled-only* (race-prone) guard -- the one a
    # low K masks.  A correct (in-flight-charging) policy is safe at every K,
    # so there is nothing to mask.
    if not metadata.get("buggy"):
        return None, None
    amount = metadata.get("amount")
    cap = metadata.get("cap")
    k = metadata.get("max_inflight")
    if amount is None or cap is None or k is None:
        return None, None
    k = int(k)
    m_min = minimal_overshoot_count(amount, cap)
    if k < m_min:
        message = (
            "K=%d cannot express %d concurrent in-flight requests (the minimal "
            "overshoot for amount=%d, cap=%d).  A settled-only (parallel-fire) "
            "race is NOT expressible at this bound, so this PROVEN does not "
            "rule it out -- re-check at K>=%d before treating the policy as "
            "safe." % (k, m_min, amount, cap, m_min))
        return MASKED_AT_LOW_K, message
    return None, None


class Verdict(object):
    """The auditable outcome of one verification run."""

    def __init__(self, status, property_name, engine,
                 counterexample=None, assumptions=None, soundness=None,
                 evidence=None, cegar_iterations=0, n_states=0, note="",
                 property_kind=None, violation_code=None, trace=None,
                 advisories=None, discharge=None, fairness_label=None,
                 stuttering_assumption=None):
        if status not in _STATUSES:
            raise ValueError("bad verdict status %r" % (status,))
        if property_kind is not None and property_kind not in _PROPERTY_KINDS:
            raise ValueError("bad property kind %r" % (property_kind,))
        if violation_code is not None and violation_code not in _VIOLATION_CODES:
            raise ValueError("bad violation code %r" % (violation_code,))
        for _adv in (advisories or ()):
            if _adv not in _ADVISORY_CODES:
                raise ValueError("bad advisory code %r" % (_adv,))
        self.status = status
        self.property_name = property_name
        self.engine = engine
        self.counterexample = counterexample
        self.assumptions = list(assumptions or [])
        self.soundness = list(soundness or [])
        self.evidence = dict(evidence or {})
        self.cegar_iterations = int(cegar_iterations)
        self.n_states = int(n_states)
        self.note = note
        self.property_kind = property_kind
        self.violation_code = violation_code
        # Loud, non-fatal advisory codes (e.g. MASKED_AT_LOW_K).  These do not
        # change the status or the exit code; they make a bound that produced a
        # bounded PROVEN visible so it is never a *silent* false-negative.
        self.advisories = list(advisories or [])
        # Step-by-step counterexample trace: a list of
        # (state, action, guard, policy_clause, delta) 5-tuples.  Set on
        # VIOLATED verdicts; each step records the state *before* the action,
        # the action name, its rendered guard, the invariant's policy clause,
        # and the state change the action caused.
        self.trace = list(trace) if trace is not None else None
        # Liveness discharge path (Phase 2).  ``discharge`` records *how* a
        # liveness claim was decided so a verdict can never be read as stronger
        # than it is:
        #   * ``"bounded"``  -- the goal is REACHABLE within the horizon,
        #     discharged by the concrete symbolic engine (spec R2a).  No
        #     fairness assumed.  Sound when ``horizon_complete``.
        #   * ``"fairness"`` -- the *unbounded* claim ``<>Goal``, discharged
        #     under weak fairness on the harness decision action (spec D2).
        #     ``fairness_label`` is then REQUIRED (never silent).
        #   * ``None``       -- a safety verdict (no liveness discharge).
        self.discharge = discharge
        # The explicit fairness formula for an unbounded-liveness discharge
        # (e.g. ``"WF(Decide)"``).  Set whenever ``discharge == "fairness"``;
        # it is recorded on the verdict and emitted as a named assumption so a
        # liveness claim is never silently strengthened by an unstated fairness
        # assumption (spec R2).  ``None`` for bounded liveness and safety.
        self.fairness_label = fairness_label
        # Phase 6.1: the stated stuttering assumption (never silent).  The IR
        # transition system has no stuttering steps, so safety verdicts are
        # sound under it at no cost; liveness verdicts are sound only UNDER it
        # (liveness-honest).  Carried on every verdict so the report states the
        # semantic gap instead of hiding it.  See ``rot.ir.STUTTERING_ASSUMPTION``.
        self.stuttering_assumption = stuttering_assumption

    # -- factories -----------------------------------------------------------
    @classmethod
    def proven(cls, property_name, engine, **kw):
        return cls(PROVEN, property_name, engine,
                   note=kw.get("note", "invariant holds"), **_strip(kw, "note"))

    @classmethod
    def violated(cls, property_name, engine, counterexample, **kw):
        return cls(VIOLATED, property_name, engine,
                   counterexample=counterexample, **_strip(kw, "note"))

    @classmethod
    def unknown(cls, property_name, engine, **kw):
        return cls(UNKNOWN, property_name, engine,
                   note=kw.get("note", "could not decide"), **_strip(kw, "note"))

    @classmethod
    def unsound(cls, property_name, engine, counterexample=None, **kw):
        return cls(UNSOUND, property_name, engine,
                   counterexample=counterexample,
                   note=kw.get("note", "counterexample not confirmed concrete"),
                   **_strip(kw, "note"))

    @classmethod
    def error(cls, property_name, engine, **kw):
        return cls(ERROR, property_name, engine,
                   note=kw.get("note", "engine error"), **_strip(kw, "note"))

    @classmethod
    def out_of_scope(cls, property_name, engine, reason="", **kw):
        """E2: an honest out-of-scope result for a claim outside the declared
        pattern class.  Never read as proven, and never silently unknown: the
        ``reason`` states which pattern class was in scope and why this code is
        outside it."""
        return cls(OUT_OF_SCOPE, property_name, engine,
                   note=kw.get("note", reason or "outside the declared pattern class"),
                   **_strip(kw, "note"))

    # -- predicates ----------------------------------------------------------
    def is_proven(self):
        return self.status == PROVEN

    def is_violated(self):
        return self.status == VIOLATED

    def is_out_of_scope(self):
        return self.status == OUT_OF_SCOPE

    # -- serialization -------------------------------------------------------
    def to_dict(self):
        return {
            "status": self.status,
            "property_name": self.property_name,
            "engine": self.engine,
            "counterexample": self.counterexample,
            "assumptions": self.assumptions,
            "soundness": self.soundness,
            "evidence": self.evidence,
            "cegar_iterations": self.cegar_iterations,
            "n_states": self.n_states,
            "note": self.note,
            "property_kind": self.property_kind,
            "violation_code": self.violation_code,
            "advisories": self.advisories,
            "trace": self.trace,
            "discharge": self.discharge,
            "fairness_label": self.fairness_label,
            "stuttering_assumption": self.stuttering_assumption,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def _write(self, out_dir, base_name):
        import os
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        base = os.path.join(out_dir, base_name) if out_dir else base_name
        with open(base + ".json", "w") as f:
            f.write(self.to_json())
        with open(base + ".md", "w") as f:
            f.write(self.to_markdown())
        return base + ".json"

    def write(self, out_dir, base_name="verdict"):
        return self._write(out_dir, base_name)

    def to_markdown(self):
        lines = []
        lines.append("# ROTN verdict: %s" % self.property_name)
        lines.append("")
        badge = {PROVEN: "**PROVEN**", VIOLATED: "**VIOLATED**",
                 UNKNOWN: "UNKNOWN", UNSOUND: "UNSAFE / UNSOUND",
                 ERROR: "ERROR"}[self.status]
        lines.append("- Status: %s" % badge)
        lines.append("- Engine: `%s`" % self.engine)
        lines.append("- States explored: %d" % self.n_states)
        lines.append("- CEGAR iterations: %d" % self.cegar_iterations)
        lines.append("- Note: %s" % self.note)
        if self.property_kind:
            lines.append("- Property kind: `%s`" % self.property_kind)
        if self.violation_code:
            lines.append("- Violation code: `%s`" % self.violation_code)
        if self.advisories:
            lines.append("")
            lines.append("## Advisories (loud, non-fatal)")
            lines.append("")
            for a in self.advisories:
                lines.append("- **%s** -- see the human warning; this bound "
                             "does not change the verdict." % a)
            lines.append("")
        lines.append("")
        if self.counterexample is not None:
            lines.append("## Counterexample")
            lines.append("")
            lines.append("```")
            for k in sorted(self.counterexample):
                lines.append("%s = %s" % (k, self.counterexample[k]))
            lines.append("```")
            lines.append("")
        if self.trace:
            lines.append("## Counterexample trace")
            lines.append("")
            lines.append("Step-by-step witness from the initial state, each step "
                         "a `(state, action, guard, policy_clause, delta)` "
                         "5-tuple:")
            lines.append("")
            for i, step in enumerate(self.trace):
                state_before, action, guard, clause, delta = step
                lines.append("%d. **%s**" % (i + 1, action))
                lines.append("   - state: `%s`" % _fmt_state(state_before))
                lines.append("   - guard: `%s`" % guard)
                lines.append("   - policy_clause: `%s`" % clause)
                lines.append("   - delta: `%s`" % _fmt_state(delta))
            lines.append("")
        if self.assumptions:
            lines.append("## Recorded assumptions")
            lines.append("")
            for a in self.assumptions:
                lines.append("- %s" % a)
            lines.append("")
        if self.stuttering_assumption:
            lines.append("## Stuttering assumption")
            lines.append("")
            lines.append(self.stuttering_assumption)
            lines.append("")
        if self.soundness:
            lines.append("## Soundness notes")
            lines.append("")
            for s in self.soundness:
                lines.append("- %s" % s)
            lines.append("")
        if self.evidence:
            lines.append("## Engine evidence")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(self.evidence, indent=2, sort_keys=False))
            lines.append("```")
            lines.append("")
        return "\n".join(lines)


def _two_layer_rows(two_layer):
    """The (name, section) rows of a two-layer section, in a stable order.

    Accepts either a single two-layer section dict (with a ``"status"`` key)
    or a ``{shape: section}`` mapping (the claim-packet form).
    """
    if not two_layer:
        return []
    if isinstance(two_layer, dict) and "status" in two_layer:
        return [("-", two_layer)]
    if isinstance(two_layer, dict):
        return [(k, two_layer[k]) for k in sorted(two_layer)
                if isinstance(two_layer[k], dict)]
    return []


def _retention_rows(retention):
    """The (name, manifest) rows of a retention section, in a stable order.

    Accepts either a single manifest dict (with a ``"shape"`` key) or a
    ``{shape: manifest}`` mapping (the claim-packet form).
    """
    if not retention:
        return []
    if isinstance(retention, dict) and "kept" in retention:
        return [(retention.get("shape", "-"), retention)]
    if isinstance(retention, dict):
        return [(k, retention[k]) for k in sorted(retention)
                if isinstance(retention[k], dict)]
    return []


class VerdictReport(object):
    """A full verification run: config + abstraction + invariant + verdict.

    Phase 7 (evidence): the report may also carry the three evidence layers
    the claim packet (``rot.cpg4``) carries -- the **two-layer agreement**
    (static<->formal composed with the engine verdict; fail-closed), the
    **A/B winner table** (the default frontend, chosen by measurement, not
    assertion), and the **lossiness manifest** (the retention manifest:
    kept vs. dropped dataflow edges, each drop classified).  All three are
    optional (``None`` / empty) -- the existing positional signature is
    unchanged.
    """

    def __init__(self, target, property_name, engine, config_dict,
                 abstraction_dict, verdict, invariant_dict=None,
                 two_layer=None, ab=None, retention=None):
        self.target = target
        self.property_name = property_name
        self.engine = engine
        self.config = config_dict or {}
        self.abstraction = abstraction_dict or {}
        self.invariant = invariant_dict or {}
        self.verdict = verdict
        # Phase 7 evidence layers (optional; empty when the run has none).
        self.two_layer = two_layer or {}
        self.ab = ab or {}
        self.retention = retention or {}

    def to_dict(self):
        d = {
            "target": self.target,
            "property_name": self.property_name,
            "engine": self.engine,
            "config": self.config,
            "abstraction": self.abstraction,
            "verdict": self.verdict.to_dict(),
        }
        if self.invariant:
            d["invariant"] = self.invariant
        if self.two_layer:
            d["two_layer"] = self.two_layer
        if self.ab:
            d["ab"] = self.ab
        if self.retention:
            d["retention"] = self.retention
        return d

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_markdown(self):
        out = ["# ROTN verification report", ""]
        out.append("- Target: `%s`" % self.target)
        out.append("- Property: `%s`" % self.property_name)
        out.append("- Engine: `%s`" % self.engine)
        out.append("- Resolved engine: `%s`"
                   % self.config.get("resolved_engine", "?"))
        if self.invariant:
            lbl = self.invariant.get("label", "unlabelled")
            pin = self.invariant.get("pinned", False)
            blk = self.invariant.get("blocking_permission", False)
            out.append("- Invariant label: `%s` (pinned=%s, "
                       "blocking_permission=%s)" % (lbl, pin, blk))
        out.append("")
        out.append("## Abstraction (property-directed)")
        out.append("")
        out.append("- Keep: %s" % ", ".join(self.abstraction.get("keep", [])))
        out.append("- Hide: %s" % ", ".join(self.abstraction.get("hide", [])))
        out.append("")
        # Phase 7 evidence layers (each rendered only when present).
        if self.two_layer:
            out.append("## Two-layer agreement (static<->formal)")
            out.append("")
            out.append("PROVEN requires **both** layers: the formal engine "
                       "verdict AND the static ground truth carrying no "
                       "taint-critical threat to the pinned property.  A "
                       "static threat to a PROVEN fails closed to UNKNOWN "
                       "(never a silent false negative); a VIOLATED is never "
                       "upgraded.")
            out.append("")
            for name, tl in _two_layer_rows(self.two_layer):
                out.append("- **%s** -- formal: `%s` | static: `%s` | "
                           "two-layer: `%s` | agreement: %s"
                           % (name, tl.get("formal"), tl.get("static"),
                              tl.get("status"), tl.get("agreement")))
            out.append("")
        if self.ab:
            out.append("## A/B winner (the default frontend)")
            out.append("")
            out.append("Winner: **%s** (lexicographic over the corpus: %s; "
                       "hard gate: no false-PROVEN)"
                       % (self.ab.get("winner"),
                          ", ".join(self.ab.get("corpus", []))))
            out.append("")
            out.append("| frontend | hard gate | cells | unavailable | ranking |")
            out.append("|---|---|---|---|---|")
            for f, agg in sorted(self.ab.get("per_frontend", {}).items()):
                gate = ("PASS" if agg.get("hard_gate_pass")
                        else "FAIL (false-PROVEN)")
                out.append("| %s | %s | %s | %s | %s |"
                           % (f, gate, agg.get("cells"),
                              agg.get("unavailable"), agg.get("ranking")))
            out.append("")
        if self.retention:
            out.append("## Retention manifest (lossiness)")
            out.append("")
            out.append("Every deliberately-dropped CPG dataflow edge is named: "
                       "kept vs. dropped, each drop classified "
                       "irrelevant / unknown / taint-critical.  A dropped edge "
                       "of unknown relevance forces UNKNOWN + "
                       "`unsound_abstraction` (the fail-closed hard rule).")
            out.append("")
            for name, rt in _retention_rows(self.retention):
                out.append("- **%s** -- kept: %d (taint-critical) | "
                           "dropped: %d (irrelevant: %d, unknown: %d)"
                           % (name,
                              len(rt.get("kept", [])),
                              len(rt.get("dropped", [])),
                              len(rt.get("irrelevant", [])),
                              len(rt.get("unknown", []))))
            out.append("")
        out.append(self.verdict.to_markdown())
        return "\n".join(out)

    def write(self, out_dir, base_name="report"):
        import os
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        base = os.path.join(out_dir, base_name) if out_dir else base_name
        with open(base + ".json", "w") as f:
            f.write(self.to_json())
        with open(base + ".md", "w") as f:
            f.write(self.to_markdown())
        return base + ".json"


__all__ = ["PROVEN", "VIOLATED", "UNKNOWN", "UNSOUND", "ERROR", "OUT_OF_SCOPE",
           "KIND_SAFETY", "KIND_LIVENESS",
           "POLICY_DENIAL", "LIVENESS_BOUND_EXCEEDED", "DEADLOCK",
           "MASKED_AT_LOW_K",
           "minimal_overshoot_count", "k_masking_advisory",
           "Verdict", "VerdictReport"]

