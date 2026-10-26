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

_STATUSES = (PROVEN, VIOLATED, UNKNOWN, UNSOUND, ERROR)

# Property kinds (mirror rot.invariants.KIND_SAFETY / KIND_LIVENESS).
KIND_SAFETY = "safety"
KIND_LIVENESS = "liveness"
_PROPERTY_KINDS = (KIND_SAFETY, KIND_LIVENESS)

# Violation codes (meaningful on VIOLATED verdicts; name the failure class).
POLICY_DENIAL = "POLICY_DENIAL"
LIVENESS_BOUND_EXCEEDED = "LIVENESS_BOUND_EXCEEDED"
DEADLOCK = "DEADLOCK"
_VIOLATION_CODES = (POLICY_DENIAL, LIVENESS_BOUND_EXCEEDED, DEADLOCK)


def _strip(d, *keys):
    return {k: v for k, v in d.items() if k not in keys}


def _fmt_state(d):
    """Render a state/delta dict as a compact ``k=v, ...`` string."""
    if not d:
        return "{}"
    return ", ".join("%s=%s" % (k, d[k]) for k in sorted(d))


class Verdict(object):
    """The auditable outcome of one verification run."""

    def __init__(self, status, property_name, engine,
                 counterexample=None, assumptions=None, soundness=None,
                 evidence=None, cegar_iterations=0, n_states=0, note="",
                 property_kind=None, violation_code=None, trace=None):
        if status not in _STATUSES:
            raise ValueError("bad verdict status %r" % (status,))
        if property_kind is not None and property_kind not in _PROPERTY_KINDS:
            raise ValueError("bad property kind %r" % (property_kind,))
        if violation_code is not None and violation_code not in _VIOLATION_CODES:
            raise ValueError("bad violation code %r" % (violation_code,))
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
        # Step-by-step counterexample trace: a list of
        # (state, action, guard, policy_clause, delta) 5-tuples.  Set on
        # VIOLATED verdicts; each step records the state *before* the action,
        # the action name, its rendered guard, the invariant's policy clause,
        # and the state change the action caused.
        self.trace = list(trace) if trace is not None else None

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

    # -- predicates ----------------------------------------------------------
    def is_proven(self):
        return self.status == PROVEN

    def is_violated(self):
        return self.status == VIOLATED

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
            "trace": self.trace,
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


class VerdictReport(object):
    """A full verification run: config + abstraction + invariant + verdict."""

    def __init__(self, target, property_name, engine, config_dict,
                 abstraction_dict, verdict, invariant_dict=None):
        self.target = target
        self.property_name = property_name
        self.engine = engine
        self.config = config_dict or {}
        self.abstraction = abstraction_dict or {}
        self.invariant = invariant_dict or {}
        self.verdict = verdict

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


__all__ = ["PROVEN", "VIOLATED", "UNKNOWN", "UNSOUND", "ERROR",
           "KIND_SAFETY", "KIND_LIVENESS",
           "POLICY_DENIAL", "LIVENESS_BOUND_EXCEEDED", "DEADLOCK",
           "Verdict", "VerdictReport"]

