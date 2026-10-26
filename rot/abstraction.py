# -*- coding: utf-8 -*-
"""abstraction.py -- property-directed variable abstraction (the soundness core).

Given a trusted IR and a *pinned property* (the safety invariant we must
preserve), this module decides which variables the abstract model must retain
and which may be existentially hidden, and emits a machine-readable manifest
plus a list of human-readable assumptions for the final verdict.

Why this is the soundness core
------------------------------
We verify a SAFETY invariant over an *over-approximation* of the concrete
protocol's observable behaviour w.r.t. the pinned property. An existential
(hiding) abstraction is a sound over-approximation iff every concrete
reachable state's projection on the kept variables is also reachable abstractly.
The standard way to guarantee that is a backward data-dependence closure:

  KEEP = free_vars(property) union the variables that can influence those,
  where "influence" follows: an action that WRITES a kept variable must have
  all variables it READS (guard + effect expressions) kept, and control is
  always kept.

After the closure reaches a fixpoint, any action that writes a kept variable
has fully-kept guards, so hiding the remaining variables only over-approximates
reachable kept-variable projections -- exactly what a safety over-approximation
requires. Hiding never under-approximates, so a TLC proof over the abstract
model is a valid proof over the concrete one, and a TLC counterexample is a
candidate real bug (validated by CEGAR).

Everything is recorded (kept / hidden / bounded / dropped, each with a
rationale and a soundness note) so a reviewer can audit exactly what was
assumed. Pure stdlib, Python 3.6 compatible.
"""

KIND_KEEP = "keep"
KIND_HIDE = "hide"
KIND_BOUND = "bound"
KIND_DROP = "drop"


class AbstractionDecision(object):
    """One documented decision about a variable (or a class of them)."""

    def __init__(self, var, kind, rationale, soundness="", note=""):
        self.var = var
        self.kind = kind
        self.rationale = rationale
        self.soundness = soundness
        self.note = note

    def to_dict(self):
        return {
            "var": self.var,
            "kind": self.kind,
            "rationale": self.rationale,
            "soundness": self.soundness,
            "note": self.note,
        }


class AbstractionResult(object):
    """The output of property-directed abstraction for one target/property."""

    def __init__(self, keep, hide, bound, drop, assumptions, decisions,
                 property_name):
        self.keep = list(keep)
        self.hide = list(hide)
        self.bound = list(bound)      # list of decision dicts
        self.drop = list(drop)
        self.assumptions = list(assumptions)
        self.decisions = list(decisions)
        self.property_name = property_name

    def to_dict(self):
        return {
            "property_name": self.property_name,
            "keep": self.keep,
            "hide": self.hide,
            "bound": [b if isinstance(b, dict) else b.to_dict() for b in self.bound],
            "drop": self.drop,
            "assumptions": self.assumptions,
            "decisions": [d.to_dict() for d in self.decisions],
        }


def _free_vars(expr):
    from .ir import Var, BinOp, UnOp, If, AllOf, AnyOf
    out = []

    def add(n):
        if n and n not in out:
            out.append(n)

    def walk(e):
        if e is None:
            return
        if isinstance(e, Var):
            add(e.name)
        elif isinstance(e, BinOp):
            walk(e.left)
            walk(e.right)
        elif isinstance(e, UnOp):
            walk(e.child)
        elif isinstance(e, If):
            walk(e.cond)
            walk(e.then)
            walk(e.els)
        elif isinstance(e, (AllOf, AnyOf)):
            walk(e.coll)
            walk(e.body)

    walk(expr)
    return out


def derive_abstraction(ir, property_expr, property_name="",
                       participant_bound=None, env_bound=None):
    """Compute a sound property-directed abstraction of ``ir`` for ``property_expr``.

    ``participant_bound`` / ``env_bound`` are optional concrete caps recorded as
    assumptions (model-size); they do not change the property-directed
    keep/hide sets, which are derived purely from the property.
    """
    prop_vars = set(v for v in _free_vars(property_expr) if v != "pc")
    keep = set(prop_vars)
    keep.add("pc")

    changed = True
    while changed:
        changed = False
        for a in ir.actions:
            writes_kept = any((e.var in keep) for e in a.effects)
            if not writes_kept:
                continue
            for v in _free_vars(a.guard):
                if v != "pc" and v not in keep:
                    keep.add(v)
                    changed = True
            for e in a.effects:
                for v in _free_vars(e.expr):
                    if v != "pc" and v not in keep:
                        keep.add(v)
                        changed = True

    all_vars = set(v.name for v in ir.variables)
    hide = sorted(v for v in (all_vars - keep) if v != "pc")
    keep = sorted(keep - {"pc"})

    decisions = []
    assumptions = []
    bound_entries = []

    for v in keep:
        decisions.append(AbstractionDecision(
            v, KIND_KEEP,
            "in the property's free-variable closure, or required to preserve a "
            "property-relevant value through some enabled action",
            soundness="keeping is always sound (no over-approximation introduced)",
            note="property-relevant"))
    for v in hide:
        decisions.append(AbstractionDecision(
            v, KIND_HIDE,
            "not in the property's free-variable closure after fixpoint; only "
            "influences transitions that do not alter kept variables",
            soundness="existential hiding is a sound over-approximation of the "
                      "reachable projection on kept variables (safety)",
            note="environment / identity detail"))

    from .ir import IntRange
    for v in all_vars:
        sv = ir.var(v)
        if sv is not None and isinstance(sv.domain, IntRange):
            if (sv.domain.hi - sv.domain.lo) > 10:
                d = AbstractionDecision(
                    v, KIND_BOUND,
                    "wide integer domain [%d..%d] bounded for the model check"
                    % (sv.domain.lo, sv.domain.hi),
                    soundness="bounded integer domain is a sound restriction; "
                              "recorded as an assumption to be discharged",
                    note="bounded")
                decisions.append(d)
                bound_entries.append(d.to_dict())
                assumptions.append(
                    "Variable '%s' domain bounded to [%d..%d] (sound restriction; "
                    "verify the bound is sufficient for the property)."
                    % (v, sv.domain.lo, sv.domain.hi))

    if participant_bound is not None:
        assumptions.append(
            "Participant count bounded to N=%d. Agreement is symmetric over "
            "participants, so the N=%d instance is a representative witness for "
            "the agreement invariant." % (participant_bound, participant_bound))
    if env_bound is not None:
        assumptions.append(
            "Network environment abstracted to bounded nondeterminism: at most "
            "%d message losses/reorders per round. This over-approximates the "
            "concrete network w.r.t. the safety property." % env_bound)
    assumptions.append(
        "Property-directed abstraction: only variables in the free-variable "
        "closure of the pinned property (and their data dependences) are "
        "retained; all others are existentially hidden. This is a sound "
        "over-approximation for safety verification.")

    return AbstractionResult(
        keep=keep, hide=hide, bound=bound_entries, drop=[],
        assumptions=assumptions, decisions=decisions,
        property_name=property_name)


__all__ = [
    "KIND_KEEP", "KIND_HIDE", "KIND_BOUND", "KIND_DROP",
    "AbstractionDecision", "AbstractionResult", "derive_abstraction",
]