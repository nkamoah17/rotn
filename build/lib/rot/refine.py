# -*- coding: utf-8 -*-
"""refine.py -- Phase 4: refinement loop (propose -> check -> repair).

The refinement loop answers the core Phase 4 question: given a *before*
protocol (v1) and a rewritten *after* protocol (v2),

  1. **propose** -- compute the rename/alias mapping that explains the
     cosmetic differences between the two (the COSMETIC elements of
     :mod:`rot.specdiff`);
  2. **check**   -- run the invariant battery against the after model with
     every invariant expression translated through the mapping;
  3. **repair**  -- for every invariant violation, attribute it to a
     SEMANTIC action change and mechanically restore the before-side
     guard/effect expression;

and repeat until the check passes (final status ``refined``), no repair
step can be attributed (``unrepairable``), or the round budget is
exhausted (``exhausted``).

The loop is deliberately conservative: it only ever *restores* behaviour
present in the before protocol.  It never invents new behaviour, so a
``refined`` verdict means the after model satisfies exactly the same
invariant battery as the before model -- an honest refinement witness,
not a hand-wave.  Invariants whose expressions the symbolic engine cannot
decide within budget stay UNKNOWN and are surfaced, never silently
assumed (the sound-fallback discipline of :mod:`rot.symbolic`).

CLI::

    python -m rot.refine <before-target> <after-target> \
        [--invariant NAME]... [--n N] [--max-states N] [--rounds R] [--out DIR]

Exit code 0 on ``refined``, 1 otherwise, 2 on usage/target errors.
"""

import json
import os

from .ir import (AllOf, AnyOf, Action, Assignment, BinOp, Const, If,
                 ProtocolIR, UnOp, Var)
from .linearization import linearize
from .specdiff import SEMANTIC, compute_spec_diff
from .symbolic import SymbolicEngine

__all__ = [
    "PASS", "FAIL", "UNKNOWN", "SKIPPED",
    "REFINED", "UNREPAIRABLE", "EXHAUSTED",
    "MappingProposal", "CheckResult", "RepairStep", "RepairPlan",
    "RoundRecord", "RefinementReport",
    "propose_mapping", "check", "repair", "run_refinement",
]

# -- check verdicts --------------------------------------------------------
PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
SKIPPED = "skipped"

# -- refinement loop final statuses ----------------------------------------
REFINED = "refined"
UNREPAIRABLE = "unrepairable"
EXHAUSTED = "exhausted"

# engine status -> check status (see rot.symbolic)
_ENGINE_STATUS = {"proven": PASS, "violated": FAIL, "unknown": UNKNOWN}


# ---------------------------------------------------------------------------
# step 1: propose
# ---------------------------------------------------------------------------
class MappingProposal(object):
    """The rename/alias mapping that explains the cosmetic v1 -> v2 diff.

    ``var_map`` / ``action_map`` map old (v1) names to new (v2) names.
    Only COSMETIC (renamed) elements participate: semantic differences are
    never aliased away (aliasing a semantic change would hide the very
    behaviour the loop must repair).
    """

    def __init__(self, var_map=None, action_map=None, reasons=None):
        self.var_map = dict(var_map or {})
        self.action_map = dict(action_map or {})
        self.reasons = list(reasons or [])

    def rename(self, name):
        """Apply the variable mapping to ``name`` (identity if unmapped)."""
        return self.var_map.get(name, name)

    def to_dict(self):
        return {
            "var_map": dict(self.var_map),
            "action_map": dict(self.action_map),
            "reasons": list(self.reasons),
        }

    def __repr__(self):
        return "<MappingProposal vars=%d actions=%d>" % (
            len(self.var_map), len(self.action_map))


def propose_mapping(before, after):
    """Step 1 of the loop.

    Compute :class:`MappingProposal` from the spec diff of ``before`` and
    ``after``: every renamed variable/action pair becomes an alias entry.
    """
    sd = compute_spec_diff(before, after)
    var_map = {}
    action_map = {}
    reasons = []
    for el in sd.elements:
        if el.kind == "variable" and el.variable is not None:
            if el.variable.kind == "renamed":
                old = el.variable.old_name
                new = el.variable.new_name
                var_map[old] = new
                reasons.append("variable %r -> %r (renamed)" % (old, new))
        elif el.kind == "action" and el.action is not None:
            if el.action.kind == "renamed":
                old = el.action.old_name
                new = el.action.name
                action_map[old] = new
                reasons.append("action %r -> %r (renamed)" % (old, new))
    return MappingProposal(var_map, action_map, reasons)
# ---------------------------------------------------------------------------
# expression rename helper (shared by check + tests)
# ---------------------------------------------------------------------------
def _rename_expr(e, var_map):
    """Rewrite an :class:`~rot.ir.Expr` through ``var_map`` (old->new).

    Idempotent for unmapped names; returns the same object when
    ``var_map`` is empty (so callers can pass proposals unconditionally).
    """
    if e is None or not var_map:
        return e
    if isinstance(e, Const):
        return e
    if isinstance(e, Var):
        return Var(var_map.get(e.name, e.name))
    if isinstance(e, BinOp):
        return BinOp(e.op, _rename_expr(e.left, var_map),
                     _rename_expr(e.right, var_map))
    if isinstance(e, UnOp):
        return UnOp(e.op, _rename_expr(e.child, var_map))
    if isinstance(e, If):
        return If(_rename_expr(e.cond, var_map),
                  _rename_expr(e.then, var_map),
                  _rename_expr(e.els, var_map))
    if isinstance(e, AllOf):
        return AllOf(e.var, _rename_expr(e.coll, var_map),
                     _rename_expr(e.body, var_map))
    if isinstance(e, AnyOf):
        return AnyOf(e.var, _rename_expr(e.coll, var_map),
                     _rename_expr(e.body, var_map))
    return e


def _free_vars(expr):
    """Sorted free variable names of an expression (for attribution)."""
    found = set()

    def _walk(e):
        if e is None:
            return
        if isinstance(e, Var):
            found.add(e.name)
        elif isinstance(e, BinOp):
            _walk(e.left)
            _walk(e.right)
        elif isinstance(e, UnOp):
            _walk(e.child)
        elif isinstance(e, If):
            _walk(e.cond)
            _walk(e.then)
            _walk(e.els)
        elif isinstance(e, (AllOf, AnyOf)):
            _walk(e.coll)
            _walk(e.body)

    _walk(expr)
    return sorted(found)


# ---------------------------------------------------------------------------
# step 2: check
# ---------------------------------------------------------------------------
class CheckResult(object):
    """Outcome of one refinement round's invariant check."""

    def __init__(self, status, invariant_results=None,
                 uncovered_semantic=None, notes=None):
        self.status = status  # PASS / FAIL / UNKNOWN
        self.invariant_results = list(invariant_results or [])
        self.uncovered_semantic = list(uncovered_semantic or [])
        self.notes = list(notes or [])

    def to_dict(self):
        return {
            "status": self.status,
            "invariants": list(self.invariant_results),
            "uncovered_semantic": list(self.uncovered_semantic),
            "notes": list(self.notes),
        }

    def __repr__(self):
        return "<CheckResult %s (%d invariants)>" % (
            self.status, len(self.invariant_results))


def check(before, after, proposal, invariants, cfg):
    """Step 2 of the loop.

    Check ``after`` against ``invariants``:

    * each invariant expression is first translated through
      ``proposal.var_map`` (so a renamed variable still refers to the
      right state);
    * the after model is linearized and checked with the symbolic engine
      under ``cfg.max_states``;
    * SEMANTIC elements of the before/after diff are reported as
      ``uncovered_semantic`` -- they require a human decision and are
      never silently accepted.

    Status: ``fail`` if any invariant is violated, ``unknown`` if any
    undecidable (budget) remains, ``pass`` otherwise.
    """
    proposal = proposal or MappingProposal()
    results = []
    for inv in invariants:
        if inv.expression is None:
            results.append({"name": inv.name, "status": SKIPPED,
                            "n_states": 0, "witness": None,
                            "note": "no expression"})
            continue
        expr = _rename_expr(inv.expression, proposal.var_map)
        engine = SymbolicEngine(linearize(after), max_states=cfg.max_states)
        er = engine.check(expr, cfg.max_states)
        results.append({
            "name": inv.name,
            "status": _ENGINE_STATUS.get(er.status, UNKNOWN),
            "n_states": er.n_states,
            "witness": er.witness if er.status == "violated" else None,
            "note": er.note,
        })
    statuses = [r["status"] for r in results]
    if FAIL in statuses:
        status = FAIL
    elif UNKNOWN in statuses:
        status = UNKNOWN
    elif statuses and all(s in (PASS, SKIPPED) for s in statuses):
        status = PASS
    else:
        status = PASS  # no invariants supplied: vacuously passes
    sd = compute_spec_diff(before, after)
    uncovered = []
    for el in sd.elements:
        if el.severity != SEMANTIC:
            continue
        name = None
        if el.kind == "variable" and el.variable is not None:
            name = el.variable.new_name or el.variable.old_name
        elif el.kind == "action" and el.action is not None:
            name = el.action.name
        uncovered.append({"name": name, "reason": el.reason})
    notes = []
    if uncovered:
        notes.append("%d semantic change(s) need human review"
                     % len(uncovered))
    return CheckResult(status, results, uncovered, notes)


# ---------------------------------------------------------------------------
# step 3: repair
# ---------------------------------------------------------------------------
class RepairStep(object):
    """One mechanical repair: restore ``before_expr`` on ``action``/``field``.

    ``field`` is ``"guard"`` or ``"effect:<var>"``.  A step is *attributed*
    -- it is only produced when the action's before-side expression touches
    a free variable of a violated invariant.
    """

    def __init__(self, action, field, before_expr, after_expr, reason=""):
        self.action = action
        self.field = field
        self.before_expr = before_expr
        self.after_expr = after_expr
        self.reason = reason

    def to_dict(self):
        return {
            "action": self.action,
            "field": self.field,
            "before": self.before_expr.to_dict() if self.before_expr is not None else None,
            "after": self.after_expr.to_dict() if self.after_expr is not None else None,
            "reason": self.reason,
        }

    def __repr__(self):
        return "<RepairStep %s.%s>" % (self.action, self.field)


class RepairPlan(object):
    """The set of repair steps for one round (empty when unrepairable)."""

    def __init__(self, steps, reason=""):
        self.steps = list(steps or [])
        self.reason = reason

    def to_dict(self):
        return {
            "steps": [s.to_dict() for s in self.steps],
            "reason": self.reason,
        }

    def __repr__(self):
        return "<RepairPlan %d step(s): %s>" % (len(self.steps), self.reason)


def _action_names(expr, effects):
    """Free variable names touched by a guard and its effect assignments."""
    names = set(_free_vars(expr))
    for e in effects:
        names.add(e.var)
        names.update(_free_vars(e.expr))
    return names

def repair(before, after, check_result, invariants):
    """Step 3 of the loop.

    For each failed invariant, find the SEMANTIC action modifications of
    the before/after diff whose before-side expression touches one of the
    invariant's free variables, and emit :class:`RepairStep` entries that
    restore those before-side expressions.

    Returns ``(repaired_ir, RepairPlan)``.  When a failed invariant cannot
    be attributed to any semantic action change, the plan is empty and
    ``after`` is returned unchanged -- the loop then reports
    ``unrepairable`` rather than guessing.
    """
    failed = [r for r in check_result.invariant_results
              if r["status"] == FAIL]
    if not failed:
        return after, RepairPlan([], "check passed; nothing to repair")

    by_name = dict((inv.name, inv) for inv in invariants)
    sd = compute_spec_diff(before, after)
    modified = []
    for el in sd.elements:
        if el.kind == "action" and el.action is not None \
                and el.action.kind == "modified":
            modified.append(el.action.name)

    steps = []
    unexplained = []
    for r in failed:
        inv = by_name.get(r["name"])
        if inv is None or inv.expression is None:
            continue
        fv = set(_free_vars(inv.expression))
        explained = False
        for name in modified:
            b_act = before.action(name)
            a_act = after.action(name)
            if b_act is None or a_act is None:
                continue
            if not (fv & _action_names(b_act.guard, b_act.effects)):
                continue
            explained = True
            reason = "restore before-side %s for violated invariant %r" \
                     % (name, inv.name)
            if b_act.guard.to_dict() != a_act.guard.to_dict():
                steps.append(RepairStep(name, "guard", b_act.guard,
                                        a_act.guard, reason))
            b_effs = dict((e.var, e.expr) for e in b_act.effects)
            for aeff in a_act.effects:
                be = b_effs.get(aeff.var)
                if be is None or be.to_dict() != aeff.expr.to_dict():
                    steps.append(RepairStep(
                        name, "effect:%s" % aeff.var, be, aeff.expr, reason))
        if not explained:
            unexplained.append(inv.name)
    if unexplained:
        return after, RepairPlan(
            [], "no attributable repair for invariant(s): %s"
            % ", ".join(sorted(unexplained)))

    # de-duplicate (same action+field may be attributed to >1 invariant)
    seen = set()
    uniq = []
    for s in steps:
        key = (s.action, s.field)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)
    repaired = _apply_repairs(after, uniq)
    return repaired, RepairPlan(uniq, "restored %d expression(s)" % len(uniq))

def _apply_repairs(ir, steps):
    """Build a copy of ``ir`` with each step's before-side expression set."""
    guard_fix = {}
    effect_fix = {}
    for s in steps:
        if s.field == "guard":
            guard_fix[s.action] = s.before_expr
        elif s.field.startswith("effect:"):
            effect_fix[(s.action, s.field[len("effect:"):])] = s.before_expr
    new_actions = []
    for a in ir.actions:
        touched = (a.name in guard_fix) or any(
            k[0] == a.name for k in effect_fix)
        if not touched:
            new_actions.append(a)
            continue
        guard = guard_fix.get(a.name, a.guard)
        effects = []
        for e in a.effects:
            key = (a.name, e.var)
            if key in effect_fix:
                effects.append(Assignment(e.var, effect_fix[key]))
            else:
                effects.append(e)
        new_actions.append(Action(
            a.name, a.owner, guard=guard, effects=effects,
            linearization=a.linearization, env_free=a.env_free,
            is_initial=a.is_initial, source=a.source, rung=a.rung,
            is_env=a.is_env))
    return ProtocolIR(
        ir.name, variables=list(ir.variables),
        channels=list(ir.channels), actions=new_actions, init=ir.init,
        pinned_property=ir.pinned_property,
        assumptions=list(ir.assumptions),
        abstraction_manifest=list(ir.abstraction_manifest),
        source_path=ir.source_path, metadata=dict(ir.metadata))

# ---------------------------------------------------------------------------
# the loop
# ---------------------------------------------------------------------------
class RoundRecord(object):
    """One refinement round: check outcome + repair plan applied."""

    def __init__(self, index, check, plan, applied):
        self.index = index
        self.check = check
        self.plan = plan
        self.applied = list(applied or [])

    def to_dict(self):
        return {
            "index": self.index,
            "check": self.check.to_dict(),
            "plan": self.plan.to_dict(),
            "applied": [s.to_dict() for s in self.applied],
        }

    def __repr__(self):
        return "<Round %d: %s, %d step(s)>" % (
            self.index, self.check.status, len(self.applied))


class RefinementReport(object):
    """Full refinement loop report."""

    def __init__(self, before_name, after_name, status, proposal,
                 rounds, final_ir, invariants):
        self.before_name = before_name
        self.after_name = after_name
        self.status = status
        self.proposal = proposal
        self.rounds = rounds
        self.final_ir = final_ir
        self.invariants = invariants

    def to_dict(self):
        return {
            "before": self.before_name,
            "after": self.after_name,
            "status": self.status,
            "proposal": self.proposal.to_dict(),
            "rounds": [r.to_dict() for r in self.rounds],
            "final_ir": self.final_ir.to_dict(),
            "invariants": [i.to_dict() for i in self.invariants],
        }

    def __repr__(self):
        return "<RefinementReport %s: %s, %d round(s)>" % (
            self.after_name, self.status, len(self.rounds))


def run_refinement(before, after, invariants, cfg, max_rounds=3):
    """Run propose -> check -> repair until refined / unrepairable / exhausted.

    ``cfg`` needs ``max_states`` (symbolic engine budget).  The after model
    is carried forward across rounds: each round re-checks the *current*
    after model and repairs only what is still failing.
    """
    proposal = propose_mapping(before, after)
    rounds = []
    current = after
    status = EXHAUSTED
    for index in range(1, max_rounds + 1):
        check_result = check(before, current, proposal, invariants, cfg)
        if check_result.status == PASS:
            status = REFINED
            rounds.append(RoundRecord(index, check_result,
                                      RepairPlan([], "check passed"), []))
            break
        if check_result.status == UNKNOWN:
            status = EXHAUSTED
            plan = RepairPlan([], "undecidable within budget; no repair")
            rounds.append(RoundRecord(index, check_result, plan, []))
            break
        # FAIL -> repair
        repaired, plan = repair(before, current, check_result, invariants)
        if not plan.steps:
            status = UNREPAIRABLE
            rounds.append(RoundRecord(index, check_result, plan, []))
            break
        applied = [RepairStep(s.action, s.field, s.before_expr,
                              s.after_expr, s.reason) for s in plan.steps]
        rounds.append(RoundRecord(index, check_result, plan, applied))
        current = repaired
    return RefinementReport(before.name, after.name, status, proposal,
                            rounds, current, invariants)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _load_ir(ref, n):
    """Load a :class:`ProtocolIR` from a registry target name or a JSON IR
    file (the ``ProtocolIR.to_dict`` schema)."""
    if os.path.exists(ref):
        with open(ref, "r") as f:
            return ProtocolIR.from_dict(json.load(f))
    from . import targets
    return targets.build(ref, n)


def main(argv=None):
    """CLI entry point: ``python -m rot.refine BEFORE AFTER``.

    Returns the exit code: 0 on ``refined``, 1 otherwise, 2 on
    usage/target errors (argparse convention).
    """
    import argparse
    parser = argparse.ArgumentParser(
        prog="rot.refine",
        description="Phase 4 refinement loop: propose -> check -> repair "
                    "until every pinned invariant holds on the after model "
                    "or no repair step remains attributable.")
    parser.add_argument("before",
                        help="before model: registry target name or JSON IR file")
    parser.add_argument("after",
                        help="after model: registry target name or JSON IR file")
    parser.add_argument("--invariant", action="append", default=[],
                        metavar="NAME",
                        help="invariant name from the rot.invariants registry "
                             "(repeatable; default: the before target's default)")
    parser.add_argument("--n", type=int, default=3,
                        help="participant count for registry targets (default 3)")
    parser.add_argument("--max-states", type=int, default=20000,
                        help="symbolic engine state budget per check (default 20000)")
    parser.add_argument("--rounds", type=int, default=3,
                        help="max propose/check/repair rounds (default 3)")
    parser.add_argument("--out", metavar="DIR", default=None,
                        help="directory to write refinement_report.json into")
    args = parser.parse_args(argv)

    from . import invariants as invmod
    from . import targets

    try:
        before = _load_ir(args.before, args.n)
        after = _load_ir(args.after, args.n)
    except KeyError as exc:
        parser.error(str(exc))

    if args.invariant:
        try:
            invariants = [invmod.get(name, args.n) for name in args.invariant]
        except KeyError as exc:
            parser.error(str(exc))
    else:
        invariants = []
        try:
            invariants = [
                invmod.get(targets.default_property(args.before), args.n)]
        except KeyError:
            pass
    if not invariants:
        parser.error("no invariants to check: pass --invariant NAME "
                     "(a name from the rot.invariants registry)")

    report = run_refinement(before, after, invariants, args,
                            max_rounds=args.rounds)
    text = json.dumps(report.to_dict(), indent=2)
    print(text)
    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        path = os.path.join(args.out, "refinement_report.json")
        with open(path, "w") as f:
            f.write(text + "\n")
        print("wrote %s" % path)
    return 0 if report.status == REFINED else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
