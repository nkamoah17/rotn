# -*- coding: utf-8 -*-
"""targeted_test.py -- Step 3.5: turn a ``SpecDiff`` / ``GateImpact`` into a
targeted suite of W3 replay schedules, each with its expected verdict.

``rot.gateimpact`` answers *where* a change is risky -- which changed gate
actions and which witness steps carry it.  This module answers *what to run*:
it turns that analysis into a concrete, ordered suite of W3 ``rotn-schedule``
replays that

  * directly exercise the changed gate actions / impacted witness steps, and
  * include a **control** schedule that MUST stay compliant, so the harness is
    proven to *discriminate* rather than merely always failing.

Each schedule carries its **expected verdict** (``violation`` / ``compliance``)
computed by replaying the schedule through a small pure-Python interpreter of
the target's IR (:func:`replay_schedule`).  Before the Java gate runs, a
reviewer therefore sees what W3 is *supposed* to return on the baseline
(``before``) vs. the candidate (``after``), and which schedules detect a
**regression** (baseline complies, candidate violates).

A schedule is exactly the W3/W4 artifact consumed by ``rot.witness`` /
``rot.schedulecheck`` and the ``twopc-java/scheduler`` pipeline (see
``write_schedule`` in ``rot/witness.py``):

  * line 1    -- the header   ``{"_meta":"rotn-schedule","format":"v1",...}``
  * lines 2.. -- the gate steps ``{"owner":...,"action":...,"step":i}``

so each ``<out>/<schedule_id>.jsonl`` drops straight into W4, and
``manifest.json`` maps every schedule to the changed action / witness step it
targets and to its expected verdict.

The W3 gate contract is 2PC-specific, so the **control** schedule is
2PC-shaped (unanimous commit); the **witness** schedule is emitted for any
target whose witness path maps to gate steps.

Pure stdlib, Python 3.6 compatible.

Usage (module form; the package imports require -m):
    python -m rot.targeted_test correct buggy --out targeted
Exit codes: 0 = suite generated, 2 = usage.
"""
from __future__ import print_function

import json
import os
import sys

import rot.targets as targets
import rot.gateimpact as gateimpact
import rot.specdiff as specdiff
import rot.witness as witness
from rot.linearization import linearize
from rot.ir import Expr

UNDEF = Expr.UNDEF

# Verdict vocabulary (matches W3/W4).
VERDICT_VIOLATION = "violation"
VERDICT_COMPLIANCE = "compliance"


# ---------------------------------------------------------------------------
# Pure-Python replay oracle: computes a schedule's "expected verdict".
# ---------------------------------------------------------------------------
def _eval(expr, state):
    """Evaluate ``expr`` in ``state``; any error / undefined -> UNDEF."""
    try:
        return expr.eval(state)
    except Exception:
        return UNDEF


def replay_schedule(ir, property_expr, path):
    """Replay ``path`` (a list of action names) on ``ir`` and report the verdict.

    Each action fires when its guard is ``True`` in the current state (the
    gate's "fire when enabled" semantics); a ``False`` / ``UNDEF`` guard is
    skipped and recorded.  Actions absent from the IR are skipped.  The verdict
    is ``violation`` when the pinned property is ``False`` in the final state,
    ``compliance`` otherwise (``True`` or ``UNDEF`` are not counterexamples).

    Returns a dict with: ``verdict``, ``state``, ``applied``, ``skipped``,
    ``property_value``.
    """
    model = linearize(ir)
    state = dict(model.init_state)
    actions = model.actions_by_name()
    applied, skipped = [], []
    for name in path:
        act = actions.get(name)
        if act is None:
            skipped.append([name, "absent"])
            continue
        if _eval(act.guard, state) is not True:
            skipped.append([name, "guard-disabled"])
            continue
        state = model._apply_effects(state, act.effects)
        applied.append(name)
    pv = _eval(property_expr, state) if property_expr is not None else True
    return {
        "verdict": VERDICT_VIOLATION if pv is False else VERDICT_COMPLIANCE,
        "state": state,
        "applied": applied,
        "skipped": skipped,
        "property_value": pv,
    }


# ---------------------------------------------------------------------------
# A single targeted schedule.
# ---------------------------------------------------------------------------
class TargetedSchedule(object):
    """One W3 replay + its expected verdict + the change it targets.

    ``expected_verdict`` is what the suite asserts (the AFTER / candidate
    verdict, or a pinned ``compliance`` for controls).  ``detects_regression``
    is True when the baseline complies but the candidate violates -- i.e. the
    schedule is the discriminating test for the change.
    """

    def __init__(self, schedule_id, case, reason, path, before_verdict,
                 after_verdict, expected_verdict,
                 changed_actions=None, impacted_step_indices=None,
                 state=None, applied=None, skipped=None,
                 detects_regression=False):
        self.schedule_id = schedule_id
        self.case = case
        self.reason = reason
        self.path = list(path)
        self.before_verdict = before_verdict
        self.after_verdict = after_verdict
        self.expected_verdict = expected_verdict
        self.changed_actions = list(changed_actions or [])
        self.impacted_step_indices = list(impacted_step_indices or [])
        self.state = state
        self.applied = list(applied or [])
        self.skipped = [list(t) for t in (skipped or [])]
        self.detects_regression = bool(detects_regression)

    def to_dict(self):
        return {
            "schedule_id": self.schedule_id,
            "case": self.case,
            "reason": self.reason,
            "path": self.path,
            "before_verdict": self.before_verdict,
            "after_verdict": self.after_verdict,
            "expected_verdict": self.expected_verdict,
            "detects_regression": self.detects_regression,
            "changed_actions": self.changed_actions,
            "impacted_step_indices": self.impacted_step_indices,
            "applied": self.applied,
            "skipped": self.skipped,
            "state": self.state,
        }


# ---------------------------------------------------------------------------
# Suite-construction helpers.
# ---------------------------------------------------------------------------
def _action_names(ir):
    return [a.name for a in linearize(ir).actions]


def _is_2pc(ir):
    names = set(_action_names(ir))
    return ("decide" in names
            and any(x.startswith("vote_") for x in names)
            and any(x.startswith("apply_") for x in names))


def _control_path(ir, n):
    """A 2PC-shaped baseline path (unanimous commit) that should stay compliant."""
    if not _is_2pc(ir):
        return None
    names = set(_action_names(ir))
    path = []
    for p in range(1, n + 1):
        nm = "vote_%d_yes" % p
        if nm in names:
            path.append(nm)
    if "decide" in names:
        path.append("decide")
    for p in range(1, n + 1):
        nm = "apply_%d" % p
        if nm in names:
            path.append(nm)
    return path or None


def _reach_path(ir, action_name, max_states=50000):
    """Best-effort path that fires ``action_name`` (guard True, then the action)."""
    model = linearize(ir)
    target = model.actions_by_name().get(action_name)
    if target is None:
        return None
    init = dict(model.init_state)
    if _eval(target.guard, init) is True:
        return [action_name]
    seen = {frozenset(init.items())}
    queue = [(init, [])]
    i = 0
    while i < len(queue) and len(seen) < max_states:
        state, path = queue[i]
        i += 1
        for a in model.actions:
            if a.name == action_name or _eval(a.guard, state) is not True:
                continue
            ns = model._apply_effects(state, a.effects)
            if _eval(target.guard, ns) is True:
                return path + [a.name, action_name]
            key = frozenset(ns.items())
            if key not in seen:
                seen.add(key)
                queue.append((ns, path + [a.name]))
    return None


# ---------------------------------------------------------------------------
# Suite generation.
# ---------------------------------------------------------------------------
def generate_suite(before, after, property_expr, spec_diff, gate_impact,
                   witness_path, n):
    """Build the targeted suite for a resolved before/after ``ProtocolIR`` pair.

    Emits (in order) a ``witness`` schedule (the counterexample, the
    discriminating test), one ``act_<name>`` schedule for each changed gate
    action not already exercised by the witness path, and a 2PC-shaped
    ``control`` schedule that must stay compliant.
    """
    schedules = []
    changed = ([ai.action for ai in gate_impact.changed_gate_actions]
               if gate_impact else [])
    impacted = list(gate_impact.impacted_step_indices) if gate_impact else []
    witness_path = list(witness_path or [])

    # 1. WITNESS -- the counterexample (baseline complies, candidate violates).
    if witness_path:
        bv = replay_schedule(before, property_expr, witness_path)
        av = replay_schedule(after, property_expr, witness_path)
        covers = [a for a in changed if a in witness_path]
        schedules.append(TargetedSchedule(
            schedule_id="witness", case="witness",
            reason="counterexample: reaches a state where the pinned property is "
                   "definitely violated on the candidate",
            path=witness_path,
            before_verdict=bv["verdict"], after_verdict=av["verdict"],
            expected_verdict=av["verdict"],
            changed_actions=covers, impacted_step_indices=impacted,
            state=av["state"], applied=av["applied"], skipped=av["skipped"],
            detects_regression=(bv["verdict"] == VERDICT_COMPLIANCE
                                and av["verdict"] == VERDICT_VIOLATION),
        ))

    # 2. Per changed gate action not already exercised by the witness path.
    for ai in (gate_impact.changed_gate_actions if gate_impact else []):
        if ai.action in witness_path:
            continue
        path = _reach_path(after, ai.action)
        if not path:
            continue
        bv = replay_schedule(before, property_expr, path)
        av = replay_schedule(after, property_expr, path)
        idxs = [i for i, a in enumerate(path) if a == ai.action]
        schedules.append(TargetedSchedule(
            schedule_id="act_%s" % ai.action, case="changed-action",
            reason="targeted exercise of changed gate action '%s' "
                   "(severity: %s)" % (ai.action, ai.severity),
            path=path,
            before_verdict=bv["verdict"], after_verdict=av["verdict"],
            expected_verdict=av["verdict"],
            changed_actions=[ai.action], impacted_step_indices=idxs,
            state=av["state"], applied=av["applied"], skipped=av["skipped"],
            detects_regression=(bv["verdict"] == VERDICT_COMPLIANCE
                                and av["verdict"] == VERDICT_VIOLATION),
        ))

    # 3. CONTROL -- a baseline run that must stay compliant (2PC-shaped).
    control = _control_path(after, n)
    if control:
        bv = replay_schedule(before, property_expr, control)
        av = replay_schedule(after, property_expr, control)
        schedules.append(TargetedSchedule(
            schedule_id="control", case="control",
            reason="control: a baseline run that must stay compliant so the "
                   "harness is proven to discriminate",
            path=control,
            before_verdict=bv["verdict"], after_verdict=av["verdict"],
            expected_verdict=VERDICT_COMPLIANCE,
            changed_actions=[], impacted_step_indices=[],
            state=av["state"], applied=av["applied"], skipped=av["skipped"],
            detects_regression=False,
        ))
    return schedules


# ---------------------------------------------------------------------------
# Output: W3/W4-compatible schedule files + manifest.
# ---------------------------------------------------------------------------
def write_suite(schedules, out_dir, before_label, after_label,
                property_name, property_expr, n):
    """Write each schedule as a W3 ``rotn-schedule`` file + a ``manifest.json``."""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    entries = []
    for s in schedules:
        steps = witness.witness_to_schedule(s.path)
        result = {"target": after_label, "property": property_name, "n": n,
                  "path": s.path, "state": s.state}
        out_path = os.path.join(out_dir, s.schedule_id + ".jsonl")
        witness.write_schedule(out_path, result, steps)
        entry = s.to_dict()
        entry["file"] = s.schedule_id + ".jsonl"
        entry["n_gate_steps"] = len(steps)
        entries.append(entry)
    manifest = {
        "suite": "rotn-targeted-test", "version": 1,
        "before": before_label, "after": after_label,
        "property": property_name,
        "property_expr": (property_expr.to_dict()
                          if property_expr is not None else None),
        "n": n, "n_schedules": len(schedules), "schedules": entries,
    }
    with open(os.path.join(out_dir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    return manifest


# ---------------------------------------------------------------------------
# High-level entry point.
# ---------------------------------------------------------------------------
def analyze_targeted(before, after, spec_diff=None, gate_impact=None,
                     property_expr=None, property_name=None,
                     witness_path=None, n=2, out_dir=None):
    """Build the targeted suite for a before/after pair (names or ``ProtocolIR``).

    ``property_expr`` (a ``rot.ir.Expr``) pins the invariant to check; when
    omitted, the default property of ``after`` (by name) is used.  ``witness_path``
    (a list of action names) is the counterexample path; when omitted it is
    discovered via ``rot.witness`` (only when ``after`` is a name).

    Returns ``(before_ir, after_ir, spec_diff, gate_impact, schedules)``.
    """
    before_name = before if isinstance(before, str) else getattr(before, "name", "before")
    after_name = after if isinstance(after, str) else getattr(after, "name", "after")
    before_ir = targets.build(before, n) if isinstance(before, str) else before
    after_ir = targets.build(after, n) if isinstance(after, str) else after

    if property_name is None:
        property_name = (targets.get(after).default_property
                         if isinstance(after, str) else "custom")
    if property_expr is None:
        if not isinstance(after, str):
            raise ValueError("property_expr is required when 'after' is a ProtocolIR")
        property_expr = targets.get_property(after, property_name, n=n).expression

    if witness_path is None and isinstance(after, str):
        res = witness.find_witness(after, property_name, n=n)
        witness_path = res.get("path")

    if spec_diff is None:
        spec_diff = specdiff.diff(before_ir, after_ir)
    if gate_impact is None:
        gate_impact = gateimpact.analyze_gate_impact(spec_diff, witness_path or [])

    schedules = generate_suite(before_ir, after_ir, property_expr, spec_diff,
                               gate_impact, witness_path or [], n)
    if out_dir:
        write_suite(schedules, out_dir, before_name, after_name,
                    property_name, property_expr, n)
    return before_ir, after_ir, spec_diff, gate_impact, schedules


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------
def _main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print("usage: python -m rot.targeted_test <before> <after> "
              "[--out DIR] [--n N]")
        print("   e.g. python -m rot.targeted_test correct buggy --out targeted")
        return 2
    before_name, after_name = argv[0], argv[1]
    out_dir = argv[argv.index("--out") + 1] if "--out" in argv else None
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 2
    _, _, sd, gi, schedules = analyze_targeted(
        before_name, after_name, n=n, out_dir=out_dir)
    print(sd.render())
    print(gi.render())
    print("")
    for s in schedules:
        flag = "   [DETECTS REGRESSION]" if s.detects_regression else ""
        print("  %-14s case=%-14s expected=%-10s%s"
              % (s.schedule_id, s.case, s.expected_verdict, flag))
    if out_dir:
        print("")
        print("wrote %d schedule file(s) + manifest.json to %s"
              % (len(schedules), out_dir))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
