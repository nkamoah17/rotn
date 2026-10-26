# -*- coding: utf-8 -*-
"""gateimpact.py -- map spec-level changes onto the W3 replay gate and witness.

This module is a thin, READ-ONLY analysis layer. It composes two things that
already exist in the pipeline and reimplements none of the verification:

  * ``rot.specdiff``  -- the semantic before/after ``ProtocolIR`` diff
    (``SpecDiff`` / ``ActionDiff`` with severity NONE < COSMETIC < STRUCTURAL <
    SEMANTIC). See ``rot/specdiff.py``.
  * the W3 2PC gate contract -- the ``(owner, action)`` Java gate points
    (``vote_<i>_<vote>``, ``decide``, ``apply_<i>``) that the replay gate
    enforces. The same mapping is used by ``rot.witness`` and
    ``rot.schedulecheck``; here it is re-declared as a single canonical helper
    (``gate_action``) so the impact analysis is self-contained.

Given (a) a ``SpecDiff`` between a before and after IR and (b) a *witness
path* -- an ordered list of IR action names that reproduces the invariant
violation (e.g. ``rot.witness.find_witness(...)[\"path\"]``) -- it answers the
reviewer's operational questions:

  * which IR actions changed, at what severity (guard? effect? rename? add/remove)?
  * which of those are *gate actions* (the ones the W3 Java replay gates)?
  * which steps of the witness path exercise a changed action, so you can tell
    at a glance whether the counterexample that broke the invariant depends on
    the part of the spec that actually changed?

Pure stdlib, Python 3.6 compatible. No dependency on cegar / abstraction /
pipeline / modelfind.
"""

from . import specdiff

__all__ = [
    "gate_action", "witness_to_gate_steps",
    "changed_gate_actions", "impacted_witness_steps",
    "analyze_gate_impact", "analyze_target_gate_impact",
    "ActionImpact", "WitnessStepImpact", "GateImpact",
]


# ---------------------------------------------------------------------------
# W3 2PC gate contract
# ---------------------------------------------------------------------------
def gate_action(action_name):
    """Map an IR action name to its ``(owner, action)`` Java gate step.

    Returns ``None`` when the action has no Java gate point (``init``,
    ``done``, or anything not part of the 2PC gate contract).

    This mirrors the gate contract re-implemented (privately) in
    ``rot.witness._step_for_action`` and ``rot.schedulecheck._owner_for_action``;
    it is re-declared here so the impact analysis stays self-contained. Keep the
    three in sync.
    """
    if action_name is None:
        return None
    if action_name.startswith("vote_"):
        rest = action_name[len("vote_"):]
        i, _, vote = rest.partition("_")
        if not i or not vote:
            return None
        return ("participant_%s" % i, action_name)
    if action_name == "decide":
        return ("coordinator", "decide")
    if action_name.startswith("apply_"):
        i = action_name[len("apply_"):]
        if not i:
            return None
        return ("participant_%s" % i, action_name)
    return None  # init, done, unknown


def witness_to_gate_steps(witness_path):
    """Ordered ``[(owner, action)]`` Java gate schedule for a witness path.

    Actions without a Java gate point (``init``, ``done``) are skipped; the
    result is the exact schedule the W3 replay gate would enforce. Mirrors
    ``rot.witness.witness_to_schedule``.
    """
    steps = []
    for action in (witness_path or []):
        g = gate_action(action)
        if g is not None:
            steps.append(g)
    return steps


# ---------------------------------------------------------------------------
# impact data classes
# ---------------------------------------------------------------------------
class ActionImpact(object):
    """The impact of one changed IR action on the gate and the witness.

    ``action`` is the after-IR action name (for a rename this is the new name;
    ``old_name`` carries the before-IR name). ``gate`` is the ``(owner,
    action)`` Java gate step when the action is part of the W3 gate contract,
    else ``None``. ``witness_step_indices`` are the 0-based indices into the
    witness path where this action appears.
    """

    def __init__(self, action, diff_kind, severity, reason="",
                 guard_changed=False, effect_changed=False, old_name=None,
                 gate_owner=None, gate_action=None,
                 witness_step_indices=()):
        self.action = action
        self.old_name = old_name
        self.diff_kind = diff_kind          # added / removed / renamed / modified
        self.severity = severity            # specdiff severity constant
        self.reason = reason
        self.guard_changed = bool(guard_changed)
        self.effect_changed = bool(effect_changed)
        self.gate_owner = gate_owner
        self.gate_action = gate_action
        self.witness_step_indices = list(witness_step_indices)
        self.is_gate = gate_owner is not None
        self.impacts_witness = len(self.witness_step_indices) > 0

    @property
    def gate(self):
        """``(owner, action)`` when this is a gate action, else ``None``."""
        return (self.gate_owner, self.gate_action) if self.is_gate else None

    def to_dict(self):
        return {
            "action": self.action,
            "old_name": self.old_name,
            "diff_kind": self.diff_kind,
            "severity": self.severity,
            "reason": self.reason,
            "guard_changed": self.guard_changed,
            "effect_changed": self.effect_changed,
            "gate": ({"owner": self.gate_owner, "action": self.gate_action}
                     if self.is_gate else None),
            "witness_step_indices": list(self.witness_step_indices),
            "impacts_witness": self.impacts_witness,
        }


class WitnessStepImpact(object):
    """One witness step (Java gate step) that exercises a changed action."""

    def __init__(self, step_index, owner, action, action_impact):
        self.step_index = step_index   # index into the witness gate schedule
        self.owner = owner
        self.action = action
        self.action_impact = action_impact   # the ActionImpact that hit this step

    @property
    def severity(self):
        return self.action_impact.severity

    def to_dict(self):
        return {
            "step_index": self.step_index,
            "owner": self.owner,
            "action": self.action,
            "severity": self.severity,
            "diff_kind": self.action_impact.diff_kind,
            "guard_changed": self.action_impact.guard_changed,
            "effect_changed": self.action_impact.effect_changed,
        }


class GateImpact(object):
    """The combined gate + witness impact of a spec diff.

    Carries the full ``spec_diff`` (for the complete action/variable/domain
    detail), the per-action ``ActionImpact`` list, the witness gate schedule,
    and the ``WitnessStepImpact`` list for the steps that exercise a changed
    action.
    """

    def __init__(self, spec_diff, witness_path, actions,
                 witness_steps, impacted_steps):
        self.spec_diff = spec_diff
        self.witness_path = list(witness_path or [])
        self.actions = list(actions)                # list[ActionImpact]
        self.witness_steps = list(witness_steps)    # list[(owner, action)]
        self.impacted_steps = list(impacted_steps)  # list[WitnessStepImpact]

    @property
    def before_name(self):
        return getattr(self.spec_diff, "before_name", None)

    @property
    def after_name(self):
        return getattr(self.spec_diff, "after_name", None)

    @property
    def overall_severity(self):
        return self.spec_diff.severity

    @property
    def changed_gate_actions(self):
        """The changed actions that are part of the W3 gate contract."""
        return [a for a in self.actions if a.is_gate]

    @property
    def impacted_step_indices(self):
        return [w.step_index for w in self.impacted_steps]

    @property
    def impacts_witness(self):
        return len(self.impacted_steps) > 0

    def to_dict(self):
        return {
            "before": self.before_name,
            "after": self.after_name,
            "overall_severity": self.overall_severity,
            "changed_actions": [a.to_dict() for a in self.actions],
            "changed_gate_actions": [a.to_dict()
                                     for a in self.changed_gate_actions],
            "witness_path": list(self.witness_path),
            "witness_steps": [[o, a] for (o, a) in self.witness_steps],
            "impacted_steps": [w.to_dict() for w in self.impacted_steps],
            "impacted_step_indices": self.impacted_step_indices,
            "impacts_witness": self.impacts_witness,
        }

    def render(self):
        lines = ["gate impact: %r -> %r  (overall: %s)"
                 % (self.before_name, self.after_name,
                    (self.overall_severity or "").upper())]
        lines.append("  changed actions (%d):" % len(self.actions))
        if not self.actions:
            lines.append("    (no action changes)")
        for a in self.actions:
            if a.is_gate:
                gate = "  gate: %s.%s" % (a.gate_owner, a.gate_action)
            else:
                gate = "  (not a gate action)"
            if a.witness_step_indices:
                w = "  witness: step(s) %s" % ",".join(
                    str(i) for i in a.witness_step_indices)
            else:
                w = "  witness: not on the witness path"
            lines.append("    ! %r (%s, guard=%s effect=%s) %s %s %s"
                         % (a.action, a.diff_kind, a.guard_changed,
                            a.effect_changed, a.severity, gate, w))
        lines.append("  witness schedule (%d steps):" % len(self.witness_steps))
        if not self.witness_steps:
            lines.append("    (empty)")
        impacted_by_index = dict((w.step_index, w) for w in self.impacted_steps)
        for i, (owner, action) in enumerate(self.witness_steps):
            mark = ""
            if i in impacted_by_index:
                w = impacted_by_index[i]
                mark = "   <-- IMPACTED (%s %s)" % (w.action, w.action_impact.diff_kind)
            lines.append("    %d %s.%s%s" % (i, owner, action, mark))
        lines.append("  => %d of %d witness steps exercise a changed action"
                     % (len(self.impacted_steps), len(self.witness_steps)))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------
def changed_gate_actions(spec_diff):
    """Map every changed IR action in ``spec_diff`` to an ``ActionImpact``.

    Each result carries the diff kind, severity, guard/effect flags, and the
    ``gate`` mapping (``(owner, action)`` or ``None``). Actions that are not
    part of the W3 2PC gate contract are still returned (with ``is_gate``
    False) so a reviewer can see non-gate changes too.

    ``spec_diff`` must expose ``action_diffs()`` (i.e. be a
    ``rot.specdiff.SpecDiff``).
    """
    if not hasattr(spec_diff, "action_diffs"):
        raise ValueError(
            "expected a rot.specdiff.SpecDiff (with action_diffs()), got %r"
            % type(spec_diff))
    out = []
    for d in spec_diff.action_diffs():
        gate = gate_action(d.name)
        owner, ga = gate if gate is not None else (None, None)
        out.append(ActionImpact(
            action=d.name, old_name=d.old_name, diff_kind=d.kind,
            severity=d.severity, reason=d.reason,
            guard_changed=d.guard_changed, effect_changed=d.effect_changed,
            gate_owner=owner, gate_action=ga))
    return out


def impacted_witness_steps(spec_diff, witness_path):
    """Which witness steps exercise an action changed by ``spec_diff``.

    ``witness_path`` is an ordered list of IR action names (a witness trace,
    e.g. ``rot.witness.find_witness(...)[\"path\"]``). Returns a list of
    ``WitnessStepImpact`` -- one per step whose action is one of the changed
    actions -- with the step index, ``(owner, action)`` gate step, and the
    ``ActionImpact`` that hit it.

    Matching is by action name and covers both before- and after-IR names, so
    it works whether the witness trace was produced from the before or the
    after model.
    """
    actions = changed_gate_actions(spec_diff)
    impact_by_name = {}
    for a in actions:
        impact_by_name[a.action] = a
        if a.old_name:
            impact_by_name[a.old_name] = a
    witness_path = list(witness_path or [])
    steps = witness_to_gate_steps(witness_path)
    out = []
    for idx, action in enumerate(witness_path):
        hit = impact_by_name.get(action)
        if hit is None:
            continue
        gate = gate_action(action)
        owner, ga = gate if gate is not None else (None, None)
        out.append(WitnessStepImpact(idx, owner, action, hit))
    return out


def analyze_gate_impact(spec_diff, witness_path):
    """Analyze the gate + witness impact of a spec diff.

    Returns a ``GateImpact`` combining:
      * the full ``spec_diff`` (action/variable/domain detail, overall severity)
      * ``changed_gate_actions`` -- per-action gate mapping + severity
      * ``impacted_witness_steps`` -- the witness steps that exercise a
        changed action, with severity.

    This is the reviewer's one-call entry point: ``analyze_gate_impact(
    compute_spec_diff(before_ir, after_ir), witness_path)``.
    """
    if not hasattr(spec_diff, "action_diffs"):
        raise ValueError(
            "expected a rot.specdiff.SpecDiff (with action_diffs()), got %r"
            % type(spec_diff))
    witness_path = list(witness_path or [])
    actions = changed_gate_actions(spec_diff)
    # fill in witness-step indices per action
    for a in actions:
        a.witness_step_indices = [
            i for i, act in enumerate(witness_path)
            if act == a.action or (a.old_name and act == a.old_name)]
        a.impacts_witness = bool(a.witness_step_indices)
    steps = witness_to_gate_steps(witness_path)
    impacted = impacted_witness_steps(spec_diff, witness_path)
    return GateImpact(spec_diff, witness_path, actions, steps, impacted)


def analyze_target_gate_impact(target_before, target_after, witness_path, n=3):
    """Convenience: build before/after IRs from target names, diff them, and
    analyze gate + witness impact in one call.

    ``witness_path`` is an ordered list of IR action names (a witness trace).
    Example (2PC, the agreement-breaking variant pair)::

        res = rot.witness.find_witness("buggy", "agreement", 3)
        gi = gateimpact.analyze_target_gate_impact(
            "correct", "buggy", res["path"], n=3)
    """
    from . import targets
    before_ir = targets.build(target_before, n)
    after_ir = targets.build(target_after, n)
    d = specdiff.compute_spec_diff(before_ir, after_ir)
    return analyze_gate_impact(d, witness_path)
