# -*- coding: utf-8 -*-
"""ladder.py -- Phase 3: the robustness ladder (R0 -> R1 -> R2).

"Refinement is just implication." The ladder does NOT refine the harness --
the *same system under test* is at every rung -- it **weakens the environment**
rung by rung and shows the claim survives each weakening. Each rung *implies*
the one above it: the same harness, a strictly larger environment, and the same
(stated) fairness on the harness.

  R0 -- ideal           : agent conforming  (``buggy=False``); denied actions
                          are policy-enforced; no harness faults.
  R1 -- adversarial     : agent compromised (``buggy=True``); denied actions are
                          enabled; counterexamples are attack paths.
  R2 -- fault-tolerant  : R1 plus benign harness faults (crash / retry /
                          stutter of harness steps); the claim must survive
                          them (exactly-once, no lost approvals, deadlock-
                          freedom under retry, eventual completion under
                          fairness).

Locked rules (spec section 6, F1--F4):

  **F1 -- monotone safety.** The reachable state space is monotone
      (``Reach(R0)`` is a subset of ``Reach(R1)`` is a subset of
      ``Reach(R2)``), so the rungs where a safety
      claim is PROVEN form a *prefix* of the ladder: a proof at rung ``j``
      implies the proofs at every rung ``i < j``, and a definite violation at a
      lower rung is a violation at every higher rung. We therefore report the
      **highest** rung at which the claim was discharged.

  **F2 -- liveness per rung.** Liveness is re-discharged at each rung under
      *that rung's* fairness; R2's fairness covers the retry/stutter steps, so
      a fair liveness discharge at R2 implies the lower rungs.

  **F3 -- the integrity rung is out of scope.** A compromised *harness*
      (tampered gateway, injected transitions) is **not** a rung. It is a
      named non-claim on every claim packet (T2).

  **F4 -- refinement is evidence.** Each rung's verdict + the implication
      argument is part of the trace (provenance), so the ladder is auditable
      end-to-end.

This module is deliberately distinct from :mod:`rot.refine` (the Phase 4
propose -> check -> repair loop). The ladder *reuses* the verification
machinery (the concrete symbolic engine, CEGAR, the verdict layer) rather than
the before/after refinement loop; it is the "same IR, different environment
model" layer the Phase 3 plan calls for.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

import rot.ir as ir
import rot.approval as approval

__all__ = [
    "R0", "R1", "R2", "FAULT_NAMES",
    "Rung", "RUNGS",
    "rung_by_level", "rung_by_name", "rung_names",
    "environment_for", "fault_actions", "with_faults",
    "build_ir_for_rung",
    "LADDER_TARGETS", "ladder_target_names", "build_fn_for",
    "default_ladder_property",
    "refinement_chain", "implication_argument",
    "run_ladder",
]

# Rung levels (monotone: R0 < R1 < R2).
R0 = 0
R1 = 1
R2 = 2

# The benign harness faults added at R2 (crash / retry / stutter of harness
# steps). They are modelled as no-op self-loops (see :func:`fault_actions`):
# transparent for a robust harness (the claim still holds) and a non-robust
# harness is caught (the claim is violated).
FAULT_NAMES = ("crash", "retry", "stutter")


class Rung(object):
    """One rung of the robustness ladder.

    Attributes
    ----------
    name : str
        ``"R0"`` / ``"R1"`` / ``"R2"``.
    level : int
        The monotone level (0 / 1 / 2).
    label : str
        ``"ideal"`` / ``"adversarial"`` / ``"fault-tolerant"``.
    buggy : bool
        The environment's agent posture (conforming ``False`` / compromised
        ``True``). This is the R0/R1 knob: the *same harness*, a different
        environment.
    harness_faults : tuple of str
        The benign harness faults added at this rung (``()`` for R0/R1,
        :data:`FAULT_NAMES` at R2).
    fairness_actions : tuple of str
        The harness actions on which weak fairness is stated at this rung
        (R2's fairness covers the retry/stutter steps -- spec F2).
    description : str
        A human-readable statement of the rung's environment.
    """

    def __init__(self, name, level, label, buggy, harness_faults,
                 fairness_actions, description):
        self.name = name
        self.level = int(level)
        self.label = label
        self.buggy = bool(buggy)
        self.harness_faults = tuple(harness_faults)
        self.fairness_actions = tuple(fairness_actions)
        self.description = description

    def environment(self):
        """The environment model for this rung (a plain dict, for reports)."""
        return {
            "name": self.name,
            "level": self.level,
            "label": self.label,
            "buggy": self.buggy,
            "harness_faults": list(self.harness_faults),
            "fairness_actions": list(self.fairness_actions),
            "description": self.description,
        }

    def to_dict(self):
        return self.environment()

    def __repr__(self):
        return "<Rung %s (%s)>" % (self.name, self.label)


#: The three rungs, in ascending order (R0 -> R1 -> R2).
RUNGS = [
    Rung("R0", R0, "ideal", buggy=False, harness_faults=(),
         fairness_actions=("Decide",),
         description="ideal environment: the agent is conforming "
                     "(buggy=False) and denied actions are policy-enforced; "
                     "no harness faults."),
    Rung("R1", R1, "adversarial", buggy=True, harness_faults=(),
         fairness_actions=("Decide",),
         description="adversarial environment: the agent is fully compromised "
                     "(buggy=True) and denied actions are enabled; "
                     "counterexamples are attack paths."),
    Rung("R2", R2, "fault-tolerant", buggy=True, harness_faults=FAULT_NAMES,
         fairness_actions=("Decide", "harness_retry", "harness_stutter"),
         description="fault-tolerant environment: R1 plus benign harness "
                     "faults (crash / retry / stutter of harness steps); the "
                     "claim must survive them (exactly-once, no lost approvals, "
                     "deadlock-freedom under retry, eventual completion under "
                     "fairness)."),
]


def rung_by_level(level):
    """The :class:`Rung` at ``level`` (raises ``KeyError`` if unknown)."""
    for r in RUNGS:
        if r.level == int(level):
            return r
    raise KeyError("no rung at level %r; have %r"
                   % (level, [r.level for r in RUNGS]))


def rung_by_name(name):
    """The :class:`Rung` named ``name`` (raises ``KeyError`` if unknown)."""
    for r in RUNGS:
        if r.name == name:
            return r
    raise KeyError("no rung %r; have %r" % (name, rung_names()))


def rung_names():
    """Ordered list of rung names (``["R0", "R1", "R2"]``)."""
    return [r.name for r in RUNGS]


def environment_for(rung):
    """The environment model for ``rung`` (a plain dict, for reports)."""
    return rung.environment()


def fault_actions(faults):
    """The harness-fault actions for ``faults`` (benign no-op self-loops).

    Each fault is a *benign* self-loop (``guard = TRUE``, no effects): the
    harness may stutter / retry / crash-and-recover, and for a robust harness
    the net state change is none. This is the "busy self-loop" that keeps
    terminal states from reading as deadlocks, and it is what makes R2's
    environment a strict superset of R1's (more enabled behaviours) without
    adding spurious reachable state. Marked ``is_env`` so the env-action
    discipline (env asynchrony, never a BLOCK driver) applies.
    """
    out = []
    for fault in faults:
        out.append(ir.Action(
            name="harness_%s" % fault,
            owner="harness",
            guard=ir.T(),
            effects=[],
            linearization="",
            is_env=True,
            source="ladder.py:harness_%s" % fault,
        ))
    return out


def with_faults(ir_model, faults):
    """Return a copy of ``ir_model`` with the harness-fault self-loops added.

    The faults are the :func:`fault_actions` for the given names. The original
    IR is not mutated (a new :class:`rot.ir.ProtocolIR` is returned).
    """
    acts = fault_actions(faults)
    return ir.ProtocolIR(
        name=ir_model.name + "+faults",
        variables=list(ir_model.variables),
        channels=list(ir_model.channels),
        actions=list(ir_model.actions) + acts,
        init=ir_model.init,
        pinned_property=ir_model.pinned_property,
        assumptions=list(ir_model.assumptions),
        abstraction_manifest=list(ir_model.abstraction_manifest),
        source_path=ir_model.source_path,
        metadata=dict(ir_model.metadata),
        policy=ir_model.policy,
    )


def build_ir_for_rung(build_fn, rung, n=1):
    """Build the protocol IR for ``rung`` from ``build_fn`` (the harness).

    "Same IR, different environment model": the harness (``build_fn``) is the
    same at every rung; only the environment changes. R0/R1 differ in the agent
    posture (``buggy``); R2 additionally injects the harness-fault self-loops.
    """
    ir_model = build_fn(n=int(n), buggy=rung.buggy)
    if rung.harness_faults:
        ir_model = with_faults(ir_model, rung.harness_faults)
    return ir_model


# ---------------------------------------------------------------------------
# Ladder-capable targets (the harness build functions, parameterised by buggy)
# ---------------------------------------------------------------------------
#: Mapping of short ladder target name -> harness ``build(n, buggy)`` callable.
#: Each value is the *same harness* at every rung; the ``buggy`` flag is the
#: R0/R1 environment knob, and R2 layers the benign harness faults on top.
LADDER_TARGETS = {
    "approval": approval.approval_build_ir,
    "delegation": approval.delegation_build_ir,
    "orchestration": approval.orchestration_build_ir,
    "budget": approval.budget_build_ir,
    "livelock": approval.livelock_build_ir,
    "deadlock": approval.deadlock_build_ir,
}


def ladder_target_names():
    """Ordered list of ladder-capable target names."""
    return list(LADDER_TARGETS)


def build_fn_for(target):
    """The harness build function for ladder target ``target``.

    Raises ``KeyError`` if ``target`` is not ladder-capable.
    """
    if target not in LADDER_TARGETS:
        raise KeyError("no ladder target %r; have %r"
                       % (target, ladder_target_names()))
    return LADDER_TARGETS[target]


# ---------------------------------------------------------------------------
# The refinement chain + the implication argument (spec F4)
# ---------------------------------------------------------------------------
def refinement_chain(build_fn=None, n=1):
    """The refinement chain: each rung a named layer (spec F4).

    Returns a list of per-rung dicts (the environment model +, when
    ``build_fn`` is given, the IR name it would build) in ascending order
    (R0 -> R1 -> R2).
    """
    chain = []
    for rung in RUNGS:
        layer = {
            "rung": rung.name,
            "level": rung.level,
            "label": rung.label,
            "environment": rung.environment(),
        }
        if build_fn is not None:
            layer["ir_name"] = build_ir_for_rung(build_fn, rung, n).name
        chain.append(layer)
    return chain


def implication_argument():
    """The F1/F4 implication argument (why R2 => R1 => R0).

    "Refinement is just implication." Each rung is the same harness under a
    strictly larger environment, so the reachable state space is monotone and a
    discharge at a higher rung implies the lower rungs. This is the auditable
    record the ladder carries (spec F4).
    """
    return {
        "principle": ("refinement is implication: the same harness under a "
                      "strictly weakening environment rung by rung"),
        "monotone_environment": [
            "Reach(R0) subset-of Reach(R1) subset-of Reach(R2)  "
            "(each rung's reachable states are a superset of the previous)",
            "R0 -> R1 weakens the agent posture (conforming -> compromised)",
            "R1 -> R2 adds benign harness faults (crash / retry / stutter)",
        ],
        "safety_F1": (
            "a safety claim proven at rung j is proven at every rung i < j "
            "(a larger environment only adds paths); a definite violation at a "
            "lower rung is a violation at every higher rung. The ladder "
            "reports the HIGHEST rung at which the claim was discharged."),
        "liveness_F2": (
            "liveness is re-discharged at each rung under that rung's fairness; "
            "R2's fairness covers the retry/stutter steps, so a fair liveness "
            "discharge at R2 implies the lower rungs."),
        "non_claim_F3": (
            "a compromised HARNESS (tampered gateway, injected transitions) is "
            "NOT a rung of this ladder; it is a named non-claim (F3)."),
    }


# ---------------------------------------------------------------------------
# Running the ladder (Phase 3): same harness, weakening environment, per rung
# ---------------------------------------------------------------------------
#: The claim a ladder target pins by default (the harness's thesis rule).
_DEFAULT_LADDER_PROPERTY = {
    "approval": "no_unapproved_irreversible",
    "delegation": "no_privilege_escalation",
    "orchestration": "task_ends_or_escalates",
    "budget": "no_runaway_budget",
    "livelock": "task_ends_or_escalates",
    "deadlock": "no_deadlock",
}


def default_ladder_property(target):
    """The claim a ladder target pins by default (its thesis rule)."""
    return _DEFAULT_LADDER_PROPERTY.get(target, "no_deadlock")


def _attach_rung_fairness(verdict, rung):
    """F2: record the rung's fairness under which the liveness claim holds.

    The rung's fairness actions (``WF(...)``) are recorded on the verdict's
    ``evidence`` + ``assumptions`` + ``fairness_label`` so the liveness
    discharge is never read as stronger than its stated fairness.
    """
    fairness = ", ".join("WF(%s)" % a for a in rung.fairness_actions) or "none"
    ev = dict(verdict.evidence or {})
    ev["rung"] = rung.name
    ev["rung_label"] = rung.label
    ev["fairness"] = fairness
    verdict.evidence = ev
    verdict.assumptions = list(verdict.assumptions or []) + [
        "rung=%s fairness=%s" % (rung.name, fairness)]
    verdict.fairness_label = fairness
    return verdict


def run_ladder(target="orchestration", property_name=None, n=1,
               max_states=200000, horizon=12, build_fn=None):
    """Run the robustness ladder (R0 -> R1 -> R2) for one claim (Phase 3).

    For each rung, builds the *same harness* under that rung's environment
    (buggy posture + harness faults), discharges the claim -- safety via the
    concrete engine's unreachability check, liveness via bounded reachability
    under the rung's fairness -- and collects the per-rung verdicts. Then
    classifies (F1: highest discharged rung + monotonicity) and names the
    non-claims (F3). Returns the structured ladder result (a dict):

      * ``target`` / ``property`` / ``kind``
      * ``rungs`` -- the per-rung environment model (:func:`refinement_chain`)
      * ``verdicts`` -- rung name -> verdict dict
      * ``highest_discharged_rung`` -- highest rung name with a discharge (F1)
      * ``monotonicity_violations`` -- F1 monotonicity violations (should be [])
      * ``implication`` -- the F1/F4 implication argument
      * ``non_claims`` -- the named non-claims (F3)

    ``build_fn`` (optional) overrides the harness for the run: a callable
    ``build_fn(n=..., buggy=...) -> ProtocolIR``. This lets a test inject a
    *robust* harness (safety holds at every rung) without touching the
    :data:`LADDER_TARGETS` registry. When omitted, the harness is looked up by
    ``target``.
    """
    from rot import classify
    from rot import invariants as invmod
    from rot.linearization import linearize
    from rot.symbolic import SymbolicEngine
    from rot.cegar import cegar, cegar_liveness
    from rot.config import Config

    if build_fn is None:
        build_fn = build_fn_for(target)
    if property_name is None:
        property_name = default_ladder_property(target)
    prop = invmod.get(property_name, n)
    kind = classify.classify_claim(prop)
    cfg = Config(max_states=max_states, liveness_horizon=horizon,
                 engine="symbolic")

    verdicts = {}
    for rung in RUNGS:
        ir_model = build_ir_for_rung(build_fn, rung, n)
        linear_model = linearize(ir_model)
        eng = SymbolicEngine(linear_model, max_states=max_states)
        if kind == invmod.KIND_LIVENESS:
            reach = eng.reach_within(prop.expression, horizon,
                                    max_states=max_states)
            verdict = cegar_liveness(reach, prop, cfg, "symbolic")
            _attach_rung_fairness(verdict, rung)
        else:
            result = eng.check(prop.expression, max_states=max_states)
            verdict = cegar(result, prop, cfg, "symbolic")
        verdicts[rung.name] = verdict

    level_map = {r.level: verdicts[r.name] for r in RUNGS}
    highest = classify.highest_discharged_rung(level_map)
    mono = classify.verify_monotonicity(level_map)

    return {
        "target": target,
        "property": property_name,
        "kind": kind,
        "rungs": refinement_chain(build_fn, n),
        "verdicts": {name: verdicts[name].to_dict() for name in rung_names()},
        "highest_discharged_rung": (rung_names()[highest]
                                    if highest is not None else None),
        "monotonicity_violations": mono,
        "implication": implication_argument(),
        "non_claims": classify.non_claims(),
    }