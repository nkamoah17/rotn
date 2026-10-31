# -*- coding: utf-8 -*-
"""liveness.py -- the liveness discharge layer (Phase 2) and its enforcement teeth.

This is where the liveness claims are decided and -- critically -- where the
spec's enforcement rules (R2 / R3 / R4) are turned into code that a test can
drive, so the rules cannot be silently bypassed.

The soundness core is the **dual-soundness rule** (spec R2): a liveness
``PROVEN`` is sound only under one of two explicit, recorded conditions --

  (R2a) **bounded** discharge: the goal is *reachable within the horizon*,
      discharged by the **concrete** symbolic engine with a *complete*
      horizon (``horizon_complete``).  No fairness is assumed.  This is the
      DEFAULT and is what the pipeline uses.

  (R2b) **fairness** discharge: the *unbounded* claim ``<>Goal`` discharged
      under a weak-fairness assumption ``WF(action)`` on a *harness* action,
      by a sound engine (Apalache primary, TLC cross-check -- spec D2).  The
      fairness formula is **always recorded** on the verdict (never silent).

A ``PROVEN`` that satisfies neither condition is **downgraded to UNKNOWN**
with an explicit note.  That is the "teeth": the rule is not a comment, it is
a check that runs on every liveness verdict.

The other two rules are enforced the same way:

  (R3) **no vacuity**: the goal must not be trivially true in the initial
      state (else "reachable within H" holds for 0 steps and proves nothing),
      and the checker must be able to *fail* -- the buggy (livelock) harness
      must leave the goal unreachable (the negative control).

  (R4) **no spurious liveness**: the goal must be a *decided outcome* (the
      task ends / escalates), not a tautology or a trivially-true flag.

Phase 6 (TLA+ essentials):

  * **The stuttering assumption is stated, never silent.**  The IR's
    transition system has no stuttering (no-op) steps, so every liveness
    verdict here carries :data:`rot.ir.STUTTERING_ASSUMPTION`: the claim is
    **safety-safe** (a safety invariant holding in all non-stuttering
    reachable states holds under stuttering extensions) but **liveness
    honest** (an unbounded ``<>Goal`` is sound only *under* the assumption
    -- the no-stuttering property itself, or a fairness assumption that
    rules out infinite stuttering, is what closes the gap).
  * **Fairness beyond single-action weak** (Phase 6.3): the unbounded
    discharge states and records the full fairness formula -- strong
    fairness ``SF(a)`` and multi-action conjunctions
    ``WF(a1) / WF(a2)`` / ``SF(a1) / SF(a2)`` -- and validates the named
    actions against the model (a formula over a non-existent action fails
    closed).  The fairness-aware engine discharge itself is Apalache-level
    (spec D2); until then the path fails closed to UNKNOWN with the
    formula recorded.

Pure stdlib, Python 3.6 compatible (no f-strings).
"""

# Discharge-path constants (recorded on ``Verdict.discharge``).
DISCHARGE_BOUNDED   = "bounded"
DISCHARGE_FAIRNESS  = "fairness"

# The harness decision action on which weak fairness WF(action) is imposed for
# the unbounded (R2b) discharge.  Fairness is stated on *harness* actions only
# (the adversary/agent is never granted fairness).  Overridable per-run via
# ``Config.fairness_action``.
DEFAULT_FAIRNESS_ACTION = "Decide"


# ---------------------------------------------------------------------------
# R2 -- the dual-soundness rule (enforced, not asserted)
# ---------------------------------------------------------------------------
def r2_soundness_ok(discharge, concrete, horizon_complete, fairness_label):
    """Spec R2: is a liveness ``PROVEN`` sound under these discharge conditions?

    Parameters
    ----------
    discharge : str
        ``DISCHARGE_BOUNDED`` or ``DISCHARGE_FAIRNESS``.
    concrete : bool
        True iff the deciding engine is a *concrete* (state-space) engine
        (the symbolic engine).  An over-approximating engine that returns
        "proved" without a concrete witness does NOT satisfy R2a.
    horizon_complete : bool
        True iff the bounded search fully drained (the horizon was not cut
        short by the state budget).
    fairness_label : str or None
        The explicit weak-fairness formula (e.g. ``"WF(Decide)"``), or
        ``None`` when no fairness was assumed.

    Returns
    -------
    bool
        ``True`` iff a ``PROVEN`` verdict is sound under these conditions.
    """
    if discharge == DISCHARGE_BOUNDED:
        # Bounded liveness is sound iff the deciding engine is concrete and the
        # horizon was fully explored.  No fairness may be (silently) assumed:
        # a bounded claim is a pure reachability claim.
        return bool(concrete and horizon_complete and fairness_label is None)
    if discharge == DISCHARGE_FAIRNESS:
        # Unbounded liveness is sound only with an EXPLICIT fairness formula
        # recorded on the verdict (never silent).
        return fairness_label is not None and str(fairness_label).strip() != ""
    return False


def _enforce_r2(verdict, discharge, concrete, horizon_complete, fairness_label):
    """If ``verdict`` is a liveness PROVEN but R2 does not hold, downgrade it
    to UNKNOWN with an explicit note (the "teeth").  Non-PROVEN verdicts pass
    through unchanged (a sound "could not decide" is already the safe answer).
    """
    from .verdicts import Verdict

    if verdict.status != "proven":
        return verdict
    if r2_soundness_ok(discharge, concrete, horizon_complete, fairness_label):
        return verdict
    note = ("R2 (dual-soundness rule) not satisfied: a liveness PROVEN "
            "requires either (a) a concrete engine with a complete horizon "
            "(bounded) or (b) an explicit fairness formula recorded on the "
            "verdict (unbounded).  discharge=%r concrete=%r "
            "horizon_complete=%r fairness_label=%r -- downgraded to UNKNOWN "
            "rather than emit a silent, unsound PROVEN."
            % (discharge, concrete, horizon_complete, fairness_label))
    return Verdict.unknown(
        verdict.property_name, verdict.engine,
        n_states=verdict.n_states, evidence=verdict.evidence,
        property_kind=verdict.property_kind,
        discharge=verdict.discharge, fairness_label=verdict.fairness_label,
        stuttering_assumption=getattr(verdict, "stuttering_assumption", None),
        note=note)


# ---------------------------------------------------------------------------
# R3 -- no vacuity  (goal not trivially true + a negative control that fails)
# ---------------------------------------------------------------------------
def r3_goal_not_vacuous(model, goal_expr):
    """Spec R3: the goal must not be trivially true in the *initial* state.

    If the goal already holds in init, then "reachable within H" holds for 0
    steps and the check proves nothing (a vacuous liveness).  Returns
    ``(ok, reason)``.
    """
    init = dict(model.init_state)
    r = goal_expr.eval(init)
    if r is True:
        return False, ("goal already holds in the initial state -- "
                       "'reachable within H' is vacuous (holds for 0 steps)")
    return True, "goal does not hold in the initial state (non-vacuous)"


def _free_vars(expr):
    """Names of the free state variables referenced by ``expr`` (a Var is free;
    BinOp/UnOp/If children are walked; AllOf/AnyOf bind their iteration var).
    Mirrors the IR node set used by the pipeline."""
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


def r3_negative_control(buggy_model, goal_expr, horizon, max_states):
    """Spec R3 (negative control): the checker must be able to *fail*.

    On the buggy (livelock) harness the goal must be **not** reachable within
    the horizon.  If the goal is reachable there too, the checker is not
    discriminating (spurious liveness).  Returns ``(ok, note)``.
    """
    from .symbolic import SymbolicEngine, REACHED, NOT_REACHED

    res = SymbolicEngine(buggy_model, max_states=max_states).reach_within(
        goal_expr, horizon, max_states=max_states)
    if res.status == REACHED:
        return False, ("negative control FAILED: the goal is reachable even on "
                      "the buggy (livelock) harness -- the checker is not "
                      "discriminating (spurious liveness, spec R4)")
    if res.status == NOT_REACHED:
        return True, ("negative control OK: the goal is NOT reachable on the "
                     "buggy (livelock) harness -- the checker discriminates")
    return False, ("negative control INCONCLUSIVE: the bounded search was "
                  "truncated before the horizon on the buggy harness")


# ---------------------------------------------------------------------------
# R4 -- no spurious liveness (the goal is a decided outcome, not a tautology)
# ---------------------------------------------------------------------------
def r4_goal_is_decided_outcome(model, goal_expr):
    """Spec R4: the liveness goal must be a *decided outcome* (the task ends /
    escalates), not a tautology or a trivially-true flag.

    Heuristic checks (all must pass for the goal to be admissible):
      1. the goal references at least one state variable (not the constant
         ``True`` / a tautology over nothing);
      2. the goal is not already true in the initial state (else it holds
         vacuously -- see :func:`r3_goal_not_vacuous`).

    Returns ``(ok, reason)``.
    """
    free = _free_vars(goal_expr)
    if not free:
        return False, ("goal references no state variable -- it is a constant "
                      "(tautology), not a decided outcome (spec R4)")
    init = dict(model.init_state)
    if goal_expr.eval(init) is True:
        return False, ("goal holds in the initial state -- a decided outcome "
                      "must be something the system must *get to* (spec R4)")
    return True, ("goal references %r and is not initial -- a decided outcome"
                 % ", ".join(free))


# ---------------------------------------------------------------------------
# Cross-engine discharge
# ---------------------------------------------------------------------------
def _symbolic_reach(model, goal_expr, horizon, max_states):
    """Primary discharge: the concrete symbolic engine's bounded reachability.

    Returns a :class:`rot.symbolic.ReachResult` (REACHED / NOT_REACHED /
    UNKNOWN).  This engine is concrete, so its REACHED / NOT_REACHED answers
    are sound (spec R2a) -- a pure reachability claim, no fairness involved.
    """
    from .symbolic import SymbolicEngine
    eng = SymbolicEngine(model, max_states=max_states)
    return eng.reach_within(goal_expr, horizon, max_states=max_states)


def _tlc_crosscheck(model, goal_expr, horizon, cfg, target="model"):
    """Cross-check reachability-within-bound with real TLC (cross-engine
    agreement).

    "Goal reachable within H" is expressed as the SAFETY property
    ``NOT Goal`` bounded to H steps (``-depth H``).  TLC's answer maps to the
    liveness question:

      * TLC ``violated`` -- some state within H has ``Goal`` true -> the goal
        is reachable within H -> **liveness holds** ("reached");
      * TLC ``proven``   -- ``NOT Goal`` holds in every state within H -> the
        goal is not reachable within H -> **liveness fails** ("not_reached");
      * otherwise         -- inconclusive -> "unknown".

    Returns one of ``"reached"`` / ``"not_reached"`` / ``"unknown"``.
    """
    from .ir import Not
    from .invariants import Invariant
    from .tlc import TlcEngine
    from .config import Config, ENGINE_TLC

    prop = Invariant(
        name="liveness_crosscheck_notgoal",
        description="cross-check: the goal is NOT reachable within the bound",
        expression=Not(goal_expr),
        kind="safety")

    sub_cfg = Config(
        engine=ENGINE_TLC,
        tlc_jar=cfg.tlc_jar,
        java_cmd=cfg.java_cmd,
        tlc_timeout=cfg.tlc_timeout,
        tlc_depth=int(horizon),
        work_dir=cfg.work_dir,
        out_dir=cfg.out_dir,
    )
    res = TlcEngine(sub_cfg).check(model, prop, target=target)
    if res.status == "violated":
        return "reached"
    if res.status == "proven":
        return "not_reached"
    return "unknown"


def fairness_label_for(cfg, action=None):
    """Build the explicit weak-fairness formula label for an unbounded
    liveness discharge (spec R2b / D2).

    ``action`` defaults to ``cfg.fairness_action`` or
    :data:`DEFAULT_FAIRNESS_ACTION`.  Fairness is stated on *harness* actions
    only.  Returns a string like ``"WF(Decide)"``.

    Phase 6.3: for strong / multi-action fairness use
    :func:`fairness_formula_for` (this function is the single-action weak
    special case, kept for backward compatibility).
    """
    a = action or getattr(cfg, "fairness_action", None) or DEFAULT_FAIRNESS_ACTION
    return "WF(%s)" % a


def fairness_formula_for(cfg):
    """Phase 6.3: resolve the fairness formula from the config.

    Returns ``(mode, actions, formula)`` where ``mode`` is ``"strong"`` or
    ``"weak"`` and ``formula`` is the TLA+ fairness formula:

      * ``cfg.strong_fairness_actions`` (one or more harness actions) ->
        strong fairness ``SF(a1) / SF(a2) / ...``;
      * ``cfg.weak_fairness_actions`` (two or more harness actions) ->
        multi-action weak fairness ``WF(a1) / WF(a2) / ...``;
      * otherwise the single-action weak fairness ``WF(action)`` (the
        pre-Phase-6 behavior: ``cfg.fairness_action`` or the default).

    Fairness is stated on *harness* actions only -- it is never imposed on
    the agent (adversary).  The formula is ALWAYS recorded on the verdict
    (never silent; spec R2 / D2).
    """
    sf = [a for a in (getattr(cfg, "strong_fairness_actions", None) or []) if a]
    if sf:
        return "strong", list(sf), " / ".join("SF(%s)" % a for a in sf)
    wf = [a for a in (getattr(cfg, "weak_fairness_actions", None) or []) if a]
    if len(wf) > 1:
        return "weak", list(wf), " / ".join("WF(%s)" % a for a in wf)
    a = getattr(cfg, "fairness_action", None) or DEFAULT_FAIRNESS_ACTION
    return "weak", [a], "WF(%s)" % a


def _stuttering(model):
    """The stuttering assumption a verdict over ``model`` carries (Phase 6.1).

    The model's own statement wins (it is the single source of truth); the
    canonical :data:`rot.ir.STUTTERING_ASSUMPTION` text is the fallback so
    the assumption is stated even for models built before Phase 6.
    """
    from .ir import STUTTERING_ASSUMPTION
    s = getattr(model, "stuttering_assumption", None)
    return s if s else STUTTERING_ASSUMPTION


def _discharge_bounded(model, goal_expr, prop, cfg, horizon, target):
    """Discharge the *bounded* liveness claim (goal reachable within
    ``horizon``) with cross-engine agreement, then enforce R2 / R3 / R4.

    Returns a :class:`rot.verdicts.Verdict`.
    """
    from .symbolic import REACHED
    from .verdicts import Verdict

    engine = "symbolic"
    max_states = int(getattr(cfg, "max_states", 200000) or 200000)

    # R3/R4 pre-checks on the goal itself (fail-closed: a vacuous or
    # non-decided goal is never PROVEN).
    vac_ok, vac_reason = r3_goal_not_vacuous(model, goal_expr)
    dec_ok, dec_reason = r4_goal_is_decided_outcome(model, goal_expr)
    if not (vac_ok and dec_ok):
        return Verdict.unknown(
            prop.name, engine, n_states=0,
            property_kind=prop.kind, discharge=DISCHARGE_BOUNDED,
            evidence={"r3_vacuity": vac_reason, "r4_decided": dec_reason},
            stuttering_assumption=_stuttering(model),
            note=("liveness goal rejected before checking -- R3/R4: %s; %s"
                  % (vac_reason, dec_reason)))

    # Primary discharge (concrete symbolic engine).
    reach = _symbolic_reach(model, goal_expr, horizon, max_states)
    primary_holds = (reach.status == REACHED)

    # Cross-check (TLC) -- agreement required.
    xcheck = _tlc_crosscheck(model, goal_expr, horizon, cfg, target=target)
    xcheck_holds = (xcheck == "reached")

    evidence = {
        "discharge": DISCHARGE_BOUNDED,
        "horizon": horizon,
        "primary": {
            "engine": "symbolic",
            "status": reach.status,
            "n_states": int(getattr(reach, "n_states", 0) or 0),
            "horizon_complete": bool(getattr(reach, "horizon_complete", False)),
        },
        "crosscheck": {"engine": "tlc", "status": xcheck},
        "agreement": (xcheck == "unknown") or (primary_holds == xcheck_holds),
    }
    if getattr(reach, "depth", None) is not None:
        evidence["primary"]["depth"] = reach.depth

    # Disagreement between the two engines -> UNKNOWN (fail-closed).
    if xcheck != "unknown" and primary_holds != xcheck_holds:
        return Verdict.unknown(
            prop.name, engine, n_states=evidence["primary"]["n_states"],
            property_kind=prop.kind, discharge=DISCHARGE_BOUNDED,
            evidence=evidence,
            stuttering_assumption=_stuttering(model),
            note=("cross-engine disagreement on bounded liveness: symbolic=%r "
                  "tlc=%r -- refusing to PROVEN/VOLATED on a single engine "
                  "(spec: cross-engine agreement required)"
                  % (reach.status, xcheck)))

    # Cross-check unavailable/inconclusive: the primary is concrete and sound,
    # so we may use its answer -- but we record that the cross-check did not
    # independently confirm it (never a silent single-engine PROVEN).
    cross_unavailable = (xcheck == "unknown")
    suffix = ("" if not cross_unavailable
              else "; TLC cross-check unavailable -- concrete primary only")

    if primary_holds:
        verdict = Verdict.proven(
            prop.name, engine, n_states=evidence["primary"]["n_states"],
            property_kind=prop.kind, discharge=DISCHARGE_BOUNDED,
            evidence=evidence,
            stuttering_assumption=_stuttering(model),
            note=("goal reachable within horizon %d (symbolic%s)"
                  % (horizon, suffix)))
    else:
        verdict = Verdict.violated(
            prop.name, engine, counterexample={},
            n_states=evidence["primary"]["n_states"],
            property_kind=prop.kind, discharge=DISCHARGE_BOUNDED,
            evidence=evidence,
            stuttering_assumption=_stuttering(model),
            note=("goal NOT reachable within horizon %d (symbolic%s) -- "
                  "bounded liveness violated" % (horizon, suffix)))
    return _enforce_r2(verdict, DISCHARGE_BOUNDED, concrete=True,
                       horizon_complete=bool(getattr(reach, "horizon_complete",
                                                     False)),
                       fairness_label=None)


def _discharge_unbounded(model, goal_expr, prop, cfg, target):
    """Discharge the *unbounded* liveness claim ``<>Goal`` under a stated
    fairness assumption (spec R2b / D1 / D2).

    The fairness formula is ALWAYS recorded on the verdict (never silent).
    Phase 6.3: the assumption generalizes beyond single-action weak
    fairness -- strong fairness ``SF(a)`` and multi-action conjunctions
    ``WF(a1) / WF(a2)`` / ``SF(a1) / SF(a2)`` -- and the named actions are
    validated against the model's action set (a formula over an action the
    model does not have fails closed rather than being silently recorded).

    The fairness-aware engine discharge itself is Apalache-level (spec D2);
    this build records the assumption and FAILS CLOSED to UNKNOWN rather
    than emit a PROVEN that is not soundly discharged under the fairness
    assumption.  (A counterexample to the *un-fair* ``<>Goal`` is not, by
    itself, a counterexample to the fair claim -- the witnessing behavior
    may not satisfy the fairness formula -- so we do not use it either.)
    The bounded path -- the default -- is the sound, cross-checked liveness
    discharge.

    Returns a :class:`rot.verdicts.Verdict`.
    """
    from .verdicts import Verdict

    engine = getattr(cfg, "fairness_engine", "apalache") or "apalache"
    mode, actions, formula = fairness_formula_for(cfg)
    fairness = {"mode": mode, "actions": list(actions), "formula": formula}
    evidence = {
        "discharge": DISCHARGE_FAIRNESS,
        "fairness": fairness,
        "fairness_label": formula,
        "primary_engine": engine,
    }

    # A fairness formula must name actions the model actually has -- a
    # formula over a non-existent action is never silently recorded.
    try:
        known = set(model.actions_by_name().keys())
    except Exception:
        known = set()
    missing = [a for a in actions if a not in known]
    if missing:
        return Verdict.unknown(
            prop.name, engine, n_states=0,
            property_kind=prop.kind, discharge=DISCHARGE_FAIRNESS,
            fairness_label=formula, evidence=evidence,
            stuttering_assumption=_stuttering(model),
            note=("fairness action(s) %r are not actions of the model -- "
                  "the fairness formula %s cannot be discharged; failing "
                  "closed to UNKNOWN rather than record a fairness "
                  "assumption over an action that does not exist"
                  % (missing, formula)))

    # The unbounded (fair) liveness claim ``<fairness> => <>Goal`` can only
    # be soundly discharged if the fairness assumption is actually *applied
    # to the spec* and checked under it.  This build records the assumption
    # (never silent -- the formula is always on the verdict, and the emitter
    # can emit ``ASSUME <fairness>`` in the ``.cfg``, spec D2) but does not
    # yet perform a fairness-aware engine discharge, so it FAILS CLOSED to
    # UNKNOWN rather than emit a PROVEN that is not soundly discharged under
    # the fairness assumption.
    return Verdict.unknown(
        prop.name, engine, n_states=0,
        property_kind=prop.kind, discharge=DISCHARGE_FAIRNESS,
        fairness_label=formula, evidence=evidence,
        stuttering_assumption=_stuttering(model),
        note=("unbounded liveness claim %s => <>Goal requires a "
              "fairness-aware discharge (%s fairness on %r); this build "
              "records the fairness assumption (never silent) and fails "
              "closed to UNKNOWN rather than emit an unsound PROVEN.  Use "
              "the bounded path (default) for the sound, cross-checked "
              "liveness discharge." % (formula, mode, actions)))


def discharge_liveness(model, goal_expr, prop, cfg, horizon=None, target="model"):
    """Discharge a liveness claim with cross-engine agreement + R2/R3/R4.

    Routes on ``cfg.unbounded_liveness``:

      * off (default) -> the *bounded* claim (goal reachable within the
        horizon), discharged by the concrete symbolic engine and cross-checked
        by TLC.  This is the sound, fairness-free default.
      * on            -> the *unbounded* claim ``<>Goal`` under a stated
        fairness assumption (spec R2b / D2): single-action weak fairness
        ``WF(action)`` (the pre-Phase-6 default), strong fairness
        ``SF(action)`` (``cfg.strong_fairness_actions``), or multi-action
        weak fairness ``WF(a1) / WF(a2)`` (``cfg.weak_fairness_actions``,
        Phase 6.3).  The fairness formula is ALWAYS recorded.

    Phase 6.1: every verdict carries the stated stuttering assumption
    (:data:`rot.ir.STUTTERING_ASSUMPTION` via ``model.stuttering_assumption``)
    -- safety-safe, liveness-honest.

    Returns a :class:`rot.verdicts.Verdict`.  A ``PROVEN`` is only returned
    when the dual-soundness rule (R2) is satisfied; otherwise the verdict is
    ``UNKNOWN`` (fail-closed).
    """
    if horizon is None:
        horizon = int(getattr(cfg, "liveness_horizon", 12) or 12)
    if getattr(cfg, "unbounded_liveness", False):
        return _discharge_unbounded(model, goal_expr, prop, cfg, target)
    return _discharge_bounded(model, goal_expr, prop, cfg, horizon, target)


__all__ = [
    "DISCHARGE_BOUNDED", "DISCHARGE_FAIRNESS", "DEFAULT_FAIRNESS_ACTION",
    "r2_soundness_ok", "r3_goal_not_vacuous", "r3_negative_control",
    "r4_goal_is_decided_outcome", "fairness_label_for", "fairness_formula_for",
    "discharge_liveness",
]