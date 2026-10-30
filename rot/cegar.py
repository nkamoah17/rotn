# -*- coding: utf-8 -*-
"""cegar.py -- counterexample-guided refinement: engine result -> final Verdict.

An engine (symbolic or TLC) returns an :class:`rot.symbolic.EngineResult` with a
status of ``proven`` / ``violated`` / ``unknown`` and, for a violation, a
concrete witness state. This module turns that into the auditable
:class:`rot.verdicts.Verdict`, and -- the CEGAR core -- *validates that a
counterexample is real* rather than an artefact of an over-approximation:

  * ``proven``   -> ``Verdict.proven``.
  * ``violated`` -> feasibility check: re-evaluate the invariant in the witness
                    state with the IR's own three-valued ``eval``.
                      - definite False -> a real bug -> ``Verdict.violated``.
                      - not definite   -> spurious    -> ``Verdict.unsound``.
  * ``unknown`` / ``timeout`` -> bounded refinement loop (re-run the engine up
                    to ``Config.cegar_max_iter``). If it converges to proven or
                    violated, report that; otherwise ``Verdict.unknown`` (a
                    sound "we could not decide" -- never silently proven).
  * ``error``    -> ``Verdict.error`` (a tool failed to run).

For the bounded 2PC model both engines are concrete, so a ``violated`` witness
is always IR-feasible and the loop terminates immediately; the loop and the
feasibility check are what make the same code path correct for an
over-approximating engine.

Phase 6 verdict metadata: every verdict carries ``property_kind`` (taken from
``prop.kind``) and each VIOLATED verdict carries a ``violation_code`` -- taken
from the invariant's declared ``violation_code`` (``POLICY_DENIAL`` by default,
``LIVENESS_BOUND_EXCEEDED`` for liveness invariants, ``DEADLOCK`` for the
``no_deadlock`` invariant when the witness shows the circular-wait/stagnation
state).

Pure stdlib, Python 3.6 compatible.
"""

from .ir import Expr
from .verdicts import Verdict, POLICY_DENIAL, LIVENESS_BOUND_EXCEEDED


def _feasible_in_ir(witness, prop):
    """``(ok, value)``: is ``witness`` a concrete state where ``prop`` is False?

    A real violation is a *definite* False under the IR's three-valued
    evaluation. ``UNDEF`` (an unmodelled / environment atom) is conservatively
    treated as "not confirmed".
    """
    if not isinstance(witness, dict) or not witness:
        return False, None
    try:
        r = prop.expression.eval(witness)
    except Exception:
        return False, None
    if r is Expr.UNDEF:
        return False, r
    return (r is False), r


def cegar(engine_result, prop, cfg, engine, model=None, recheck=None):
    """Map an ``EngineResult`` to a :class:`Verdict`, refining if needed.

    Parameters
    ----------
    engine_result : rot.symbolic.EngineResult
        Outcome of one engine run (symbolic or TLC).
    prop : rot.invariants.Invariant
        The pinned invariant (``.name`` + ``.expression``).
    cfg : rot.config.Config
        Runtime config; ``cfg.cegar_max_iter`` caps the refinement loop.
    engine : str
        Resolved engine name (``"symbolic"`` / ``"tlc"``), recorded on the verdict.
    model : rot.linearization.LinearModel, optional
        Needed only if the ``recheck`` hook re-runs the engine.
    recheck : callable(model, prop, max_states) -> EngineResult, optional
        Refinement hook. Called on ``unknown`` up to ``cfg.cegar_max_iter``
        times to try to converge. Omit for a single-shot check.
    """
    status = engine_result.status
    # The violation code a VIOLATED verdict carries: the invariant's declared
    # code (e.g. ``DEADLOCK`` for ``no_deadlock``) if set, else the safety
    # default (``POLICY_DENIAL``).
    _code = getattr(prop, "violation_code", None) or POLICY_DENIAL

    if status == "proven":
        return Verdict.proven(prop.name, engine,
                              n_states=engine_result.n_states,
                              property_kind=prop.kind,
                              note=engine_result.note or "invariant holds")

    if status == "violated":
        witness = engine_result.witness
        if isinstance(witness, dict) and witness:
            feasible, _ = _feasible_in_ir(witness, prop)
            if feasible:
                return Verdict.violated(
                    prop.name, engine, counterexample=witness,
                    n_states=engine_result.n_states,
                    property_kind=prop.kind,
                    violation_code=_code,
                    note="concrete counterexample confirmed in the IR")
            return Verdict.unsound(
                prop.name, engine, counterexample=witness,
                n_states=engine_result.n_states,
                property_kind=prop.kind,
                note="counterexample not confirmed concrete in the IR "
                     "(over-approximation artefact)")
        # The engine is authoritative (it refuted the invariant) but we could
        # not capture/parse a concrete witness. Report a violation with that
        # caveat rather than silently downgrading to unknown.
        return Verdict.violated(
            prop.name, engine, counterexample={},
            n_states=engine_result.n_states,
            property_kind=prop.kind,
            violation_code=_code,
            note="engine reported a violation; witness not captured")

    if status in ("unknown", "timeout"):
        iters = 0
        cur = engine_result
        if recheck is not None and model is not None:
            for iters in range(1, int(cfg.cegar_max_iter) + 1):
                cur = recheck(model, prop, cfg.max_states)
                if cur.status in ("proven", "violated"):
                    break
        if cur.status == "violated":
            feasible, _ = _feasible_in_ir(cur.witness, prop)
            if feasible:
                return Verdict.violated(
                    prop.name, engine, counterexample=cur.witness,
                    cegar_iterations=iters,
                    property_kind=prop.kind,
                    violation_code=_code,
                    note="confirmed by refinement")
            return Verdict.unsound(
                prop.name, engine, counterexample=cur.witness,
                cegar_iterations=iters,
                property_kind=prop.kind,
                note="refined counterexample not confirmed concrete")
        if cur.status == "proven":
            return Verdict.proven(
                prop.name, engine, cegar_iterations=iters,
                property_kind=prop.kind,
                note="confirmed by refinement")
        return Verdict.unknown(
            prop.name, engine, cegar_iterations=iters,
            property_kind=prop.kind,
            note="could not decide after %d refinement(s): %s"
                 % (iters, engine_result.note))

    if status == "error":
        return Verdict.error(prop.name, engine,
                             property_kind=prop.kind,
                             note=engine_result.note or "engine error")

    raise ValueError("unknown engine status %r" % (status,))


def cegar_liveness(reach_result, prop, cfg, engine):
    """Map a bounded-liveness ``ReachResult`` to a :class:`Verdict`.

    Liveness invariants (``kind="liveness"``, e.g. ``bounded_eventually``)
    are the mirror image of the safety path handled by :func:`cegar`:
    instead of proving the *negation* of the predicate unreachable, the engine
    searches for the *goal* within a bounded horizon
    (``SymbolicEngine.reach_within``) and returns a ``ReachResult`` whose
    ``status`` is one of ``REACHED`` / ``NOT_REACHED`` / ``UNKNOWN``:

      * ``REACHED``     -> ``Verdict.proven``   (goal reachable: liveness holds)
      * ``NOT_REACHED`` -> ``Verdict.violated`` (goal unreachable: liveness fails)
      * ``UNKNOWN``     -> ``Verdict.unknown``  (budget cut short: undecidable)

    The horizon recorded on the verdict is ``cfg.liveness_horizon`` (the bound
    the search actually used), so the verdict always stays *relative to its
    bound* -- never an unconditional liveness claim.

    Parameters
    ----------
    reach_result : rot.symbolic.ReachResult
        Outcome of one ``SymbolicEngine.reach_within`` call.
    prop : rot.invariants.Invariant
        The pinned liveness invariant (``.name`` + ``.expression`` goal).
    cfg : rot.config.Config
        Runtime config; ``cfg.liveness_horizon`` is the recorded bound.
    engine : str
        Resolved engine name, recorded on the verdict.
    """
    from .symbolic import REACHED, NOT_REACHED, UNKNOWN

    horizon = int(getattr(cfg, "liveness_horizon", 12) or 12)
    status = reach_result.status
    n_states = int(getattr(reach_result, "n_states", 0) or 0)
    depth = getattr(reach_result, "depth", None)

    if status == REACHED:
        evidence = {"liveness": "reached", "horizon": horizon, "depth": depth}
        path = getattr(reach_result, "path", None)
        if path:
            evidence["path"] = path
        return Verdict.proven(
            prop.name, engine, n_states=n_states, evidence=evidence,
            property_kind=prop.kind,
            note=("goal reachable within horizon %d at step %s -- "
                  "bounded liveness holds" % (horizon, depth)))

    if status == NOT_REACHED:
        return Verdict.violated(
            prop.name, engine, counterexample={}, n_states=n_states,
            evidence={"liveness": "not_reached", "horizon": horizon},
            property_kind=prop.kind,
            violation_code=LIVENESS_BOUND_EXCEEDED,
            note=("goal not reachable within horizon %d -- "
                  "bounded liveness violated" % horizon))

    if status == UNKNOWN:
        return Verdict.unknown(
            prop.name, engine, n_states=n_states,
            evidence={"liveness": "unknown", "horizon": horizon},
            property_kind=prop.kind,
            note=("reach_within could not decide within horizon %d "
                  "(state budget exhausted) -- this is NOT a proof of "
                  "non-reachability" % horizon))

    raise ValueError("unknown liveness status %r" % (status,))


# ---------------------------------------------------------------------------
# Code-to-TLA+ verification (spec §7, D3) -- discharge a lowered candidate.
# ---------------------------------------------------------------------------

def verify_candidate(ir, cfg, engine="symbolic"):
    """Discharge a lowered P1 candidate (spec §7, D3) into a :class:`Verdict`.

    This is the Verify-plane glue (E3): it takes the ``ProtocolIR`` that
    :func:`rot.lower.lower_candidate` materialized from the narrow-waist
    front-end's candidate and runs it through the *existing* safety pipeline
    (``linearize`` -> ``Invariant`` -> ``SymbolicEngine.check`` ->
    :func:`cegar`), so a P1 claim is discharged exactly like any other pinned
    property:

    * **PROVEN**    -- the extracted control holds (the code is safe for this
      control), and the verdict evidence states it is *candidate* (E1) and
      *per-instance* (E4).
    * **VIOLATED**  -- the bypass is reachable; the verdict carries the exact
      witness (the bypass), not a prose description.
    * **UNKNOWN**   -- the state budget was exhausted: an honest "not
      decided", never a proof of either direction (E3).

    If the candidate was ``out_of_scope`` (E2), the verdict is
    :func:`Verdict.out_of_scope` -- the engine never runs.

    Args:
        ir: a :class:`rot.ir.ProtocolIR` produced by
            :func:`rot.lower.lower_candidate` (carries the candidate scope in
            its metadata).
        cfg: a :class:`rot.config.Config` (state budget, etc.).
        engine: the engine tag recorded on the verdict (default ``"symbolic"``).

    Returns:
        rot.verdicts.Verdict: PROVEN / VIOLATED (+ witness) / UNKNOWN /
        OUT_OF_SCOPE.
    """
    from .linearization import linearize
    from .invariants import Invariant
    from .symbolic import SymbolicEngine
    from .verdicts import Verdict, KIND_SAFETY, OUT_OF_SCOPE

    meta = dict(getattr(ir, "metadata", {}) or {})

    # E2: an out-of-scope candidate never runs the engine.
    if meta.get("out_of_scope"):
        return Verdict.out_of_scope(
            ir.name or "control", engine,
            reason=meta.get("out_of_scope_reason")
            or "outside the declared pattern class (P1)")

    pattern = meta.get("pattern") or "control"
    prop = Invariant(
        name=ir.name or pattern,
        description=("Extracted P1 %s control -- a *candidate* the code "
                     "enforces, not intent (E1/E4)." % pattern),
        expression=ir.pinned_property,
        kind=KIND_SAFETY,
    )
    linear_model = linearize(ir)
    eng = SymbolicEngine(linear_model, max_states=cfg.max_states)
    engine_result = eng.check(prop.expression, cfg.max_states)
    verdict = cegar(engine_result, prop, cfg, engine)

    # Stamp the candidate scope (E1 / E4 / E5) onto the verdict evidence so
    # the claim is never read as an unconditional statement about the codebase.
    evidence = dict(verdict.evidence)
    evidence["candidate"] = bool(meta.get("candidate", True))
    evidence["pattern_class"] = meta.get("pattern_class", "P1")
    evidence["pattern"] = pattern
    evidence["enforced"] = meta.get("enforced")
    evidence["provenance"] = meta.get("provenance", {})
    evidence["agent_replacement"] = (
        "the agent stands in for the extracted control; the claim is scoped "
        "to the extracted shape + instantiation bounds, not the whole system")
    evidence["scope"] = ("per-instance (E4): this verdict is scoped to the "
                         "extracted control and its instantiation bounds")
    verdict.evidence = evidence
    return verdict


__all__ = ["cegar", "cegar_liveness", "_feasible_in_ir", "verify_candidate"]
