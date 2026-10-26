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
``prop.kind``) and each VIOLATED verdict carries a ``violation_code`` --
``POLICY_DENIAL`` on the safety path, ``LIVENESS_BOUND_EXCEEDED`` on the
liveness path (``DEADLOCK`` is left for the caller to assign when the witness
shows stagnation).

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
                    violation_code=POLICY_DENIAL,
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
            violation_code=POLICY_DENIAL,
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
                    violation_code=POLICY_DENIAL,
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


__all__ = ["cegar", "cegar_liveness", "_feasible_in_ir"]
