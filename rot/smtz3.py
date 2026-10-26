# -*- coding: utf-8 -*-
"""smtz3.py -- dual-backend SMT verification engine (Z3 + pure-Python).

This is the only engine module in the repo.  It verifies IR predicates
over the linearised protocol IR (``rot.ir.ProtocolIR``) using two
independent backends and cross-checks their answers:

  * ``Z3Backend`` -- a bounded model checker that translates the IR
    transition system into Z3 (Int/Bool arithmetic) and queries a real
    SMT solver.  Bounded by a step horizon H (default 32); ``sat`` and
    ``unsat`` are the only trusted answers, a solver ``unknown`` or a
    timeout is *inconclusive* (never a verdict).
  * ``PurePythonBackend`` -- the reference concrete-state engine
    (``rot.modelfind``): exhaustive BFS reachability with exact symbolic
    evaluation.  It is the *canonical* backend: counterexamples,
    liveness witnesses, and counterexample traces all come from it.

Agreement policy: the two backends must agree on the *status* of the
query (safety: proven<->unsat, violated<->sat; liveness:
proven<->sat, violated<->unsat).  Any disagreement -- or an
unavailable/inconclusive Z3 backend -- yields an ``unknown`` verdict
that records both engines' answers, rather than a false PROVEN or a
false VIOLATED.

The API is deliberately small (two methods, both returning
``rot.verdicts.Verdict``):

  SMTBackend(ir)
      .verify_safety(prop, bound=None)   -> Verdict
      .verify_liveness(prop, bound=1000) -> Verdict

``prop`` is a ``rot.invariants.Invariant`` (``expression`` is the IR
predicate; ``kind`` is ``safety`` or ``liveness``).

Z3 is an *optional dependency*: if ``import z3`` fails (or the IR cannot
be encoded -- e.g. unsupported domains or free variables), the facade
degrades gracefully to the pure-Python backend and records the fallback
in the verdict evidence.
"""

from rot import ir
from rot.ir import Expr
from rot import modelfind
from rot import verdicts as v
from rot.expr_render import render_expr

ENGINE = "smtz3"

# Z3Backend answer vocabulary (engine-internal):
SAT = "sat"                      # queried bad/good state reachable <= H steps
UNSAT = "unsat"                  # queried state not reachable <= H steps
INCONCLUSIVE = "inconclusive"    # z3 unavailable / IR not encodable / timeout


class _Inconclusive(Exception):
    """Raised internally when an IR node cannot be encoded to Z3."""
    pass


def _subst(e, name, value):
    """Replace free occurrences of ``Var(name)`` in ``e`` by ``Const(value)``."""
    if isinstance(e, ir.Const):
        return e
    if isinstance(e, ir.Var):
        return ir.Const(value) if e.name == name else e
    if isinstance(e, ir.UnOp):
        return ir.UnOp(e.op, _subst(e.child, name, value))
    if isinstance(e, ir.BinOp):
        return ir.BinOp(e.op, _subst(e.left, name, value),
                        _subst(e.right, name, value))
    if isinstance(e, ir.If):
        return ir.If(_subst(e.cond, name, value),
                     _subst(e.then, name, value),
                     _subst(e.els, name, value))
    if isinstance(e, ir.AllOf):
        return ir.AllOf(e.var, _subst(e.coll, name, value),
                        _subst(e.body, name, value))
    if isinstance(e, ir.AnyOf):
        return ir.AnyOf(e.var, _subst(e.coll, name, value),
                        _subst(e.body, name, value))
    return e

class PurePythonBackend(object):
    """The canonical concrete-state backend (``rot.modelfind`` BFS).

    Soundness: it enumerates the concrete reachable state space and
    evaluates IR expressions exactly (undefined expression values are
    treated conservatively, never as "holds").  Counterexamples,
    witnesses, and traces produced here are the ground truth used by
    the ``SMTBackend`` facade.
    """

    def __init__(self, ir, max_states=200000):
        self.ir = ir
        self.mf = modelfind.ModelFinder.from_ir(ir, max_states=max_states)

    # -- safety -------------------------------------------------------------
    def verify_safety(self, prop):
        """Return a Verdict for ``prop`` (safety: predicate must always hold)."""
        expr = prop.expression
        predicate = lambda s: expr.eval(s)
        flag, counterexample = self.mf.forall_reachable(predicate)
        if flag is True:
            n = len(self.mf.reachable_states())
            return v.Verdict(
                status=v.PROVEN, property_name=prop.name, engine=ENGINE,
                assumptions=[
                    "all reachable states enumerated (%d) and predicate holds"
                    % n,
                ],
                soundness=[
                    "sound if every action's effects and guards are total; "
                    "the concrete evaluator returns UNDEF for undefined "
                    "expressions, which is treated conservatively",
                ],
                property_kind="safety")
        if flag is False:
            trace = self._trace(counterexample, prop)
            return v.Verdict(
                status=v.VIOLATED, property_name=prop.name, engine=ENGINE,
                counterexample=counterexample,
                evidence={"engine": ENGINE,
                          "model": "concrete-state BFS (rot.modelfind)"},
                violation_code=v.POLICY_DENIAL,
                trace=trace,
                property_kind="safety")
        # flag is UNKNOWN: the reachable-state enumeration hit its budget.
        return v.Verdict(
            status=v.UNKNOWN, property_name=prop.name, engine=ENGINE,
            assumptions=["bounded enumeration exceeded its state budget"],
            property_kind="safety")

    # -- liveness -------------------------------------------------------------
    def verify_liveness(self, prop, bound=1000):
        """Return a Verdict for ``prop`` (liveness: predicate must be reachable)."""
        expr = prop.expression
        predicate = lambda s: expr.eval(s)
        flag, witness = self.mf.exists_reachable(predicate, max_states=bound)
        if flag == modelfind.SAT:
            trace = self._trace(witness, prop)
            return v.Verdict(
                status=v.PROVEN, property_name=prop.name, engine=ENGINE,
                evidence={"engine": ENGINE,
                          "witness": witness,
                          "model": "concrete-state BFS (rot.modelfind)",
                          "bound": bound},
                trace=trace,
                property_kind="liveness")
        if flag == modelfind.UNSAT:
            return v.Verdict(
                status=v.VIOLATED, property_name=prop.name, engine=ENGINE,
                evidence={"bound": bound},
                violation_code=v.LIVENESS_BOUND_EXCEEDED,
                property_kind="liveness")
        # flag is UNKNOWN: the reachable-state enumeration hit its budget.
        return v.Verdict(
            status=v.UNKNOWN, property_name=prop.name, engine=ENGINE,
            evidence={"bound": bound},
            assumptions=["bounded enumeration exceeded its state budget"],
            property_kind="liveness")

    # -- counterexample trace --------------------------------------------------
    def _trace(self, target_state, prop):
        """Deterministic (state, action, guard, policy_clause, delta) trace.

        ``path_to`` returns the canonical BFS steps as
        ``(state_before, action, delta)`` triples; we keep the action's
        name, render its guard as a readable string, and attach the
        invariant's policy clause as the step's rationale.
        """
        path = self.mf.path_to(target_state)
        clause = getattr(prop, "policy_clause", None) or ""
        steps = []
        for state_before, action, delta in path:
            steps.append((dict(state_before),
                          action.name,
                          render_expr(action.guard),
                          clause,
                          dict(delta)))
        return steps


class Z3Backend(object):
    """Bounded model checker over Z3 (independent of ``rot.modelfind``).

    Translates the IR transition system into Z3 and unrolls it for a
    fixed step horizon ``H``.  State variables are declared *unbounded*
    (no IntRange/Enum domain constraints are added) so the Z3 search
    space is at least as large as the concrete engine's -- an
    over-approximation, which is what makes the cross-check useful for
    catching spurious PROVEN verdicts.

    Result vocabulary (module-level ``SAT``/``UNSAT``/``INCONCLUSIVE``):
      SAT          -- the queried state is reachable within H steps
      UNSAT        -- the queried state is not reachable within H steps
      INCONCLUSIVE -- z3 unavailable, IR not encodable, or the solver
                      timed out / returned unknown (never a verdict)
    """

    def __init__(self, ir, horizon=32, timeout_ms=10000):
        import z3  # raises ImportError if z3 is not installed
        self.z3 = z3
        self.ir = ir
        self.horizon = max(1, int(horizon))
        self.timeout_ms = int(timeout_ms)
        # decide the sort of every state variable up front
        self.sorts = {}
        for sv in ir.variables:
            self.sorts[sv.name] = self._sort_for(sv.domain)

    def _sort_for(self, domain):
        z3 = self.z3
        if isinstance(domain, ir.IntRange):
            return z3.IntSort()
        if isinstance(domain, ir.Bool):
            return z3.BoolSort()
        raise _Inconclusive("unsupported domain %r" % (domain,))

    # -- IR -> z3 translation -------------------------------------------------
    def _z3expr(self, e, varmap):
        """Translate an IR expression over state vars (``varmap``) to a z3 expr."""
        z3 = self.z3
        if isinstance(e, ir.Const):
            val = e.value
            if isinstance(val, bool):
                return z3.BoolVal(val)
            if isinstance(val, int):
                return z3.IntVal(val)
            if isinstance(val, str):
                return z3.StringVal(val)
            raise _Inconclusive("unsupported constant %r" % (val,))
        if isinstance(e, ir.Var):
            if e.name in varmap:
                return varmap[e.name]
            raise _Inconclusive("free variable %r" % (e.name,))
        if isinstance(e, ir.UnOp):
            if e.op == "not":
                return z3.Not(self._z3expr(e.child, varmap))
            return -self._z3expr(e.child, varmap)
        if isinstance(e, ir.BinOp):
            if e.op == "and":
                return z3.And(self._z3expr(e.left, varmap),
                              self._z3expr(e.right, varmap))
            if e.op == "or":
                return z3.Or(self._z3expr(e.left, varmap),
                             self._z3expr(e.right, varmap))
            if e.op == "in":
                r = e.right
                if not (isinstance(r, ir.Const) and
                        isinstance(r.value, (list, tuple))):
                    raise _Inconclusive("non-concrete 'in' collection")
                left = self._z3expr(e.left, varmap)
                return z3.In(left, [self._z3expr(ir.Const(x), varmap)
                                    for x in r.value])
            l = self._z3expr(e.left, varmap)
            r = self._z3expr(e.right, varmap)
            if e.op == "+":
                return l + r
            if e.op == "-":
                return l - r
            if e.op == "*":
                return l * r
            if e.op == "=":
                return l == r
            if e.op == "!=":
                return l != r
            if e.op == "<":
                return l < r
            if e.op == "<=":
                return l <= r
            if e.op == ">":
                return l > r
            if e.op == ">=":
                return l >= r
            raise _Inconclusive("unsupported op %r" % (e.op,))
        if isinstance(e, ir.If):
            return z3.If(self._z3expr(e.cond, varmap),
                         self._z3expr(e.then, varmap),
                         self._z3expr(e.els, varmap))
        if isinstance(e, (ir.AllOf, ir.AnyOf)):
            if not (isinstance(e.coll, ir.Const) and
                    isinstance(e.coll.value, (list, tuple))):
                raise _Inconclusive("non-concrete quantifier collection")
            parts = [self._z3expr(_subst(e.body, e.var, x), varmap)
                     for x in e.coll.value]
            if isinstance(e, ir.AllOf):
                return z3.And(*parts) if parts else z3.BoolVal(True)
            return z3.Or(*parts) if parts else z3.BoolVal(False)
        raise _Inconclusive("unsupported expression %s" % type(e).__name__)

    # -- transition unrolling -------------------------------------------------
    def _unroll(self, horizon):
        """Build the conjunction of unrolled transitions for ``horizon`` steps.

        Returns (constraints, states) where ``states[t]`` maps each state
        variable name to its z3 constant at step ``t`` (step 0 = initial).
        """
        z3 = self.z3
        pir = self.ir
        names = [sv.name for sv in pir.variables]
        if not names:
            raise _Inconclusive("no state variables")
        actions = [a for a in pir.actions
                   if not getattr(a, "is_initial", False)]
        inits = [a for a in pir.actions if getattr(a, "is_initial", False)]
        if not inits:
            raise _Inconclusive("no initial action")
        # concrete initial state (effects must be ground)
        init = {}
        for e in inits[0].effects:
            r = e.expr.eval({})
            if r is Expr.UNDEF:
                raise _Inconclusive("non-ground initial effect")
            if e.var not in self.sorts:
                raise _Inconclusive("initial var %r not a state var"
                                    % (e.var,))
            init[e.var] = r
        missing = [n for n in names if n not in init]
        if missing:
            raise _Inconclusive("initial state leaves %r unconstrained"
                                % (missing,))
        cons = []
        states = []
        s0 = dict((n, z3.Const("s0_%s" % n, self.sorts[n])) for n in names)
        cons.append(z3.And([s0[n] == self._z3expr(ir.Const(init[n]), {})
                            for n in names]))
        states.append(s0)
        for t in range(1, horizon + 1):
            st = dict((n, z3.Const("s%d_%s" % (t, n), self.sorts[n]))
                      for n in names)
            options = []
            for a in actions:
                clause = [self._z3expr(a.guard, states[-1])]
                assigns = {}
                for e in a.effects:
                    if e.var not in self.sorts:
                        raise _Inconclusive("effect var %r not a state var"
                                            % (e.var,))
                    assigns[e.var] = self._z3expr(e.expr, states[-1])
                for n in names:
                    clause.append(st[n] == assigns.get(n, states[-1][n]))
                options.append(z3.And(clause))
            if not options:
                break  # dead transition system; earlier states still valid
            cons.append(z3.Or(options))
            states.append(st)
        return cons, states

    # -- solving ---------------------------------------------------------------
    def _check(self, cons, states, predicate_expr, want):
        """Add ``want(predicate)`` over all unrolled states and solve.

        ``want`` is ``z3.Not`` for safety (bad state reachable?) and the
        identity for liveness (good state reachable?).  Returns
        (status, model_or_None).
        """
        z3 = self.z3
        solver = z3.Solver()
        for c in cons:
            solver.add(c)
        solver.add(z3.Or([want(self._z3expr(predicate_expr, st))
                          for st in states]))
        solver.set("timeout", self.timeout_ms)
        r = solver.check()
        if r == z3.unknown:
            return INCONCLUSIVE, None
        if r == z3.sat:
            return SAT, solver.model()
        return UNSAT, None

    # -- witness extraction -----------------------------------------------------
    def _witness(self, states, model, expr, want):
        """First unrolled state whose exact evaluation equals ``want``."""
        fallback = None
        for varmap in states:
            concrete = {}
            ok = True
            for n in varmap:
                val = model.eval(varmap[n], model_completion=True)
                sort = val.sort()
                if sort == self.z3.BoolSort():
                    concrete[n] = bool(val)
                elif sort == self.z3.IntSort():
                    concrete[n] = val.as_long()
                elif sort == self.z3.StringSort():
                    concrete[n] = val.as_string()
                else:
                    ok = False
                    break
            if not ok:
                continue
            fallback = concrete
            if expr.eval(concrete) is want:
                return concrete
        return fallback

    # -- queries -----------------------------------------------------------------
    def verify_safety(self, prop, bound=None):
        """(status, witness_or_None) for a safety predicate (bad state reachable?)."""
        try:
            cons, states = self._unroll(self.horizon)
            status, model = self._check(cons, states, prop.expression,
                                        lambda e: self.z3.Not(e))
            if status != SAT:
                return status, None
            return SAT, self._witness(states, model, prop.expression, False)
        except Exception:
            return INCONCLUSIVE, None

    def verify_liveness(self, prop, bound=None):
        """(status, witness_or_None) for a liveness predicate (good state reachable?)."""
        try:
            cons, states = self._unroll(self.horizon)
            status, model = self._check(cons, states, prop.expression,
                                        lambda e: e)
            if status != SAT:
                return status, None
            return SAT, self._witness(states, model, prop.expression, True)
        except Exception:
            return INCONCLUSIVE, None


class SMTBackend(object):
    """Dual-backend facade: Z3 + pure-Python, cross-checked.

    The pure-Python backend is canonical (its counterexamples, witnesses
    and traces are what appear in the Verdict).  Z3 is an independent
    cross-check: if the two backends disagree on the query status, the
    verdict is ``unknown`` with both answers recorded -- never a false
    PROVEN or a false VIOLATED.
    """

    def __init__(self, ir, max_states=200000, horizon=32, timeout_ms=10000):
        self.ir = ir
        self._pp = PurePythonBackend(ir, max_states=max_states)
        self._z3 = None
        self._z3_reason = "unavailable"
        try:
            self._z3 = Z3Backend(ir, horizon=horizon, timeout_ms=timeout_ms)
            self._z3_reason = None
        except ImportError:
            self._z3_reason = "z3 not installed"
        except Exception as exc:
            self._z3_reason = "%s: %s" % (type(exc).__name__, exc)

    def engines(self):
        """Names of the active backends (for reports / introspection)."""
        out = ["pure-python (canonical)"]
        if self._z3 is not None:
            out.append("z3 (cross-check)")
        return out

    # -- safety ---------------------------------------------------------------
    def verify_safety(self, prop, bound=None):
        """Cross-checked safety verdict for ``prop``.

        Agrees:  pure-python PROVEN  + z3 UNSAT  -> PROVEN
                 pure-python VIOLATED + z3 SAT   -> VIOLATED (with trace)
        Otherwise (disagreement / z3 down / inconclusive) -> UNKNOWN.
        """
        pp = self._pp.verify_safety(prop)
        if pp.status == v.UNKNOWN:
            return self._annotate(pp, "skipped: pure-python already unknown")
        if self._z3 is None:
            return self._z3_unavailable(prop, "safety", pp, self._z3_reason)
        z3_status, z3_witness = self._z3.verify_safety(prop, bound=bound)
        if z3_status == INCONCLUSIVE:
            return self._z3_unavailable(prop, "safety", pp,
                                        "inconclusive (z3 timeout or unknown)")
        agree = ((pp.status == v.PROVEN and z3_status == UNSAT) or
                 (pp.status == v.VIOLATED and z3_status == SAT))
        if agree:
            return self._annotate(pp, z3_status)
        return self._disagreement(prop, "safety", pp, z3_status, z3_witness)

    # -- liveness ---------------------------------------------------------------
    def verify_liveness(self, prop, bound=1000):
        """Cross-checked liveness verdict for ``prop`` (within ``bound``).

        Agrees:  pure-python PROVEN  + z3 SAT   -> PROVEN (witness + trace)
                 pure-python VIOLATED + z3 UNSAT -> VIOLATED (bound exceeded)
        Otherwise (disagreement / z3 down / inconclusive) -> UNKNOWN.
        """
        pp = self._pp.verify_liveness(prop, bound=bound)
        if pp.status == v.UNKNOWN:
            return self._annotate(pp, "skipped: pure-python already unknown")
        if self._z3 is None:
            return self._z3_unavailable(prop, "liveness", pp, self._z3_reason)
        z3_status, z3_witness = self._z3.verify_liveness(prop, bound=bound)
        if z3_status == INCONCLUSIVE:
            return self._z3_unavailable(prop, "liveness", pp,
                                        "inconclusive (z3 timeout or unknown)")
        agree = ((pp.status == v.PROVEN and z3_status == SAT) or
                 (pp.status == v.VIOLATED and z3_status == UNSAT))
        if agree:
            return self._annotate(pp, z3_status)
        return self._disagreement(prop, "liveness", pp, z3_status, z3_witness)

    # -- helpers ------------------------------------------------------------------
    def _annotate(self, verdict, note):
        """Return a copy of ``verdict`` with a z3 cross-check note in evidence."""
        ev = dict(verdict.evidence)
        ev["z3"] = note
        return v.Verdict(
            status=verdict.status, property_name=verdict.property_name,
            engine=ENGINE, counterexample=verdict.counterexample,
            assumptions=verdict.assumptions, soundness=verdict.soundness,
            evidence=ev, cegar_iterations=verdict.cegar_iterations,
            n_states=verdict.n_states, note=verdict.note,
            property_kind=verdict.property_kind,
            violation_code=verdict.violation_code, trace=verdict.trace)

    def _z3_unavailable(self, prop, kind, pp, reason):
        """Return an UNKNOWN verdict when the z3 cross-check is missing.

        Soundness: a PROVEN/VIOLATED verdict is only ever issued when BOTH
        backends (pure-python canonical + z3 cross-check) actually agree. If
        the z3 backend is unavailable or inconclusive, the pure-python answer
        alone is NOT trusted -- we return UNKNOWN and record the pure-python
        answer for auditability, so a single engine can never mint a verdict.
        """
        return v.Verdict(
            status=v.UNKNOWN, property_name=prop.name, engine=ENGINE,
            assumptions=[
                "dual-backend cross-check: z3 backend %s" % (reason,),
                "pure-python (canonical) says %s" % (pp.status,),
            ],
            soundness=[
                "no PROVEN/VIOLATED is issued unless BOTH backends agree; z3 "
                "was %s so the pure-python answer alone is not trusted"
                % (reason,),
            ],
            evidence={"pure_python": pp.status,
                      "z3": reason,
                      "pure_python_counterexample": pp.counterexample},
            property_kind=kind,
            note="z3 backend %s; pure-python said %s" % (reason, pp.status))

    def _disagreement(self, prop, kind, pp, z3_status, z3_witness):
        return v.Verdict(
            status=v.UNKNOWN, property_name=prop.name, engine=ENGINE,
            assumptions=[
                "dual-backend cross-check: the two backends disagree on %s"
                % (kind,),
                "pure-python (canonical) says %s" % (pp.status,),
                "z3 (bounded, H=%d) says %s" % (self._z3.horizon, z3_status,),
            ],
            soundness=[
                "no PROVEN/VIOLATED is issued on disagreement; a human must "
                "resolve which backend's bounded answer is the real one",
            ],
            evidence={"pure_python": pp.status,
                      "z3": z3_status,
                      "z3_witness": z3_witness,
                      "pure_python_counterexample": pp.counterexample},
            property_kind=kind,
            note="backends disagree: %s vs %s" % (pp.status, z3_status))


__all__ = [
    "ENGINE",
    "SAT", "UNSAT", "INCONCLUSIVE",
    "PurePythonBackend",
    "Z3Backend",
    "SMTBackend",
]

