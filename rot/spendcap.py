# -*- coding: utf-8 -*-
"""spendcap.py -- a spend-cap policy under a parallel fire race (AWS Dogwood).

A single service approves a spend request (``spend_ok``) and *later* settles
it (``respond``) -- the response is asynchronous, so several approved-but-
unsettled (in-flight) requests can coexist.  The policy must charge in-flight
requests against the cap: the settled amount plus the in-flight amount may
never exceed the cap.

The two variants share the same state, the same actions, and the same pinned
property; they differ only in the decision rule -- ``spend_ok``'s guard
admits on it and ``spend_deny``'s guard is its negation.  Both guards are
derived from the policy text under the named evaluation semantics recorded in
:data:`SEMANTICS` (closed/reflexive window; whether the CURRENT request is
charged is decided by the aggregate's EVENT KIND, not the window boundary):

  * correct -- the policy sums over ``::request`` events, and the window is
    reflexive (the current event included), so the current request IS in the
    sum: ``completed + inflight * AMOUNT + AMOUNT <= CAP`` -- the trailing
    ``+ AMOUNT`` is the current request, and the request is admitted only if
    settled + in-flight + this request all fit within the cap;
  * buggy   -- the policy sums over ``::response`` events, and the current
    event is a request, never a response, so the current request is NOT in
    the sum (by event kind, under reflexive or non-reflexive semantics):
    ``completed <= CAP`` -- the guard charges settled amount only.  The bug
    is *off-by-one sequentially* (a request admitted at ``completed = CAP``
    settles past the cap) and *unbounded under concurrency* (a burst of
    parallel ``spend_ok`` fires each sees low ``completed`` and is admitted
    regardless of how much is already in flight) -- the invariant is
    VIOLATED at every ``K``, not "masked at K=1".

Note on the ``formerly`` window (see :data:`SEMANTICS`): the Dogwood window
is *closed/reflexive* -- ``formerly within W body`` holds iff ``body`` holds
at some position in the window, the current event included.  So the window
boundary does not decide whether the current request is charged: a sum over
``::request`` events includes it, a sum over ``::response`` events excludes
it.  That event-kind difference -- not the window -- separates the two
guards above.

Both variants keep the same structural client-side bound
``inflight < K`` in the ``spend_ok`` guard (``K`` defaults to
``MAX_INFLIGHT``): that is a resource limit of the request pool, present in
both variants -- not the policy decision.  It also keeps the concrete state
space finite, since the concrete engines do not enforce variable domains.
``K`` is fully parameterized end-to-end (IR -> CLI -> tests -> report): it
bounds how many concurrent in-flight requests the state space can *express*,
so the parallel-fire race is itself a function of ``K``:

* ``K = 1``  -- the invariant is VIOLATED by the *sequential* off-by-one
  (witness ``completed = 200, inflight = 1``: a request admitted at
  ``completed = CAP`` settles past the cap); two in-flight requests cannot
  coexist, so the parallel-fire signature is not expressible;
* ``K = 2``  -- the invariant is VIOLATED with the *parallel-fire* witness
  (``completed = 100, inflight = 2``);
* ``K >= 3`` -- the clean 3-parallel-fire signature is reachable
  (witness ``completed = 0, inflight = 3``).

State (single service; all variables owned by "service"):
    completed -- settled amount (sum of responded requests)
    inflight  -- approved-but-unsettled (in-flight) request count

Actions:
    init      : completed = 0, inflight = 0
    spend_ok  : the policy decision (the guard is the seeded difference);
                effect: inflight := inflight + 1
    spend_deny: the other branch of the same decision (guard: NOT(decision));
                effect: none -- a no-op outcome action, so the concrete
                engines generate no transition for it; it makes the
                decision plane explicit in the IR
    respond   : settle one in-flight request (guard: inflight >= 1);
                effects: inflight := inflight - 1,
                         completed := completed + AMOUNT

Pinned property: ``completed + inflight * AMOUNT <= CAP`` (registered in
:mod:`rot.invariants` as ``spendcap_within_cap``).

Pure stdlib, Python 3.6 compatible.
"""

import rot.ir as ir

#: The Dogwood evaluation semantics this model assumes (guide §temporal +
#: formal spec §6):
#:   * the window is closed/reflexive -- ``formerly within W body`` holds iff
#:     ``body`` holds at some position j in [0, i] (the current event
#:     included);
#:   * every event is observed before it is decided;
#:   * whether the CURRENT request is charged is decided by the aggregate's
#:     EVENT KIND, not the window boundary:
#:       - sum over ::request  -> current request IS in the sum  -> charge it
#:       - sum over ::response -> current request is NOT in sum  -> charge
#:         settled only
SEMANTICS = "dogwood-reflexive@2a66026"

__all__ = [
    "SEMANTICS",
    "AMOUNT",
    "CAP",
    "MAX_INFLIGHT",
    "MAX_WINDOW",
    "build_ir",
    "spend_ok_guard_buggy",
    "spend_ok_guard_correct",
    "within_cap_property",
    "assume_inflight_at_most",
    "k_sweep",
]

#: Uniform spend amount per request (the fixture reduces all amounts to one
#: uniform value so the state space stays tiny and exhaustively provable).
AMOUNT = 100
#: The service's spend cap (the policy limit).
CAP = 200
#: Default client-side structural bound: at most this many concurrent
#: (in-flight) requests (``K``).  A resource limit shared by both variants --
#: not the policy.  Overridable per run via :func:`build_ir`
#: (``max_inflight=K``) / the CLI (``--max-inflight K``).
#:
#: GUARDRAIL: keep the default >= 2.  K is the concurrency-pool bound, and
#: the witness shape tracks K: K = 1 gives the sequential off-by-one
#: (``completed = 200, inflight = 1``), K >= 2 the parallel-fire signature
#: (``completed = 100, inflight = 2`` at K = 2; ``completed = 0,
#: inflight = 3`` at K >= 3).  The default (4) expresses the parallel-fire
#: signature.  K = 1 stays a valid *explicit* override (the K-sweep uses it
#: to show the sequential off-by-one), never the default.
MAX_INFLIGHT = 4


#: Default temporal-window bound (``W``).  Dogwood's ``formerly within
#: <window>`` is a *time* bound (e.g. ``24h``) that finite model checking
#: cannot represent -- the model is time-free, so the window is approximated
#: as a *bounded event count*: "at most ``W`` events are live inside the
#: window".  A modeling parameter (like :data:`MAX_INFLIGHT`), recorded in the
#: IR metadata (``window``) and surfaced in the verdict's
#: ``abstraction_manifest`` so reports state the discretization a verdict was
#: produced under.  The original time token (e.g. ``"24h"``) is preserved
#: verbatim as the ``dw_window`` provenance tag.  Overridable per run via
#: :func:`build_ir` (``window=W``) / the CLI (``--window W``).
MAX_WINDOW = 4


def spend_ok_guard_buggy(amount=AMOUNT, cap=CAP):
    """Decision rule (buggy): charge settled responses only.

    Derived under :data:`SEMANTICS`: the policy's aggregate is a sum over
    ``::response`` events, and the current event is a *request*, never a
    response -- so the current request is NOT in the sum (by event kind, not
    by the window boundary).  The guard therefore charges the settled amount
    only: ``completed <= cap``.  No ``+ amount`` term: the response-sum
    excludes the current request, so it is not charged.

    That guard is *off-by-one sequentially* (it admits a request at
    ``completed = cap``; once it settles, ``completed + AMOUNT > cap``) and
    *unbounded under concurrency* (a parallel burst of ``spend_ok`` fires
    each sees low ``completed`` and is admitted regardless of how much is
    already in flight) -- the invariant is VIOLATED at every ``K``.

    ``amount`` / ``cap`` are the policy's per-request amount and cap; they
    default to the module constants so the hand-written model is unchanged.
    (``amount`` no longer appears in the guard -- see the derivation above.)
    """
    return ir.BinOp("<=", ir.V("completed"), ir.C(cap))


def spend_ok_guard_correct(amount=AMOUNT, cap=CAP):
    """Decision rule (correct): charge in-flight requests against the cap.

    ``completed + inflight * amount + amount <= cap`` -- settled amount, plus
    the amount already in flight, plus the current request, must all fit
    within the cap.

    Derived under :data:`SEMANTICS`: the policy's aggregate is a sum over
    ``::request`` events and the window is closed/reflexive (the current
    event included), so the CURRENT request IS in the sum -- the explicit
    ``+ amount`` charges it (because it is in the request-sum, not because
    the window is past-only).
    """
    return ir.BinOp("<=",
                    ir.BinOp("+",
                             ir.BinOp("+",
                                      ir.V("completed"),
                                      ir.BinOp("*", ir.V("inflight"), ir.C(amount))),
                             ir.C(amount)),
                    ir.C(cap))


def within_cap_property(amount=AMOUNT, cap=CAP):
    """The pinned safety property: settled + in-flight never exceeds the cap.

    ``completed + inflight * amount <= cap`` -- in every reachable state, the
    committed (settled) amount plus the in-flight amount stays within the
    cap.  This is the parallel-fire guarantee: admitted-but-unsettled
    requests count against the cap *before* their responses settle.
    """
    return ir.BinOp("<=",
                    ir.BinOp("+",
                             ir.V("completed"),
                             ir.BinOp("*", ir.V("inflight"), ir.C(amount))),
                    ir.C(cap))


def build_ir(n=1, buggy=False, max_inflight=MAX_INFLIGHT, amount=AMOUNT, cap=CAP,
             window=MAX_WINDOW, assumes=None):
    """Build the spendcap IR.

    ``n`` is accepted for registry uniformity (this slice is a single
    service).  ``buggy`` selects the decision rule of the ``spend_ok``
    action; everything else (state, actions, property) is shared.

    ``max_inflight`` (``K``) is the client-side request-pool bound: the
    maximum number of concurrent in-flight requests the state space can
    express (``inflight <= K``).  It is a *structural* parameter shared by
    both variants -- not the policy decision -- and it is recorded in the IR
    metadata (``max_inflight``) so the CLI, tests, and reports all agree on
    the ``K`` a verdict was produced under.  Because the state space cannot
    express more than ``K`` in-flight requests, the *witness shape* is itself
    a function of ``K`` (see the module docstring): the buggy policy is
    VIOLATED at every ``K`` -- ``K = 1`` by the sequential off-by-one
    (``completed = 200, inflight = 1``), ``K = 2`` with the parallel-fire
    witness (``completed = 100, inflight = 2``), ``K >= 3`` with the clean
    3-parallel-fire signature (``completed = 0, inflight = 3``).

    ``amount`` and ``cap`` are the policy's per-request settlement amount and
    spend cap; they default to the module constants (:data:`AMOUNT` /
    :data:`CAP`) so the hand-written model is unchanged, but a policy front-end
    can thread the policy's own values through so the model is *derived from
    the policy* rather than fixed to one example.

    ``assumes`` (Phase 6.2) is an optional list of state constraints
    (TLA+ ``ASSUME`` clauses) -- :class:`rot.ir.Assume` nodes or raw
    expressions.  They restrict the state space the engines explore
    (sound pruning: a promise about the environment or a modelling
    parameter, like a bound) and are recorded on the IR, so a verdict
    decided under them carries them as NAMED assumptions -- never silent.
    See :func:`assume_inflight_at_most` and :func:`k_sweep`.

    Raises:
        ValueError: if ``max_inflight`` is not an integer >= 1.
    """
    k = int(max_inflight)
    if k < 1:
        raise ValueError(
            "max_inflight (K) must be an integer >= 1 (got %r)"
            % (max_inflight,))
    w = int(window)
    if w < 1:
        raise ValueError(
            "window (W) must be an integer >= 1 (got %r)"
            % (window,))
    if buggy:
        name = "spendcap-buggy"
        decision = spend_ok_guard_buggy(amount, cap)
    else:
        name = "spendcap-correct"
        decision = spend_ok_guard_correct(amount, cap)
    # The structural client-side bound (request-pool resource limit) is
    # shared by both variants; it is not the policy decision.  It also keeps
    # the concrete state space finite, since the concrete engines do not
    # enforce variable domains.
    spend_ok_guard = ir.And(decision,
                            ir.BinOp("<", ir.V("inflight"), ir.C(k)))
    # spend_deny is the other branch of the same policy decision: enabled
    # exactly where the seeded rule rejects the request.  It carries no
    # effect (a no-op outcome action), so the concrete engines generate no
    # transition for it -- it makes the decision plane explicit in the IR.
    spend_deny_guard = ir.Not(decision)

    variables = [
        ir.StateVar("completed", ir.IntRange(0, cap), ir.MODE_PRECISE, "service",
                    "settled amount (sum of responded requests)"),
        ir.StateVar("inflight", ir.IntRange(0, k), ir.MODE_PRECISE,
                    "service", "approved-but-unsettled (in-flight) request count"),
    ]
    actions = [
        ir.Action(name="init", owner="service", guard=ir.T(),
                  effects=[ir.Assignment("completed", ir.C(0)),
                           ir.Assignment("inflight", ir.C(0))],
                  is_initial=True,
                  source="spendcap.py:init"),
        ir.Action(name="spend_ok", owner="service", guard=spend_ok_guard,
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("+", ir.V("inflight"), ir.C(1)))],
                  linearization="send(spend_ok)",
                  source="spendcap.py:spend_ok"),
        ir.Action(name="spend_deny", owner="service", guard=spend_deny_guard,
                  effects=[],
                  source="spendcap.py:spend_deny"),
        ir.Action(name="respond", owner="service",
                  guard=ir.BinOp(">=", ir.V("inflight"), ir.C(1)),
                  effects=[ir.Assignment("inflight",
                                         ir.BinOp("-", ir.V("inflight"), ir.C(1))),
                           ir.Assignment("completed",
                                         ir.BinOp("+", ir.V("completed"), ir.C(amount)))],
                  linearization="send(respond)",
                  source="spendcap.py:respond"),
    ]
    # Phase 6.2: state constraints (TLA+ ASSUME clauses) -- normalized to
    # :class:`rot.ir.Assume` nodes and carried on the IR so every consumer
    # (engines, reports) sees the exact state space a verdict was decided in.
    assumes = [a if isinstance(a, ir.Assume) else ir.Assume(a)
               for a in (assumes or [])]
    return ir.ProtocolIR(
        name=name,
        variables=variables,
        channels=[],
        actions=actions,
        init=ir.T(),
        # The pinned property the soundness core must check: the settled
        # amount plus the in-flight amount never exceeds the cap (the
        # parallel-fire guarantee).  Setting it here -- the single source of
        # truth for the model -- lets every consumer (the ``.dw`` front-end,
        # the ``--policy`` path, ...) verify against the real cap predicate
        # instead of the ``ProtocolIR`` default of ``Const(True)``.
        pinned_property=within_cap_property(amount, cap),
        assumes=assumes,
        source_path="tests/fixtures/aws_dogwood/spendcap",
        metadata={"protocol": "SPENDCAP", "target": "spendcap",
                  "buggy": buggy, "amount": amount, "cap": cap,
                  "max_inflight": k, "window": w,
                  # Phase 0 IR contract: the oracle's source is the hand-
                  # authored module that builds it (source-pinned provenance).
                  "provenance": {
                      "module": "rot/spendcap.py",
                      "function": "build_ir",
                      "pin": "hand-authored oracle (AWS Dogwood spend-cap spec)"},
                  "lossiness": [
                      ir.lossiness_entry(
                          "the `formerly` window's time bound approximated "
                          "as an event count (the window is closed/reflexive "
                          "-- the current event is included)",
                          "captured by the settled/in-flight split "
                          "(completed + inflight * AMOUNT); the window bound "
                          "W is recorded in metadata"),
                      ir.lossiness_entry(
                          "unbounded in-flight concurrency",
                          "bounded by max_inflight (K) to keep the concrete "
                          "state space finite; K >= 2 still expresses the "
                          "parallel-fire race"),
                  ]},
    )


def assume_inflight_at_most(k, note=None):
    """Phase 6.2: the in-flight bound as an ASSUME clause.

    ``assume(inflight <= k)`` -- a state constraint restricting the state
    space to at most ``k`` in-flight requests.  This is the concurrency-pool
    bound behind the K-scale: the buggy policy is VIOLATED at every ``k``,
    but the *witness shape* tracks ``k`` (``k = 1`` -- sequential off-by-one;
    ``k >= 2`` -- parallel-fire).  A PROVEN for any cap/budget policy at a
    ``k`` below the minimal overshoot would still not rule the parallel-fire
    race out -- the assumption is recorded on the IR (and hence on the
    verdict as a named assumption) so the bound a verdict was decided under
    is never silent.

    Returns a :class:`rot.ir.Assume` node (usable as an IR ``assumes``
    entry or in :func:`build_ir`).
    """
    k = int(k)
    if k < 1:
        raise ValueError("the in-flight bound must be >= 1 (got %r)" % (k,))
    expr = ir.BinOp("<=", ir.V("inflight"), ir.C(k))
    if note is None:
        note = ("concurrency assumption: at most %d in-flight request(s); "
                "the witness shape tracks k (k=1 sequential off-by-one, "
                "k>=2 parallel-fire)" % k)
    return ir.Assume(expr, note)


def k_sweep(buggy=True, k_values=(1, 2, 3, 4), amount=AMOUNT, cap=CAP,
            window=MAX_WINDOW, max_states=200000):
    """Phase 6.4: the K-scale sweep.

    Runs the pinned safety property (``spendcap_within_cap``) under a sweep
    of the concurrency-pool bound ``K`` (``max_inflight``) and returns one
    verdict per ``K``.  The buggy policy is VIOLATED at every ``K``; what
    tracks ``K`` is the *witness shape* (``K = 1`` -- sequential off-by-one;
    ``K >= 2`` -- parallel-fire), which is *reported*, not assumed.

    Each row is ``(K, verdict)`` where ``verdict`` is a
    :class:`rot.verdicts.Verdict` decided by the concrete symbolic engine
    (the independent oracle) with the bounded re-check.  The verdict records
    the bound in ``evidence["k"]`` and the ``MASKED_AT_LOW_K`` advisory in
    ``evidence["k_masking"]`` when one applies (a PROVEN at a ``K`` below
    the minimal overshoot count), and carries the bound as a NAMED
    assumption -- never silent.

    Returns a list; pure stdlib, Python 3.6 compatible.
    """
    from .cegar import cegar
    from .config import Config
    from .invariants import Invariant
    from .linearization import linearize
    from .symbolic import SymbolicEngine
    from .verdicts import k_masking_advisory

    prop = Invariant(
        name="spendcap_within_cap",
        description="settled + in-flight never exceeds the cap",
        expression=within_cap_property(amount, cap))
    cfg = Config(engine="symbolic", max_states=max_states)
    out = []
    for k in k_values:
        ir = build_ir(buggy=buggy, max_inflight=k, amount=amount,
                      cap=cap, window=window)
        model = linearize(ir)
        eng = SymbolicEngine(model, max_states=cfg.max_states)
        res = eng.check(prop.expression)

        def _recheck(mdl, p, ms, _eng=eng):
            return _eng.check(p.expression)

        v = cegar(res, prop, cfg, "symbolic", model=model,
                  recheck=_recheck)
        v.evidence = dict(v.evidence or {})
        v.evidence["k"] = k
        code, msg = k_masking_advisory(ir.metadata, v.status)
        if code:
            v.evidence["k_masking"] = {"code": code, "message": msg}
        v.assumptions = list(v.assumptions or [])
        v.assumptions.append(
            "assume: inflight < %d (concurrency-pool bound K=%d; the "
            "witness shape tracks K: K=1 sequential off-by-one, K>=2 "
            "parallel-fire)" % (k, k))
        out.append((k, v))
    return out