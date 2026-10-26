# -*- coding: utf-8 -*-
"""pipeline.py -- end-to-end ROTN verification pipeline (2PC + ZAB; CLI).

Orchestrates the ROTN soundness core for the 2PC and ZAB targets:

    target -> IR -> property-directed abstraction -> linearization
           -> engine (symbolic | TLC) -> CEGAR -> Verdict -> report (json+md)

For 2PC, the IR can also be built directly from Java sources
(``--source JAVA_DIR``), with an optional CPG artifact (``--cpg`` or an
auto-discovered ``*.cpg.json``) consulted by the narrow-waist frontend
(``rot.frontends.java``) as evidence.

Engines
-------
* ``symbolic`` -- pure-Python bounded model checker (``rot.symbolic``).
  Always available; the independent oracle for cross-checking TLC.
* ``tlc``      -- the TLA+ model checker via the Toolbox jar (``rot.tlc``).
  Requires ``tla2tools.jar`` (set ``$TLA2TOOLS_JAR`` or pass ``--tlc-jar``).
* ``auto``     -- TLC when a jar is resolvable, else symbolic (the default).
* ``crosscheck`` -- three-engine: run SMT (Z3), TLC, *and* policy-direct and
  only issue PROVEN/VIOLATED when all three agree; disagreement or UNKNOWN ->
  UNKNOWN.  Opt-in; requires an Int/Bool-domain target and the TLC jar.

Exit codes
----------
* 0 -- proven
* 1 -- violated
* 2 -- unknown / unsound (could not decide; never silently "proven")
* 3 -- error (a tool failed to run, or the run could not start)

Pure stdlib, Python 3.6 compatible.
"""

import argparse
import json
import os
import sys

# Make ``rot`` importable whether run as ``python pipeline.py`` from the repo
# root or imported as a module from elsewhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

EXIT_PROVEN = 0
EXIT_VIOLATED = 1
EXIT_UNKNOWN = 2
EXIT_ERROR = 3

DEFAULT_MAX_STATES = 200000
DEFAULT_CEGAR_MAX_ITER = 6
DEFAULT_TLC_TIMEOUT = 120
DEFAULT_APALACHE_TIMEOUT = 120


def _run_engine(cfg, engine, linear_model, prop, target_name):
    """Run one engine pass over ``linear_model`` for ``prop``.

    Returns a ``rot.symbolic.EngineResult``. ``prop`` is a
    ``rot.invariants.Invariant``; the symbolic engine checks its
    ``.expression`` while the TLC engine re-emits TLA+ from the linear model
    and checks the named invariant. The ``apalache`` engine evaluates
    ``prop`` over a concrete Apalache ITF counterexample trace
    (``cfg.itf_trace`` / ``--itf``): it can refute, never prove. The
    ``apalache-mc`` engine (``rot.apalache``) is the real Apalache runner:
    it emits bounded TLA+ and drives ``apalache.jar`` to prove (bounded
    NoError) or refute (counterexample + witness); it needs a jar + Java 21
    (see ``cfg.apalache_available()``).
    """
    if engine == "tlc":
        from rot.tlc import TlcEngine
        return TlcEngine(cfg).check(linear_model, prop, target=target_name)
    if engine == "apalache":
        from rot.itf import ItfEngine
        return ItfEngine(cfg).check(linear_model, prop, target=target_name)
    if engine == "apalache-mc":
        from rot.apalache import ApalacheEngine
        return ApalacheEngine(cfg).check(linear_model, prop, target=target_name)
    from rot.symbolic import SymbolicEngine
    eng = SymbolicEngine(linear_model, max_states=cfg.max_states)
    return eng.check(prop.expression)


def _load_cpg_model(cpg_path, source_dir, quiet=False):
    """Load a CPG artifact for the source frontend, or None (source-only).

    An explicit ``cpg_path`` must exist and be valid (a hard error otherwise:
    the user asked for it).  Without one, the first ``*.cpg.json`` under
    ``source_dir`` is used opportunistically; an invalid artifact there is
    downgraded to a warning and the source-only frontend is used instead.
    """
    from rot.frontends import cpg_reader
    if cpg_path:
        return cpg_reader.load_cpg(cpg_path)   # raises CpgReadError -> exit 3
    if source_dir:
        import glob
        cands = sorted(glob.glob(os.path.join(os.path.abspath(source_dir),
                                              "**", "*.cpg.json"),
                                recursive=True))
        if cands:
            model = cpg_reader.load_cpg_or_none(cands[0])
            if model is None and not quiet:
                print("WARNING: CPG artifact invalid (%s); "
                      "using source-only frontend" % cands[0])
            return model
    return None


def run(target_name="correct", property_name=None, engine="auto",
        n=None, max_states=None, cegar_max_iter=None,
        tlc_jar=None, work_dir=None, tlc_timeout=None, itf_trace=None,
        participant_bound=None, env_bound=None,
        llm_enabled=False, llm_model=None, llm_base_url=None,
        source_dir=None, cpg_path=None,
        apalache_enabled=False, apalache_jar=None, apalache_java=None,
        apalache_timeout=None, apalache_length=None,
        out_dir="out", quiet=False):
    """Run one verification pass; return the final ``rot.verdicts.Verdict``.

    Every argument is optional and defaults to a valid, complete run, so
    ``run("correct")`` is sufficient. Raises on an unknown target/property, or
    if a run cannot be produced (the CLI maps that to exit code 3).

    ``source_dir`` switches to the narrow-waist source frontend: the IR is
    built directly from a directory of Java 2PC sources (``Coordinator.java``
    + ``Participant.java``) via ``rot.frontends.java`` instead of the hand-
    written registry target. ``cpg_path`` optionally supplies a CPG artifact
    (``CpgModel`` JSON) the frontend consults as evidence; without it, any
    ``*.cpg.json`` under ``source_dir`` is used opportunistically.

    ``engine="apalache"`` + ``itf_trace`` evaluates the pinned invariant over
    a concrete Apalache ITF counterexample (a ``.itf.json`` file): a definite
    refutation is reported as a violation, and the engine can never report
    ``proven`` (one concrete path refutes but cannot prove).
    """
    import rot.targets as targets
    from rot.config import Config
    from rot.abstraction import derive_abstraction
    from rot.linearization import linearize
    from rot.cegar import cegar, cegar_liveness
    from rot.invariants import KIND_LIVENESS
    from rot.verdicts import VerdictReport

    # 1. resolve the target and the pinned property.
    if source_dir is not None:
        # 2PC source frontend: the IR is built from the Java sources
        # themselves (narrow waist: rot.ir is the only model dependency).
        import rot.invariants as invariants
        import rot.frontends.java as java_fe
        if not os.path.isdir(source_dir):
            raise ValueError("source directory not found: %s" % source_dir)
        spec = targets.get("correct")  # 2PC: default property + protocol label
        if property_name is None:
            property_name = spec.default_property
        if property_name not in ("agreement", "validity", "no_spurious_abort"):
            raise ValueError(
                "the 2PC source frontend supports properties %r, not %r"
                % (("agreement", "validity", "no_spurious_abort"),
                   property_name))
        n_eff = int(n) if n is not None else 3
        prop = invariants.get(property_name, n_eff)
        model = _load_cpg_model(cpg_path, source_dir, quiet)
        ir = java_fe.build_ir(source_dir, n=n_eff, model=model)
        base = os.path.basename(os.path.abspath(source_dir).rstrip("/\\"))
        target_name = "java-" + (base or "src")
    else:
        spec = targets.get(target_name)            # KeyError if unknown
        if property_name is None:
            property_name = spec.default_property
        n_eff = int(n) if n is not None else 3
        prop = targets.get_property(target_name, property_name, n_eff)
        ir = targets.build(target_name, n_eff)

    # 2. runtime config (resolves the engine; every default is safe).
    cfg = Config(
        engine=engine,
        tlc_jar=tlc_jar,
        tlc_timeout=tlc_timeout if tlc_timeout is not None else DEFAULT_TLC_TIMEOUT,
        itf_trace=itf_trace,
        max_states=max_states if max_states is not None else DEFAULT_MAX_STATES,
        cegar_max_iter=cegar_max_iter if cegar_max_iter is not None else DEFAULT_CEGAR_MAX_ITER,
        participant_bound=participant_bound,
        env_bound=env_bound,
        llm_enabled=llm_enabled,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        out_dir=out_dir,
        work_dir=work_dir,
        apalache_enabled=apalache_enabled,
        apalache_jar=apalache_jar,
        apalache_java=apalache_java,
        apalache_timeout=(apalache_timeout if apalache_timeout is not None
                          else DEFAULT_APALACHE_TIMEOUT),
        apalache_length=apalache_length,
    )
    chosen = cfg.select_engine()

    # 3. property-directed abstraction (soundness manifest for the report).
    ab = derive_abstraction(ir, prop.expression, prop.name,
                            participant_bound=n_eff, env_bound=env_bound)

    # 4. linearize the concrete model (init + ordered transitions).
    linear_model = linearize(ir)

    # 5. engine pass + CEGAR refinement.
    #    * safety invariants -> unreachability check + ``cegar`` (re-runs the
    #      same engine on ``unknown`` up to ``cfg.cegar_max_iter`` times via
    #      the recheck hook; deterministic for the concrete engines, but
    #      correct for any over-approximating engine).
    #    * liveness invariants (kind="liveness", e.g. bounded_eventually) ->
    #      bounded reachability: the goal must be REACHABLE within
    #      ``cfg.liveness_horizon`` steps. Only the symbolic engine exposes
    #      ``reach_within``, so liveness is dispatched to it (it is the
    #      independent oracle, and the other engines can only refute safety).
    if getattr(prop, "kind", None) == KIND_LIVENESS:
        from rot.symbolic import SymbolicEngine
        # Only the symbolic engine exposes reach_within, so the liveness check
        # always runs on symbolic regardless of the auto-resolved ``chosen``.
        effective_engine = "symbolic"
        reach = (SymbolicEngine(linear_model, max_states=cfg.max_states)
                 .reach_within(prop.expression, cfg.liveness_horizon,
                               max_states=cfg.max_states))
        verdict = cegar_liveness(reach, prop, cfg, effective_engine)
    else:
        if chosen == "crosscheck":
            # Three-engine cross-check (SMT/Z3 + TLC + policy-direct).  Only
            # PROVEN/VIOLATED when all three engines agree; disagreement or
            # UNKNOWN -> UNKNOWN.
            # Bypasses CEGAR (which refines a single engine's abstraction)
            # because the point is to *not* trust any single engine.
            from rot.crosscheck import CrossChecker
            effective_engine = "crosscheck"
            verdict = CrossChecker(ir, linear_model, prop, cfg).check()
        else:
            effective_engine = chosen
            def _recheck(model, p, max_states):
                return _run_engine(cfg, chosen, model, p, target_name)

            verdict = cegar(_run_engine(cfg, chosen, linear_model, prop, target_name),
                            prop, cfg, chosen,
                            model=linear_model, recheck=_recheck)

    # 6. auditable report (JSON + Markdown).
    report = VerdictReport(
        target=target_name,
        property_name=prop.name,
        engine=effective_engine,
        config_dict=cfg.to_dict(),
        abstraction_dict=ab.to_dict(),
        verdict=verdict,
        invariant_dict=prop.to_dict(),
    )
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    json_path = report.write(out_dir, "%s_%s" % (target_name, prop.name))

    # 6b. OPTIONAL NON-SOUND LLM baseline (opt-in). It runs whenever enabled,
    #     writes an audit artifact, and NEVER changes the verdict/exit code.
    llm_report = None
    if _llm_enabled(cfg):
        llm_report = _run_llm_baseline(cfg, linear_model, prop, target_name,
                                       out_dir, spec, verdict.status)

    if not quiet:
        _print_summary(target_name, prop, effective_engine, verdict, json_path,
                       protocol=getattr(spec, "protocol", "2PC"))
        if llm_report is not None:
            _print_llm_baseline(llm_report)

    return verdict


def _print_summary(target_name, prop, engine, verdict, json_path,
                   protocol="2PC"):
    bar = "-" * 62
    print(bar)
    print("  ROTN %s verification" % protocol)
    print(bar)
    print("  target    : %s" % target_name)
    print("  property  : %s" % prop.name)
    print("             %s" % prop.description)
    lbl = getattr(prop, "label", None)
    pin = getattr(prop, "pinned", False)
    blk = prop.blocking_permission() if hasattr(prop, "blocking_permission") else False
    if lbl:
        print("  label     : %s (pinned=%s, blocking=%s)" % (lbl, pin, blk))
    print("  engine    : %s" % engine)
    print("  verdict   : %s" % verdict.status.upper())
    print("  states    : %d" % verdict.n_states)
    if verdict.cegar_iterations:
        print("  cegar iter: %d" % verdict.cegar_iterations)
    if verdict.note:
        print("  note      : %s" % verdict.note)
    if verdict.counterexample:
        try:
            ce = json.dumps(verdict.counterexample, sort_keys=True)
        except Exception:
            ce = repr(verdict.counterexample)
        print("  counterex : %s" % ce)
    cc = (verdict.evidence or {}).get("crosscheck") or {}
    ap = cc.get("apalache")
    if ap:
        print("  apalache  : %s  (%s)" % (ap["status"].upper(),
                                         ap.get("note") or ""))
    print("  report    : %s" % json_path)
    print(bar)


def _llm_enabled(cfg):
    return bool(getattr(cfg, "llm_enabled", False))


def _run_llm_baseline(cfg, linear_model, prop, target_name, out_dir, spec,
                      verdict_status):
    """Run the optional LLM baseline and write an audit artifact.

    NEVER raises to the caller: any failure is folded into the report dict
    (``status="error"``) so it cannot affect the formal verdict or the exit
    code. The report is always written to ``<out_dir>/<target>_<prop>_
    llmbaseline.json`` for auditability.
    """
    from rot.llm_baseline import llm_baseline

    # Emit the exact TLA+ the engine sees, so the LLM reads the real spec.
    spec_text = ""
    try:
        from rot.emitter import Emitter
        module = getattr(spec, "protocol", None) or "Module"
        em = Emitter(linear_model, module_name=module)
        spec_text, _op = em.emit(prop.name, prop.expression)
    except Exception:
        spec_text = ""

    report = llm_baseline(cfg, spec_text, [prop.name], verdict_status)

    # Best-effort audit artifact (never fatal).
    if out_dir:
        try:
            if not os.path.isdir(out_dir):
                os.makedirs(out_dir)
            path = os.path.join(
                out_dir, "%s_%s_llmbaseline.json" % (target_name, prop.name))
            with open(path, "w") as f:
                json.dump(report, f, indent=2, sort_keys=True)
        except Exception:
            pass
    return report


def _print_llm_baseline(report):
    bar = "-" * 62
    print(bar)
    print("  LLM baseline (NON-SOUND -- informational only, does NOT affect "
          "the verdict)")
    print(bar)
    status = report.get("status")
    print("  status    : %s" % status)
    if status == "ok":
        print("  model     : %s" % report.get("model"))
        if report.get("interesting_invariants"):
            print("  invariants: %s" % ", ".join(report["interesting_invariants"]))
        if report.get("likely_bug"):
            print("  likely bug: %s" % report["likely_bug"])
        ce = report.get("counterexample")
        if ce:
            print("  candidate : %s" % json.dumps(ce, sort_keys=True))
            print("              (LLM-guessed trace -- NOT engine-verified, "
                  "may be wrong)")
        else:
            print("  counterex : none supplied by the LLM")
    elif status == "unavailable":
        print("  %s" % report.get("error"))
    elif status == "error":
        print("  %s" % report.get("error"))
    print("  note      : %s" % report.get("disclaimer"))
    print(bar)


def _exit_code(verdict):
    status = verdict.status
    if status == "proven":
        return EXIT_PROVEN
    if status == "violated":
        return EXIT_VIOLATED
    if status in ("unknown", "unsound"):
        return EXIT_UNKNOWN
    return EXIT_ERROR


def _print_registry():
    import rot.targets as targets
    for name in targets.names():
        spec = targets.get(name)
        props = ", ".join(targets.list_properties(name))
        print("%-8s  [%s]  %s" % (name, props, spec.description))


def _cmd_refine(args):
    """Run the Phase 4 refinement loop (:mod:`rot.refine`) for --before/--after.

    Delegates to ``rot.refine.main`` so the standalone refinement CLI (loading,
    invariant resolution, propose/check/repair, report writing) is reused
    verbatim.  Returns the process exit code: 0 on ``refined``, 1 otherwise,
    2 on usage errors.
    """
    from rot import refine as refine_mod
    argv = [args.before, args.after]
    for name in (args.invariant or []):
        argv.extend(["--invariant", name])
    if args.n is not None:
        argv.extend(["--n", str(args.n)])
    if args.max_states is not None:
        argv.extend(["--max-states", str(args.max_states)])
    if args.rounds is not None:
        argv.extend(["--rounds", str(args.rounds)])
    if args.out_dir is not None:
        argv.extend(["--out", args.out_dir])
    try:
        return refine_mod.main(argv)
    except SystemExit as exc:
        code = exc.code
        return 0 if code is None else int(code)


def _parse_action_list(spec):
    """Parse a comma-separated action list into a sorted list of non-empty
    strings (deduplicated). ``None`` / empty -> ``[]``."""
    if spec is None:
        return []
    out = set()
    for part in str(spec).split(","):
        name = part.strip()
        if name:
            out.add(name)
    return sorted(out)


def _cmd_trifecta(args):
    """Run the three-facet policy audit (--trifecta) and emit a manifest.

    Builds a :class:`rot.ir.AdversarialPolicy` from the ``--allowed`` /
    ``--denied`` action lists, runs :func:`rot.manifest.build_manifest` (which
    wraps :func:`rot.trifecta.audit`), and -- when ``--manifest`` is set --
    writes the deterministic report to ``<out>/trifecta_manifest.json``.

    Also runs the D6 "Lethal Trifecta" design-time risk flag
    (:func:`rot.trifecta_risk.detect`) over the policy's action set and prints
    it in the summary; with ``--manifest`` it is written to
    ``<out>/trifecta_risk.json``.  The flag is a design-time heuristic (no
    engine, no soundness claim) and does NOT affect the audit result or the
    exit code.

    Returns the process exit code (0 proven / 1 violated / 2 unknown / 3 error).
    """
    from rot import manifest
    from rot import trifecta_risk
    from rot.ir import AdversarialPolicy

    allowed = _parse_action_list(args.allowed)
    denied = _parse_action_list(args.denied)
    if not allowed and not denied:
        print("ERROR: --trifecta needs --allowed and/or --denied",
              file=sys.stderr)
        return EXIT_ERROR
    overlap = set(allowed) & set(denied)
    if overlap:
        print("ERROR: --allowed and --denied overlap: %r" % (sorted(overlap),),
              file=sys.stderr)
        return EXIT_ERROR

    policy = AdversarialPolicy(allowed, denied)
    horizon = (args.liveness_horizon if args.liveness_horizon is not None
               else 12)
    max_states = (args.max_states if args.max_states is not None
                  else DEFAULT_MAX_STATES)
    buggy = bool(args.buggy)

    try:
        m = manifest.build_manifest(policy, buggy=buggy, horizon=horizon,
                                    max_states=max_states)
    except Exception as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    result = m.overall["result"]
    exit_code = {"proven": EXIT_PROVEN,
                 "violated": EXIT_VIOLATED}.get(result, EXIT_UNKNOWN)

    # D6 "Lethal Trifecta" design-time risk flag over the policy's action
    # set.  Informational only: it never changes the audit result or the
    # exit code (a design-time heuristic, not a soundness claim).
    try:
        risk = trifecta_risk.detect(policy)
    except Exception as exc:
        print("WARNING: D6 risk flag failed: %s" % exc, file=sys.stderr)
        risk = None

    path = None
    risk_path = None
    if args.manifest:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
            path = os.path.join(args.out_dir, "trifecta_manifest.json")
            with open(path, "w") as f:
                f.write(m.to_json())
        except Exception as exc:
            print("WARNING: could not write manifest: %s" % exc,
                  file=sys.stderr)
            path = None
        if risk is not None:
            try:
                risk_path = os.path.join(args.out_dir, "trifecta_risk.json")
                with open(risk_path, "w") as f:
                    f.write(risk.to_json())
            except Exception as exc:
                print("WARNING: could not write D6 risk flag: %s" % exc,
                      file=sys.stderr)
                risk_path = None

    if not args.quiet:
        bar = "-" * 62
        print(bar)
        print("  ROTN three-facet audit (safety + liveness + conformance)")
        print(bar)
        print("  agent     : %s" % ("adversarial" if buggy else "conforming"))
        print("  allowed   : %s" % (", ".join(allowed) or "(none)"))
        print("  denied    : %s" % (", ".join(denied) or "(none)"))
        print("  horizon   : %d" % horizon)
        print("  max-states: %d" % max_states)
        print("  policy    : %s" % m.policy["hash"][:16])
        for facet in ("safety", "liveness", "conformance"):
            print("  %-11s : %s" % (facet, m.verdicts[facet]["status"].upper()))
        print("  overall   : %s" % result.upper())
        if risk is not None:
            print("  risk      : %s" % risk.message)
        if m.witness is not None:
            print("  witness   : %s" % json.dumps(m.witness, sort_keys=True))
        print("  manifest  : %s" % m.manifest_id[:16])
        if path:
            print("  report    : %s" % path)
        if risk_path:
            print("  risk file : %s" % risk_path)
        print(bar)

    return exit_code


def _cmd_policy(args):
    """Run the policy-driven verification path (``--policy``).

    Builds a ``rot.ir.ProtocolIR`` from the policy file via the narrow-waist
    policy front-end (:mod:`rot.frontends.policy`), then checks the pinned
    property with the bounded checkers.  The property kind drives the query:

    * ``safety``        -> ``forall_reachable`` (must hold in *every* state)
    * ``realizability`` -> ``exists_reachable``  (must hold in *some* state)
    * ``liveness``      -> bounded reachability: the goal must be REACHABLE
      within ``--liveness-horizon`` steps (``SymbolicEngine.reach_within``
      + ``cegar_liveness`` -- the same dispatch ``run()`` uses for
      liveness invariants)

    ``--kind`` forces the property kind (default: auto-route by file
    extension).  Returns the process exit code (0 proven / 1 violated /
    2 unknown / 3 error).
    """
    import rot.frontends.policy as policy_fe
    from rot.modelfind import ModelFinder, SAT, UNSAT

    policy_path = args.policy
    tools_path = args.tools
    n_steps = args.n_steps if args.n_steps is not None else 1

    # 1. Build the IR (narrow waist: only rot.ir under the hood).  ``--kind``
    #    optionally forces the property kind (default: auto-route by file
    #    extension).
    try:
        ir = policy_fe.build_ir(policy_path, tools_path=tools_path,
                                n_steps=n_steps, kind=args.kind,
                                max_inflight=args.max_inflight,
                                amount=args.amount, cap=args.cap,
                                window=args.window)
    except policy_fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()

    kind = ir.metadata.get("property_kind")
    prop_name = ir.metadata.get("property_name", "policy_property")
    target_name = "policy-" + os.path.basename(policy_path)
    witness = None
    note = ""

    # 2a. --engine crosscheck: the D3 three-engine (SMT/Z3 + TLC + policy-direct)
    #     soundness core.  It is a *safety* engine, so it applies only to safety
    #     policies; a realizability policy is an existential query that
    #     crosscheck cannot discharge (hard error), and a liveness policy
    #     falls through to the bounded-liveness path below -- exactly as
    #     run() dispatches liveness invariants to the symbolic engine
    #     regardless of --engine.
    if args.engine == "crosscheck":
        if kind == "safety":
            return _cmd_policy_crosscheck(args, ir, prop_name, target_name)
        if kind == "realizability":
            print("ERROR: --engine crosscheck is a safety engine and cannot "
                  "discharge a realizability policy; re-run with "
                  "--engine symbolic (or --engine auto)", file=sys.stderr)
            return EXIT_ERROR
        # kind == "liveness" -> fall through to the symbolic path below

    # 2. Bounded check.
    #    * safety / realizability -> reachable-state enumerator (rot.modelfind)
    #    * liveness -> the bounded-liveness machinery, exactly as ``run()``
    #      dispatches liveness invariants: linearize, then
    #      SymbolicEngine.reach_within within the horizon + cegar_liveness.
    if kind == "liveness":
        from rot.config import Config
        from rot.invariants import Invariant, KIND_LIVENESS
        from rot.linearization import linearize
        from rot.symbolic import SymbolicEngine
        from rot.cegar import cegar_liveness

        horizon = (args.liveness_horizon if args.liveness_horizon is not None
                   else 12)
        cfg = Config(max_states=DEFAULT_MAX_STATES,
                     liveness_horizon=horizon)
        prop = Invariant(name=prop_name,
                         description="bounded liveness goal pinned by the "
                                    "policy front-end (the goal must be "
                                    "reachable within the horizon)",
                         expression=ir.pinned_property,
                         kind=KIND_LIVENESS)
        linear_model = linearize(ir)
        reach = (SymbolicEngine(linear_model, max_states=cfg.max_states)
                 .reach_within(prop.expression, cfg.liveness_horizon,
                               max_states=cfg.max_states))
        verdict = cegar_liveness(reach, prop, cfg, "symbolic")
        status = verdict.status
        note = verdict.note
        witness = (verdict.evidence or {}).get("path")
        if status == "proven":
            exit_code = EXIT_PROVEN
        elif status == "violated":
            exit_code = EXIT_VIOLATED
        elif status == "unknown":
            exit_code = EXIT_UNKNOWN
        else:
            exit_code = EXIT_ERROR
    else:
        mf = ModelFinder.from_ir(ir)
        pred = lambda s: ir.pinned_property.eval(s)
        if kind == "safety":
            result, witness = mf.forall_reachable(pred)
            if result is True:
                status, exit_code = "proven", EXIT_PROVEN
            elif result is False:
                status, exit_code = "violated", EXIT_VIOLATED
            else:
                status, exit_code = "unknown", EXIT_UNKNOWN
        elif kind == "realizability":
            result, witness = mf.exists_reachable(pred)
            if result == SAT:
                status, exit_code = "proven", EXIT_PROVEN
            elif result == UNSAT:
                status, exit_code = "violated", EXIT_VIOLATED
            else:
                status, exit_code = "unknown", EXIT_UNKNOWN
        else:
            print("ERROR: unknown property kind %r" % kind, file=sys.stderr)
            return EXIT_ERROR

    # 3. Auditable report (JSON) + human summary.
    report = {
        "target": target_name,
        "property_name": prop_name,
        "property_kind": kind,
        "verdict": status,
        "n_steps": n_steps,
        "policy_source": ir.metadata.get("policy_source"),
        "tools_source": ir.metadata.get("tools_source"),
        "witness": witness,
    }
    if ir.metadata.get("max_inflight") is not None:
        report["max_inflight"] = ir.metadata["max_inflight"]
    if ir.metadata.get("window") is not None:
        report["window"] = ir.metadata["window"]
    if ir.metadata.get("dw_window") is not None:
        report["dw_window"] = ir.metadata["dw_window"]
    if kind == "liveness":
        report["liveness_horizon"] = horizon
        report["note"] = note
    if args.out_dir:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
            path = os.path.join(args.out_dir, "%s_%s.json"
                               % (target_name, prop_name))
            with open(path, "w") as f:
                json.dump(report, f, indent=2, sort_keys=True)
        except Exception:
            path = None
    else:
        path = None

    if not args.quiet:
        bar = "-" * 62
        print(bar)
        print("  ROTN policy verification (%s)" % kind)
        print(bar)
        print("  target    : %s" % target_name)
        print("  property  : %s" % prop_name)
        print("  source    : %s" % ir.metadata.get("policy_source"))
        if ir.metadata.get("tools_source"):
            print("  tools     : %s" % ir.metadata.get("tools_source"))
        print("  n-steps   : %d" % n_steps)
        if ir.metadata.get("max_inflight") is not None:
            print("  max-inflt : %d (bounded concurrency pool K)"
                  % ir.metadata["max_inflight"])
        if ir.metadata.get("window") is not None:
            print("  window    : %d (bounded event count W; %s)"
                  % (ir.metadata["window"],
                     ir.metadata.get("dw_window") or "n/a"))
        print("  verdict   : %s" % status.upper())
        if note:
            print("  note      : %s" % note)
        if witness:
            try:
                w = json.dumps(witness, sort_keys=True)
            except Exception:
                w = repr(witness)
            print("  witness   : %s" % w)
        if path:
            print("  report    : %s" % path)
        print(bar)

    return exit_code


def _cmd_policy_crosscheck(args, ir, prop_name, target_name):
    """``--engine crosscheck`` branch of :func:`_cmd_policy` (D3 core).

    Mirrors the registry-target path in :func:`run`: build the pinned safety
    invariant from the policy's pinned property, derive the property-directed
    abstraction (the soundness manifest), linearize the concrete model, then
    run the SMT (Z3), TLC, and policy-direct engines in parallel via
    :class:`rot.crosscheck.CrossChecker`, accepting only a verdict all three
    engines agree on.  Emits the canonical D3 report (JSON + Markdown,
    :class:`rot.verdicts.VerdictReport`) so the output carries the per-engine
    evidence (``verdict.evidence["crosscheck"]`` = SMT + TLC + policy-direct
    status, counterexamples, and the join) -- the same schema a registry-target
    cross-check run produces.  Returns the process exit code
    (0 proven / 1 violated / 2 unknown / 3 error).
    """
    import rot.invariants as invariants
    from rot.abstraction import derive_abstraction
    from rot.config import Config
    from rot.crosscheck import CrossChecker
    from rot.linearization import linearize
    from rot.verdicts import PROVEN, VIOLATED, VerdictReport

    # 1. runtime config (resolves to the cross-check engine; TLC is required,
    #    so a missing TLC jar / java is a hard error up front).
    cfg = Config(
        engine="crosscheck",
        tlc_jar=args.tlc_jar,
        tlc_timeout=args.tlc_timeout if args.tlc_timeout is not None
        else DEFAULT_TLC_TIMEOUT,
        max_states=args.max_states if args.max_states is not None
        else DEFAULT_MAX_STATES,
        out_dir=args.out_dir,
        work_dir=args.work_dir or os.path.join(args.out_dir, "work"),
        verbose=not args.quiet,
        apalache_enabled=args.apalache,
        apalache_jar=args.apalache_jar,
        apalache_java=args.apalache_java,
        apalache_timeout=(args.apalache_timeout
                          if args.apalache_timeout is not None
                          else DEFAULT_APALACHE_TIMEOUT),
        apalache_length=args.apalache_length,
    )
    if not cfg.tlc_available():
        print("ERROR: --engine crosscheck needs a TLC jar + a java runtime "
              "(set --tlc-jar or $TLA2TOOLS_JAR)", file=sys.stderr)
        return EXIT_ERROR

    # 2. the pinned safety invariant, from the policy's pinned property.
    prop = invariants.Invariant(
        name=prop_name,
        description="policy cross-check: %s" % prop_name,
        expression=ir.pinned_property,
        kind="safety",
        label=invariants.LABEL_BOUNDED,
        pinned=True,
    )

    # 3. property-directed abstraction (soundness manifest for the report).
    ab = derive_abstraction(ir, prop.expression, prop.name)

    # 4. linearize the concrete model (init + ordered transitions).
    linear_model = linearize(ir)

    # 5. three-engine cross-check (SMT/Z3 + TLC + policy-direct, run in parallel).
    verdict = CrossChecker(ir, linear_model, prop, cfg).check()

    # 6. canonical D3 report (JSON + Markdown), same schema as run().
    report = VerdictReport(
        target=target_name,
        property_name=prop_name,
        engine="crosscheck",
        config_dict=cfg.to_dict(),
        abstraction_dict=ab.to_dict(),
        verdict=verdict,
        invariant_dict=prop.to_dict(),
    )
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        report_path = report.write(args.out_dir,
                                   "%s_%s" % (target_name, prop_name))
    else:
        report_path = None

    # 7. human summary (mirrors the other --policy branches).
    if not args.quiet:
        bar = "-" * 62
        print(bar)
        print("  ROTN policy verification (crosscheck: SMT/Z3 + TLC + policy-direct, "
              "parallel)")
        print(bar)
        print("  target    : %s" % target_name)
        print("  property  : %s" % prop_name)
        print("  source    : %s" % ir.metadata.get("policy_source"))
        if ir.metadata.get("tools_source"):
            print("  tools     : %s" % ir.metadata.get("tools_source"))
        if ir.metadata.get("max_inflight") is not None:
            print("  max-inflt : %d (bounded concurrency pool K)"
                  % ir.metadata["max_inflight"])
        print("  engine    : crosscheck (SMT/Z3 + TLC + policy-direct)")
        print("  verdict   : %s" % verdict.status.upper())
        if verdict.note:
            print("  note      : %s" % verdict.note)
        if verdict.counterexample:
            try:
                ce = json.dumps(verdict.counterexample, sort_keys=True)
            except Exception:
                ce = repr(verdict.counterexample)
            print("  counterex : %s" % ce)
        cc = (verdict.evidence or {}).get("crosscheck")
        if cc:
            print("  smt       : %s  (%s)"
                  % (cc["smt"]["status"].upper(), cc["smt"]["engine"]))
            print("  tlc       : %s  (%s)"
                  % (cc["tlc"]["status"].upper(), cc["tlc"]["engine"]))
            pd = cc.get("policy_direct")
            if pd:
                print("  policy    : %s  (%s)"
                      % (pd["status"].upper(), pd.get("engine", "policy_direct")))
            ap = cc.get("apalache")
            if ap:
                print("  apalache  : %s  (%s)"
                      % (ap["status"].upper(), ap.get("note") or ""))
            print("  joined    : %s  (policy=%s)"
                  % (cc["joined"].upper(), cc["policy"]))
            if cc.get("witness_match") is not None:
                print("  witness   : %s"
                      % ("MATCH (all three engines -> same attack state)"
                         if cc["witness_match"] else
                         "MISMATCH (engines found different states)"))
        if report_path:
            print("  report    : %s" % report_path)
        print(bar)

    if verdict.status == PROVEN:
        return EXIT_PROVEN
    if verdict.status == VIOLATED:
        return EXIT_VIOLATED
    return EXIT_UNKNOWN


def _cmd_classify(args):
    """Classify spend-cap policies as SAFE / UNSAFE + witness (Phase 5).

    For each policy in ``--policies`` (or the single ``--policy``), build the
    narrow-waist IR, check the pinned safety property over the reachable
    states, and report:

    * ``SAFE``    -- the cap holds in *every* reachable state (proven);
    * ``UNSAFE``  -- some reachable state exceeds the cap (violated), with a
      concrete witness state (``completed`` / ``inflight``);
    * ``UNKNOWN`` -- the bounded search was inconclusive.

    This is the generalization face of the spend-cap slice: the same sound
    core that separates the two endpoints (``spendcap-correct`` /
    ``spendcap-buggy``) classifies *unseen* corpus policies (filters,
    thresholds, forbid/permit shapes) with no per-policy tuning. The verdict
    is driven by the event kind the sum quantifies over (``request`` ->
    in-flight accounting -> SAFE; ``response`` -> settled-only -> UNSAFE).

    Returns the process exit code (0 all SAFE / 1 any UNSAFE / 2 any UNKNOWN
    / 3 any error) and, when ``--out`` is set, writes ``classify_report.json``.
    """
    import rot.frontends.policy as policy_fe
    from rot.modelfind import ModelFinder

    policies = list(args.policies or [])
    if args.policy:
        policies.append(args.policy)
    if not policies:
        print("ERROR: --classify needs at least one policy "
              "(--policies A.dw --policies B.dw, or --policy A.dw)",
              file=sys.stderr)
        return EXIT_ERROR

    n_steps = args.n_steps if args.n_steps is not None else 1
    results = []
    for policy_path in policies:
        entry = {
            "policy": policy_path,
            "verdict": None,
            "witness": None,
            "property": None,
            "event_kind": None,
            "cap": None,
            "error": None,
        }
        try:
            ir = policy_fe.build_ir(policy_path, tools_path=args.tools,
                                    n_steps=n_steps, kind=args.kind,
                                    max_inflight=args.max_inflight,
                                    amount=args.amount, cap=args.cap,
                                    window=args.window)
        except policy_fe.PolicyFrontendError as exc:
            entry["error"] = str(exc)
            results.append(entry)
            continue
        entry["property"] = ir.metadata.get("property_name")
        entry["event_kind"] = ir.metadata.get("dw_event_kind")
        entry["cap"] = ir.metadata.get("dw_cap")
        kind = ir.metadata.get("property_kind")
        if kind != "safety":
            entry["error"] = ("classify supports safety policies only "
                              "(got kind %r)" % (kind,))
            results.append(entry)
            continue
        mf = ModelFinder.from_ir(ir)
        result, witness = mf.forall_reachable(
            lambda s: ir.pinned_property.eval(s))
        if result is True:
            entry["verdict"] = "SAFE"
        elif result is False:
            entry["verdict"] = "UNSAFE"
            entry["witness"] = witness
        else:
            entry["verdict"] = "UNKNOWN"
        results.append(entry)

    n_safe = sum(1 for r in results if r["verdict"] == "SAFE")
    n_unsafe = sum(1 for r in results if r["verdict"] == "UNSAFE")
    n_unknown = sum(1 for r in results if r["verdict"] == "UNKNOWN")
    n_error = sum(1 for r in results if r["error"] is not None)

    report = {
        "n_steps": n_steps,
        "max_inflight": (args.max_inflight
                         if args.max_inflight is not None
                         else None),
        "window": (args.window if args.window is not None else None),
        "results": results,
        "summary": {"safe": n_safe, "unsafe": n_unsafe,
                    "unknown": n_unknown, "error": n_error},
    }
    path = None
    if args.out_dir:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
            path = os.path.join(args.out_dir, "classify_report.json")
            with open(path, "w") as f:
                json.dump(report, f, indent=2, sort_keys=True)
        except Exception:
            path = None

    if not args.quiet:
        bar = "=" * 74
        print(bar)
        print("  ROTN spend-cap classification (SAFE / UNSAFE + witness)")
        print(bar)
        name_w = max([len("policy")] + [len(os.path.basename(r["policy"]))
                                        for r in results])
        name_w = max(name_w, 12)
        print("  %-*s  %-8s  %-8s  %s" % (name_w, "policy", "verdict",
                                          "event", "witness"))
        print("  " + "-" * (name_w + 8 + 8 + 24))
        for r in results:
            name = os.path.basename(r["policy"])
            if len(name) > name_w:
                name = name[:name_w - 1] + "~"
            verdict = r["verdict"] if r["verdict"] else "ERROR"
            event = r["event_kind"] if r["event_kind"] else "-"
            if r["witness"] is not None:
                try:
                    wit = json.dumps(r["witness"], sort_keys=True)
                except Exception:
                    wit = repr(r["witness"])
            else:
                wit = "-"
            print("  %-*s  %-8s  %-8s  %s" % (name_w, name, verdict, event, wit))
            if r["error"]:
                print("  %*s    error: %s" % (name_w + 2, "", r["error"]))
        print(bar)
        print("  %d SAFE, %d UNSAFE, %d UNKNOWN, %d ERROR"
              % (n_safe, n_unsafe, n_unknown, n_error))
        if path:
            print("  report    : %s" % path)
        print(bar)

    if n_error:
        return EXIT_ERROR
    if n_unknown:
        return EXIT_UNKNOWN
    if n_unsafe:
        return EXIT_VIOLATED
    return EXIT_PROVEN


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pipeline.py",
        description="ROTN verification pipeline (2PC + ZAB; soundness core).")
    parser.add_argument("target", nargs="?", default=None,
                        help="target name (correct|buggy) [default: correct; "
                             "omit when using --source]")
    parser.add_argument("--property", dest="property_name", default=None,
                        help="property to pin (default: the target's default, "
                             "'agreement')")
    parser.add_argument("--engine", default="auto",
                        choices=["auto", "tlc", "symbolic", "apalache",
                                 "crosscheck"],
                        help="engine [default: auto]")
    parser.add_argument("--n", type=int, default=None,
                        help="participant count [default: 3]")
    parser.add_argument("--env", dest="env_bound", type=int, default=None,
                        help="environment bound: at most N message losses/reorders "
                             "per round (recorded as a sound assumption)")
    parser.add_argument("--max-states", dest="max_states", type=int,
                        default=None,
                        help="symbolic engine state bound [default: %d]"
                             % DEFAULT_MAX_STATES)
    parser.add_argument("--cegar-max-iter", dest="cegar_max_iter", type=int,
                        default=None,
                        help="CEGAR refinement cap [default: %d]"
                             % DEFAULT_CEGAR_MAX_ITER)
    parser.add_argument("--tlc-jar", dest="tlc_jar", default=None,
                        help="path to tla2tools.jar (or set $TLA2TOOLS_JAR)")
    parser.add_argument("--work-dir", dest="work_dir", default=None,
                        help="TLC work/artifact directory [default: out/work]")
    parser.add_argument("--tlc-timeout", dest="tlc_timeout", type=int,
                        default=None,
                        help="TLC timeout (s) [default: %d]"
                             % DEFAULT_TLC_TIMEOUT)
    parser.add_argument("--itf", dest="itf_trace", default=None,
                        metavar="ITF_JSON",
                        help="Apalache ITF counterexample trace for the "
                             "'apalache' engine (a .itf.json file from an "
                             "apalache-mc run, e.g. violation.itf.json)")
    # -- Apalache native model checker (rot.apalache): the informational
    #    third engine in --engine crosscheck, or a standalone engine.
    parser.add_argument("--apalache", dest="apalache", action="store_true",
                        help="enable the Apalache native model checker "
                             "(rot.apalache) as the informational third "
                             "engine in --engine crosscheck; needs "
                             "apalache.jar + Java 21 (via --apalache-jar / "
                             "--apalache-java, or $APALACHE_JAR / "
                             "$APALACHE_JAVA)")
    parser.add_argument("--apalache-jar", dest="apalache_jar", default=None,
                        help="path to apalache.jar (or set $APALACHE_JAR)")
    parser.add_argument("--apalache-java", dest="apalache_java", default=None,
                        help="path to a Java 21 `java` to run Apalache with "
                             "(or set $APALACHE_JAVA)")
    parser.add_argument("--apalache-timeout", dest="apalache_timeout",
                        type=int, default=None,
                        help="Apalache timeout (s) [default: %d]"
                             % DEFAULT_APALACHE_TIMEOUT)
    parser.add_argument("--apalache-length", dest="apalache_length",
                        type=int, default=None,
                        help="Apalache bounded-check length (max steps) "
                             "[default: engine default]")
    parser.add_argument("--source", dest="source_dir", default=None,
                        metavar="JAVA_DIR",
                        help="build the 2PC IR directly from a directory of "
                             "Java sources (Coordinator.java + "
                             "Participant.java) via the narrow-waist frontend "
                             "instead of a registry target; mutually "
                             "exclusive with the positional target")
    parser.add_argument("--cpg", dest="cpg_path", default=None,
                        metavar="CPG_JSON",
                        help="CPG artifact (CpgModel JSON) the --source "
                             "frontend consults as evidence [default: "
                             "auto-discovered *.cpg.json under --source]")
    # -- Policy-driven verification (rot.frontends.policy) --------------------
    parser.add_argument("--policy", dest="policy", default=None,
                        metavar="POLICY_FILE",
                        help="verify a policy file (.cedar, .json, or .dw) "
                             "via the narrow-waist policy front-end instead "
                             "of a registry target; implies the --tools "
                             "catalog when present")
    parser.add_argument("--tools", dest="tools", default=None,
                        metavar="TOOLS_JSON",
                        help="optional Dogwood tools.json catalog paired with "
                             "--policy (ignored for Cedar policies)")
    parser.add_argument("--n-steps", dest="n_steps", type=int, default=None,
                        help="agent-step horizon bound for --policy "
                             "[default: 1]")
    parser.add_argument("--max-inflight", dest="max_inflight", type=int,
                        default=None, metavar="K",
                        help="bounded concurrency pool K for the spend-cap "
                             "slice (max in-flight requests); the structural "
                             "limit shared by the correct and buggy variants "
                             "-- K=1 masks the parallel-fire race, K>=3 "
                             "exposes the clean (completed=0, inflight=3) "
                             "witness [default: 4; .dw spend-cap policies "
                             "only, ignored for Cedar / .json]")
    parser.add_argument("--window", dest="window", type=int,
                        default=None, metavar="W",
                        help="bounded event count W for the spend-cap "
                             "formerly-within window: the discretization of "
                             "the policy's time window (e.g. '24h') into at "
                             "most W tracked events; provenance recorded in "
                             "the report [default: 4; .dw spend-cap policies "
                             "only, ignored for Cedar / .json]")
    parser.add_argument("--amount", dest="amount", type=int, default=None,
                        metavar="AMOUNT",
                        help="per-request amount for the spend-cap slice "
                             "(overrides the policy's amount); .dw spend-cap "
                             "policies only [default: the policy's amount]")
    parser.add_argument("--cap", dest="cap", type=int, default=None,
                        metavar="CAP",
                        help="spend cap for the spend-cap slice (overrides "
                             "the policy's cap); .dw spend-cap policies only "
                             "[default: the policy's cap]")
    # -- Spend-cap classification (Phase 5): SAFE / UNSAFE + witness ---------
    parser.add_argument("--classify", dest="classify", action="store_true",
                        help="classify one or more spend-cap policies as "
                             "SAFE / UNSAFE (with a counterexample witness "
                             "for UNSAFE) instead of the generic "
                             "proven/violated verdict; pair with --policies "
                             "(repeatable) or a single --policy. This is the "
                             "generalization face: the same sound core that "
                             "separates the two endpoints classifies UNSEEN "
                             "corpus policies (filters, thresholds, "
                             "forbid/permit shapes) with no per-policy tuning")
    parser.add_argument("--policies", dest="policies", action="append",
                        default=[], metavar="POLICY_FILE",
                        help="policies to classify (repeatable); used with "
                             "--classify (e.g. --policies A.dw --policies B.dw)")
    parser.add_argument("--kind", dest="kind", default=None,
                        choices=["safety", "realizability", "liveness"],
                        help="property kind to pin for --policy "
                             "[default: auto-route by extension "
                             "(.cedar -> realizability, .dw / .json -> safety); "
                             "'liveness' pins the agent-step bounded-liveness "
                             "goal (decision != idle) that must be reachable "
                             "within --liveness-horizon]")
    parser.add_argument("--liveness-horizon", dest="liveness_horizon",
                        type=int, default=None,
                        help="bounded-liveness horizon (max steps) for "
                             "--kind liveness [default: 12]")
    # -- Three-facet audit (rot.trifecta) + manifest (rot.manifest) -----------
    parser.add_argument("--trifecta", dest="trifecta", action="store_true",
                        help="run the three-facet policy audit (safety + "
                             "liveness + conformance) on the AgentStep model "
                             "instead of a single pinned property; requires "
                             "--allowed and/or --denied; mutually exclusive "
                             "with --policy")
    parser.add_argument("--manifest", dest="manifest", action="store_true",
                        help="with --trifecta: write the deterministic "
                             "verification report (rot.manifest -> "
                             "trifecta_manifest.json) and the D6 Lethal "
                             "Trifecta risk flag (rot.trifecta_risk -> "
                             "trifecta_risk.json) to the out directory")
    parser.add_argument("--allowed", dest="allowed", default=None,
                        metavar="ACTIONS",
                        help="comma-separated allowed actions for --trifecta "
                             "(e.g. 'buy,hold')")
    parser.add_argument("--denied", dest="denied", default=None,
                        metavar="ACTIONS",
                        help="comma-separated denied actions for --trifecta "
                             "(e.g. 'sell')")
    parser.add_argument("--buggy", dest="buggy", action="store_true",
                        help="with --trifecta: audit the ADVERSARIAL agent "
                             "(denied actions left enabled) instead of the "
                             "conforming one")
    # -- Phase 4 refinement (rot.refine): verify a rewritten protocol ----------
    parser.add_argument("--before", default=None,
                        help="refinement: before model (target name or JSON IR file)")
    parser.add_argument("--after", default=None,
                        help="refinement: after model (target name or JSON IR file)")
    parser.add_argument("--invariant", dest="invariant", action="append",
                        default=[], metavar="NAME",
                        help="refinement: invariant name from the rot.invariants "
                             "registry (repeatable; default: the before target's)")
    parser.add_argument("--rounds", type=int, default=None,
                        help="refinement: max propose/check/repair rounds [default: 3]")
    parser.add_argument("--out", dest="out_dir", default="out",
                        help="report output directory [default: out]")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the human summary (still writes the report)")
    parser.add_argument("--list", dest="list_targets", action="store_true",
                        help="list available targets and their properties")
    parser.add_argument("--llm-baseline", dest="llm_baseline",
                        action="store_true",
                        help="enable the OPTIONAL, NON-SOUND LLM baseline "
                             "(informational only; never affects the verdict "
                             "or exit code)")
    parser.add_argument("--llm-model", dest="llm_model", default=None,
                        help="LLM model name for the baseline [default: "
                             "gpt-4o-mini]")
    parser.add_argument("--llm-base-url", dest="llm_base_url", default=None,
                        help="OpenAI-compatible endpoint for the baseline "
                             "[default: $LLM_BASE_URL or api.openai.com]")
    args = parser.parse_args(argv)

    if args.list_targets:
        _print_registry()
        return EXIT_PROVEN

    if args.trifecta:
        if args.policy:
            print("ERROR: --trifecta and --policy are mutually exclusive",
                  file=sys.stderr)
            return EXIT_ERROR
        return _cmd_trifecta(args)

    if args.classify:
        return _cmd_classify(args)

    if args.policy:
        return _cmd_policy(args)

    if args.before or args.after:
        if not (args.before and args.after):
            print("ERROR: refinement needs both --before and --after",
                  file=sys.stderr)
            return EXIT_ERROR
        return _cmd_refine(args)

    if args.source_dir and args.target:
        parser.error("--source (build the IR from Java sources) and the "
                     "positional target are mutually exclusive")
    target_name = args.target or "correct"

    try:
        verdict = run(
            target_name=target_name,
            property_name=args.property_name,
            engine=args.engine,
            n=args.n,
            max_states=args.max_states,
            cegar_max_iter=args.cegar_max_iter,
            tlc_jar=args.tlc_jar,
            work_dir=args.work_dir,
            tlc_timeout=args.tlc_timeout,
            itf_trace=args.itf_trace,
            apalache_enabled=args.apalache,
            apalache_jar=args.apalache_jar,
            apalache_java=args.apalache_java,
            apalache_timeout=args.apalache_timeout,
            apalache_length=args.apalache_length,
            env_bound=args.env_bound,
            llm_enabled=args.llm_baseline,
            llm_model=args.llm_model,
            llm_base_url=args.llm_base_url,
            source_dir=args.source_dir,
            cpg_path=args.cpg_path,
            out_dir=args.out_dir,
            quiet=args.quiet,
        )
    except Exception as exc:
        print("ERROR: %s" % exc)
        return EXIT_ERROR

    return _exit_code(verdict)


if __name__ == "__main__":
    sys.exit(main())
