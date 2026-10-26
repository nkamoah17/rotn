"""rot.crosscheck -- three-engine cross-check (SMT/Z3 + TLC + policy-direct).

A single engine can suffer a soundness leak: a solver bug, an encoding
mismatch, or an unsound abstraction can all let one engine mint a PROVEN
(or a VIOLATED) verdict on its own.  ``CrossChecker`` defends against
that by running the property on THREE engines and only issuing a
PROVEN/VIOLATED verdict when all three *agree*.  Any disagreement, or an
UNKNOWN/ERROR/UNSOUND answer from any engine, is conservatively
downgraded to UNKNOWN.

The three engines span two axes of independence:

* **Engine independence** -- SMT (Z3) and TLC are independent model
  checkers (different engines) over the *same* IR state-machine model.
* **Model independence** -- the policy-direct engine (``rot.policy_smt``)
  checks a *different model family*: a direct Z3 encoding of the policy
  obligation over a bounded event sequence, not the transition system.
  A soundness leak in one model family cannot hide a bug in the other.

An optional fourth engine -- Apalache's native model checker
(``rot.apalache``) -- can be enabled via ``cfg.apalache_enabled``.  Its
result is recorded in the per-run evidence and the curated report for
information, but it never participates in the join: the join stays a pure
function of the SMT, TLC, and policy-direct statuses.

This is deliberately opt-in (``engine="crosscheck"``): the Z3 backend
only supports Int/Bool domains, and TLC needs a jar, so it is not the
default path.  The join policy is a pure function of the three engines'
statuses, so it can be unit-tested without any engine installed.

Report layer
------------
``build_crosscheck_report`` curates one per-run report (the JSON the
pipeline writes for a ``--engine crosscheck`` run) into the stable
``crosscheck_report.json`` schema: per-engine statuses, *each* engine's
counterexample, the engine-vs-model independence distinction, the
agreement flag, and a slot for third-party *witnesses* (e.g. an Apalache
ITF counterexample trace replayed through ``rot.itf``).  ``add_witness``
appends a witness; ``main`` is the CLI::

    python -m rot.crosscheck out/policy-..._spendcap_within_cap.json \\
        --witness apalache-itf=trace.itf.json --out out/crosscheck_report.json

Witnesses are independent evidence: they are recorded alongside the three
engines but never participate in the join (no single witness can mint a
PROVEN/VIOLATED verdict).
"""
import json
import os
import sys

from . import verdicts as v

__all__ = ["CrossChecker", "join_status", "join_status3",
           "witness_match", "witness_match3", "REPORT_VERSION",
           "build_crosscheck_report", "add_witness",
           "format_side_by_side", "main"]

#: Schema version of the curated crosscheck report.
REPORT_VERSION = 1


def _norm(status):
    """Map an engine's raw status onto the join vocabulary."""
    if status == v.PROVEN:
        return v.PROVEN
    if status == v.VIOLATED:
        return v.VIOLATED
    return v.UNKNOWN  # unknown / error / unsound all collapse to UNKNOWN


def join_status(smt_status, tlc_status):
    """Join two engines' statuses into one verdict status.

    PROVEN requires BOTH engines to say PROVEN; VIOLATED requires both to
    say VIOLATED; anything else (disagreement, UNKNOWN, ERROR, UNSOUND)
    collapses to UNKNOWN.  No single engine can mint a decision alone.
    """
    s, t = _norm(smt_status), _norm(tlc_status)
    if s == v.PROVEN and t == v.PROVEN:
        return v.PROVEN
    if s == v.VIOLATED and t == v.VIOLATED:
        return v.VIOLATED
    return v.UNKNOWN


def join_status3(smt_status, tlc_status, policy_direct_status):
    """Join three engines' statuses into one verdict status.

    PROVEN requires ALL THREE engines to say PROVEN; VIOLATED requires all
    three to say VIOLATED; anything else (disagreement, UNKNOWN, ERROR,
    UNSOUND) collapses to UNKNOWN.  No single engine can mint a decision
    alone.

    This is the three-way join that adds the *model independence* axis:
    the SMT/Z3 and TLC engines check the IR state-machine model, while the
    policy-direct engine checks a *different model family* (a direct Z3
    encoding of the policy obligation).  A soundness leak in one model
    family cannot hide a bug in the other.
    """
    s = _norm(smt_status)
    t = _norm(tlc_status)
    p = _norm(policy_direct_status)
    if s == v.PROVEN and t == v.PROVEN and p == v.PROVEN:
        return v.PROVEN
    if s == v.VIOLATED and t == v.VIOLATED and p == v.VIOLATED:
        return v.VIOLATED
    return v.UNKNOWN


def _witness_fingerprint(witness):
    """Canonical, order-insensitive fingerprint of a counterexample state.

    Both engines report a violated state as a dict of state variables
    (e.g. ``{"completed": 0, "inflight": 3}``).  Two witnesses denote the
    *same attack state* iff their canonical JSON (keys sorted, non-JSON
    values coerced to strings) is identical -- independent of key order,
    dict type, or which engine produced it.  Returns ``None`` when
    ``witness`` is not a dict (a PROVEN run has no witness) so the caller
    can treat the match as N/A rather than a mismatch.
    """
    if not isinstance(witness, dict):
        return None
    try:
        return json.dumps(witness, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return None


def witness_match(smt_ce, tlc_witness, joined=None):
    """True iff BOTH engines point at the same attack state.

    ``smt_ce`` is the SMT counterexample, ``tlc_witness`` the TLC witness.
    When ``joined`` is supplied and is not ``VIOLATED`` the match is N/A and
    ``None`` is returned (a PROVEN/UNKNOWN run has no counterexample to
    compare).  This is the "two independent engines found the *same* path"
    claim, and it is a pure function of the two witnesses.
    """
    if joined is not None and joined != v.VIOLATED:
        return None
    a = _witness_fingerprint(smt_ce)
    b = _witness_fingerprint(tlc_witness)
    return (a is not None and b is not None and a == b)


def witness_match3(smt_ce, tlc_witness, policy_direct_witness, joined=None):
    """True iff ALL THREE engines point at the same attack state.

    ``smt_ce`` is the SMT counterexample, ``tlc_witness`` the TLC witness,
    and ``policy_direct_witness`` the policy-direct witness.  When
    ``joined`` is supplied and is not ``VIOLATED`` the match is N/A and
    ``None`` is returned (a PROVEN/UNKNOWN run has no counterexample to
    compare).  This is the "three independent engines found the *same*
    path" claim, and it is a pure function of the three witnesses.
    """
    if joined is not None and joined != v.VIOLATED:
        return None
    a = _witness_fingerprint(smt_ce)
    b = _witness_fingerprint(tlc_witness)
    c = _witness_fingerprint(policy_direct_witness)
    return (a is not None and b is not None and c is not None
            and a == b == c)


class CrossChecker:
    """Run a safety property on SMT (Z3), TLC, and the policy-direct engine;
    verdict only when ALL THREE agree.

    Parameters mirror the pipeline's safety dispatch: ``ir`` (the
    ``ProtocolIR`` the Z3 backend encodes), ``linear_model`` (the
    ``LinearModel`` TLC checks), ``prop`` (the ``Invariant`` under test)
    and ``cfg`` (engine config, used to locate the TLC jar).
    """

    def __init__(self, ir, linear_model, prop, cfg):
        self.ir = ir
        self.linear_model = linear_model
        self.prop = prop
        self.cfg = cfg

    # -- engine seams (patchable in tests) ---------------------------------
    def _smt_verdict(self):
        from .smtz3 import SMTBackend
        return SMTBackend(self.ir).verify_safety(self.prop)

    def _tlc_result(self):
        from .tlc import TlcEngine
        return TlcEngine(self.cfg).check(self.linear_model, self.prop)

    def _apalache_result(self):
        """Run Apalache (native MC) on the pinned property, if enabled.

        Returns an ``EngineResult`` (``status``/``note``/``n_states``/
        ``witness``), or ``None`` when Apalache is disabled (or there is no
        config).  This is an *informational* third engine: its result is
        recorded in the crosscheck evidence and the curated report, but it
        never feeds ``join_status`` (which stays a pure function of the SMT
        and TLC statuses).  A seam: tests stub this out to avoid needing
        the jar.
        """
        cfg = self.cfg
        if cfg is None or not getattr(cfg, "apalache_enabled", False):
            return None
        from .apalache import ApalacheEngine
        return ApalacheEngine(cfg).check(self.linear_model, self.prop)

    def _policy_direct_verdict(self):
        """Run the policy-direct Z3 engine on the pinned property.

        This is a *different model family* from the IR state-machine model
        checked by the SMT/Z3 and TLC engines: it encodes the policy
        obligation directly over a bounded event sequence (amounts as free
        bounded integers, the decision rule as the policy's guard), not the
        transition system.  The result is an ``EngineResult``.

        This is the *model independence* axis of the crosscheck: the same
        engine (Z3) checks a *different model*, so a soundness leak in one
        model family cannot hide a bug in the other.

        A seam: tests stub this out to avoid needing Z3.
        """
        from .policy_smt import policy_direct_check

        # Extract the policy parameters from the IR metadata.  The
        # policy-direct model is spendcap-specific; if the IR is not a
        # spendcap IR (no metadata), return UNKNOWN with a note.
        meta = getattr(self.ir, "metadata", None) or {}
        if "amount" not in meta or "cap" not in meta:
            from .symbolic import EngineResult, UNKNOWN
            return EngineResult(
                status=UNKNOWN,
                note="policy_direct: IR is not a spendcap IR; "
                     "the direct policy model does not apply")
        amount = meta.get("amount", 100)
        cap = meta.get("cap", 200)
        buggy = meta.get("buggy", False)
        max_inflight = meta.get("max_inflight", 4)
        return policy_direct_check(amount, cap, max_inflight, buggy)

    # -- join ---------------------------------------------------------------
    def check(self):
        smt = self._smt_verdict()
        tlc = self._tlc_result()
        apalache = self._apalache_result()
        policy_direct = self._policy_direct_verdict()
        joined = join_status3(smt.status, tlc.status, policy_direct.status)

        # Witness identity: when ALL THREE engines mint VIOLATED, do they
        # point at the SAME attack state?  This is the "three independent
        # engines found the same path" claim -- a pure function of the three
        # witnesses.  N/A (None) when the join is not VIOLATED (a PROVEN run
        # has no witness).
        w_match = witness_match3(
            smt.counterexample, tlc.witness, policy_direct.witness, joined)

        cross = {
            "policy": ("PROVEN/VIOLATED require ALL THREE engines to agree; "
                       "disagreement or UNKNOWN -> UNKNOWN"),
            "smt": {
                "engine": "smtz3",
                "model": "ir_state_machine",
                "status": smt.status,
                "normalized": _norm(smt.status),
                "note": smt.note,
                "counterexample": smt.counterexample,
            },
            "tlc": {
                "engine": "tlc",
                "model": "ir_state_machine",
                "status": tlc.status,
                "normalized": _norm(tlc.status),
                "note": tlc.note,
                "n_states": tlc.n_states,
                "complete": tlc.complete,
                "witness": tlc.witness,
            },
            # Model-independence third engine: a DIFFERENT model family
            # (direct Z3 encoding of the policy obligation, not the IR
            # state-machine).  Always present; feeds the join above.
            "policy_direct": {
                "engine": "policy_direct",
                "model": "direct_policy",
                "status": policy_direct.status,
                "normalized": _norm(policy_direct.status),
                "note": policy_direct.note,
                "witness": policy_direct.witness,
            },
            # Informational fourth engine: present only when
            # ``cfg.apalache_enabled``; never feeds the join above.
            "apalache": (
                {"engine": "apalache-mc",
                 "model": "ir_state_machine",
                 "status": apalache.status,
                 "note": apalache.note,
                 "n_states": apalache.n_states,
                 "witness": apalache.witness}
                if apalache is not None else None),
            "independence": {
                "engine": ("SMT/Z3, TLC, Apalache are independent model "
                           "checkers (different engines) over the IR "
                           "state-machine model"),
                "model": ("policy_direct is a different model family "
                          "(direct Z3 encoding of the policy obligation) "
                          "checked by the same Z3 engine -- a soundness "
                          "leak in one model family cannot hide a bug in "
                          "the other"),
            },
            "joined": joined,
            "witness_match": w_match,
        }

        evidence = dict(smt.evidence or {})
        evidence["crosscheck"] = cross

        # When all three agree the property is violated, prefer the SMT
        # counterexample (canonical, with a step-by-step trace); fall back
        # to TLC's witness if SMT had none.
        counterexample = None
        trace = None
        if joined == v.VIOLATED:
            counterexample = (smt.counterexample
                              if smt.counterexample is not None
                              else tlc.witness)
            trace = smt.trace

        notes = {
            v.PROVEN: ("cross-check: SMT (Z3), TLC, and policy-direct all "
                       "proved the invariant"),
            v.VIOLATED: ("cross-check: SMT (Z3), TLC, and policy-direct all "
                         "found a counterexample"),
            v.UNKNOWN: ("cross-check: engines disagree or one is UNKNOWN "
                        "(SMT=%s, TLC=%s, policy_direct=%s); no verdict "
                        "issued"
                        % (smt.status, tlc.status, policy_direct.status)),
        }

        return v.Verdict(
            status=joined,
            property_name=self.prop.name,
            engine="crosscheck",
            counterexample=counterexample,
            assumptions=[
                ("cross-check policy: PROVEN/VIOLATED require ALL THREE "
                 "engines (SMT/Z3, TLC, policy-direct) to agree"),
                "SMT (Z3) engine reported: %s" % smt.status,
                "TLC engine reported: %s" % tlc.status,
                "policy-direct engine reported: %s" % policy_direct.status,
            ],
            soundness=[
                "no PROVEN/VIOLATED is issued on a single engine's answer "
                "alone",
                "disagreement or UNKNOWN/ERROR on any engine forces UNKNOWN",
                ("model independence: policy_direct uses a different model "
                 "family (direct policy vs IR state-machine)"),
            ],
            evidence=evidence,
            note=notes[joined],
            property_kind=getattr(self.prop, "kind", v.KIND_SAFETY),
            trace=trace,
        )


# --------------------------------------------------------------------------
# Report layer: crosscheck_report.json + third-party witnesses + CLI
# --------------------------------------------------------------------------

def _agreement_note(smt_status, tlc_status, pd_status, joined, agree):
    if agree:
        return ("crosscheck: smtz3=%s tlc=%s policy_direct=%s -> %s "
                "(all three engines agree)"
                % (smt_status, tlc_status, pd_status, joined))
    return ("crosscheck: smtz3=%s tlc=%s policy_direct=%s -> %s "
            "(engines do not agree; no decision minted)"
            % (smt_status, tlc_status, pd_status, joined))


def build_crosscheck_report(run_report, witnesses=None):
    """Curate one per-run report into the ``crosscheck_report.json`` schema.

    ``run_report`` is the dict of one ``--engine crosscheck`` pipeline run
    (the shape of ``verdicts.VerdictReport.to_dict()``).  The result is a
    small, stable, purpose-built report:

    * ``engines``         -- per-engine status/note for smtz3, tlc,
      policy_direct and the optional apalache MC (all-``None`` fields when
      it was not run);
    * ``counterexamples`` -- the counterexample from *each* engine;
    * ``witnesses``       -- third-party witnesses (e.g. an Apalache ITF
      counterexample trace replayed through ``rot.itf``);
    * ``independence``    -- the engine-vs-model independence distinction:
      ``engine`` (SMT/Z3, TLC, Apalache are independent model checkers over
      the IR state-machine model) and ``model`` (policy_direct is a
      different model family -- a direct Z3 encoding of the policy
      obligation -- checked by the same Z3 engine);
    * ``agreement``       -- per-engine statuses (``apalache`` is
      informational and excluded from ``agree``), the joined verdict and
      the ``agree`` flag (True only when ALL THREE engines mint the same
      decision — a single engine can never mint a verdict on its own).
    """
    verdict = run_report.get("verdict") or {}
    cross = (verdict.get("evidence") or {}).get("crosscheck") or {}
    smt = cross.get("smt") or {}
    tlc = cross.get("tlc") or {}
    policy_direct = cross.get("policy_direct") or {}
    apalache = cross.get("apalache") or {}
    apalache_status = apalache.get("status")
    joined = cross.get("joined") or verdict.get("status")
    smt_norm = _norm(smt.get("status"))
    tlc_norm = _norm(tlc.get("status"))
    pd_norm = _norm(policy_direct.get("status"))
    agree = (smt_norm == tlc_norm == pd_norm
             and smt_norm in (v.PROVEN, v.VIOLATED))
    # Witness identity: when all three engines report VIOLATED, do they
    # point at the SAME attack state?  Computed here (from the three
    # counterexamples) so the curated report is self-contained; identical
    # to what ``CrossChecker.check()`` records in the per-run evidence.
    w_match = witness_match3(
        smt.get("counterexample"), tlc.get("witness"),
        policy_direct.get("witness"), joined)

    return {
        "report": "crosscheck",
        "version": REPORT_VERSION,
        "target": run_report.get("target"),
        "property": run_report.get("property_name"),
        "verdict": joined,
        "engines": {
            "smtz3": {
                "engine": smt.get("engine", "smtz3"),
                "model": smt.get("model", "ir_state_machine"),
                "status": smt.get("status"),
                "normalized": smt_norm,
                "note": smt.get("note"),
            },
            "tlc": {
                "engine": tlc.get("engine", "tlc"),
                "model": tlc.get("model", "ir_state_machine"),
                "status": tlc.get("status"),
                "normalized": tlc_norm,
                "note": tlc.get("note"),
                "n_states": tlc.get("n_states"),
                "complete": tlc.get("complete"),
            },
            "policy_direct": {
                "engine": policy_direct.get("engine", "policy_direct"),
                "model": policy_direct.get("model", "direct_policy"),
                "status": policy_direct.get("status"),
                "normalized": pd_norm,
                "note": policy_direct.get("note"),
            },
            "apalache": {
                "engine": apalache.get("engine", "apalache-mc"),
                "model": apalache.get("model", "ir_state_machine"),
                "status": apalache_status,
                "normalized": (_norm(apalache_status)
                               if apalache_status is not None else None),
                "note": apalache.get("note"),
                "n_states": apalache.get("n_states"),
            },
        },
        "counterexamples": {
            "smtz3": smt.get("counterexample"),
            "tlc": tlc.get("witness"),
            "policy_direct": policy_direct.get("witness"),
            "apalache": apalache.get("witness"),
        },
        "witnesses": list(witnesses or []),
        "independence": {
            "engine": ("SMT/Z3, TLC, Apalache are independent model "
                       "checkers (different engines) over the IR "
                       "state-machine model"),
            "model": ("policy_direct is a different model family (direct "
                      "Z3 encoding of the policy obligation) checked by "
                      "the same Z3 engine -- a soundness leak in one model "
                      "family cannot hide a bug in the other"),
        },
        "agreement": {
            "smtz3": smt.get("status"),
            "tlc": tlc.get("status"),
            "policy_direct": policy_direct.get("status"),
            # Informational only: Apalache never participates in the join,
            # so it is excluded from ``agree`` above.
            "apalache": apalache_status,
            "joined": joined,
            "agree": agree,
            "witness_match": w_match,
        },
        "note": _agreement_note(smt.get("status"), tlc.get("status"),
                                policy_direct.get("status"),
                                joined, agree),
    }


def add_witness(report, entry):
    """Append one third-party witness entry to a crosscheck report.

    A witness is independent evidence — e.g. an Apalache ITF
    counterexample trace replayed through ``rot.itf`` — that does NOT
    participate in the join; it is recorded alongside the three engines and
    the agreement flag.  ``entry`` must carry ``name`` and ``status``;
    ``note``/``counterexample``/``source``/``n_states`` are optional.
    """
    if not isinstance(entry, dict) or "name" not in entry \
            or "status" not in entry:
        raise ValueError("a witness entry needs at least 'name' and 'status'")
    record = {
        "name": entry["name"],
        "status": entry["status"],
        "note": entry.get("note"),
        "counterexample": entry.get("counterexample"),
        "source": entry.get("source"),
    }
    if entry.get("n_states") is not None:
        record["n_states"] = entry["n_states"]
    report.setdefault("witnesses", []).append(record)
    return report


def _fmt_ce(ce):
    if ce is None:
        return "-"
    try:
        return json.dumps(ce, sort_keys=True)
    except (TypeError, ValueError):
        return str(ce)


def format_side_by_side(report):
    """Render the compact engine x status x counterexample table."""
    engines = report.get("engines") or {}
    ces = report.get("counterexamples") or {}
    lines = [
        "Crosscheck  target=%s  property=%s"
        % (report.get("target"), report.get("property")),
        "  %-14s %-10s  %s" % ("engine", "status", "counterexample"),
    ]
    for key in ("smtz3", "tlc", "policy_direct"):
        eng = engines.get(key) or {}
        lines.append("  %-14s %-10s  %s"
                     % (key, eng.get("status"), _fmt_ce(ces.get(key))))
    ap_eng = engines.get("apalache") or {}
    if ap_eng.get("status") is not None:
        lines.append("  %-14s %-10s  %s   (informational; not in the join)"
                     % ("apalache", ap_eng.get("status"),
                        _fmt_ce(ces.get("apalache"))))
    for w in report.get("witnesses") or []:
        lines.append("  %-14s %-10s  %s   (witness)"
                     % (w.get("name"), w.get("status"),
                        _fmt_ce(w.get("counterexample"))))
    ag = report.get("agreement") or {}
    lines.append(
        "  %-14s smtz3=%s  tlc=%s  policy_direct=%s  joined=%s  -> %s"
        % ("agreement", ag.get("smtz3"), ag.get("tlc"),
           ag.get("policy_direct"), ag.get("joined"),
           "AGREE" if ag.get("agree") else "DISAGREE"))
    if ag.get("witness_match") is not None:
        lines.append(
            "  %-14s %s"
            % ("witness",
               "MATCH (all three engines -> same attack state)"
               if ag.get("witness_match") else
               "MISMATCH (engines found different states)"))
    return "\n".join(lines)


def _witness_from_itf(name, trace_path, property_name):
    """Replay an Apalache ITF trace against the pinned property.

    ``rot.itf`` is a sound refuter: a trace in which the invariant
    evaluates to a definite False yields ``violated`` with the offending
    state as the witness; a trace that never refutes it yields
    ``unknown`` (a single concrete path can never PROVE), and a
    structural parse failure yields ``error``.  All of these are recorded
    verbatim as the witness entry — the CLI never fails hard on an
    unconvincing witness.
    """
    from .invariants import get as get_invariant
    from .itf import ItfEngine
    prop = get_invariant(property_name)
    result = ItfEngine(None, trace_path=trace_path).check(None, prop)
    return {
        "name": name,
        "status": result.status,
        "n_states": result.n_states,
        "note": result.note,
        "counterexample": result.witness,
        "source": trace_path,
    }


def main(argv=None):
    """CLI: build ``crosscheck_report.json`` from a per-run crosscheck report.

    Usage::

        python -m rot.crosscheck RUN_REPORT.json \\
            [--witness NAME=ITF_JSON]... [--out FILE] [--quiet]

    ``RUN_REPORT.json`` is one per-run report written by an
    ``--engine crosscheck`` pipeline run.  Each ``--witness`` replaying an
    Apalache ITF trace (``.itf.json``) against the pinned property is
    appended to the report's ``witnesses`` list.  Returns 0 when the
    report was written, 2 on usage/parse/IO errors.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m rot.crosscheck",
        description=(
            "Build the curated crosscheck report (crosscheck_report.json) "
            "from one --engine crosscheck pipeline run, with optional "
            "third-party witnesses (Apalache ITF counterexample traces)."))
    parser.add_argument(
        "run_report",
        help="per-run report JSON from a --engine crosscheck run "
             "(e.g. out/policy-..._spendcap_within_cap.json)")
    parser.add_argument(
        "--witness", action="append", default=[], metavar="NAME=ITF_JSON",
        help="third-party witness: NAME=PATH to an Apalache ITF trace "
             "replayed against the pinned property (repeatable)")
    parser.add_argument(
        "--out", default=None, metavar="FILE",
        help="output path [default: <run-report dir>/crosscheck_report.json]")
    parser.add_argument(
        "--quiet", action="store_true",
        help="suppress the side-by-side table")
    args = parser.parse_args(argv)

    try:
        with open(args.run_report, "r") as f:
            run_report = json.load(f)
        property_name = run_report.get("property_name")
        if not property_name:
            raise ValueError("run report has no 'property_name'")
        report = build_crosscheck_report(run_report)
        for spec in args.witness:
            if "=" not in spec:
                raise ValueError("--witness must be NAME=ITF_JSON (got %r)"
                                 % spec)
            name, trace_path = spec.split("=", 1)
            if not name:
                raise ValueError("--witness NAME must not be empty")
            add_witness(report, _witness_from_itf(name, trace_path,
                                                  property_name))
    except (IOError, OSError, ValueError, KeyError) as exc:
        sys.stderr.write("ERROR: %s\n" % exc)
        return 2

    out = args.out
    if not out:
        out = os.path.join(
            os.path.dirname(os.path.abspath(args.run_report)),
            "crosscheck_report.json")
    try:
        out_dir = os.path.dirname(os.path.abspath(out))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        with open(out, "w") as f:
            f.write(json.dumps(report, indent=2))
    except (IOError, OSError) as exc:
        sys.stderr.write("ERROR: cannot write %s: %s\n" % (out, exc))
        return 2

    if not args.quiet:
        print(format_side_by_side(report))
        print("  report      : %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
