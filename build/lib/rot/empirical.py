# -*- coding: utf-8 -*-
"""empirical.py -- Phase 2 W4: the empirical-plane orchestration layer.

This is the top-level, READ-ONLY entry point that turns a W3 2PC replay trace
into a deterministic conformance verdict + a verdict artifact. It COMPOSES the
three pure-stdlib modules below it and reimplements none of them:

    rot.tracefmt        v1 trace schema, normalization rules, verdict records
    rot.tracecheck      W4 conformance judge (verdict + deterministic artifact)
    rot.schedulecheck   the W3 replay-schedule contract (gate actions)

The pipeline -- "schedule -> run -> check -> verdict artifact" -- is split
across those modules so each concern stays unit-testable:

    schedule   check_schedule()     validate the W3 replay schedule (this module)
    run        run(runner=...)      seam where the W3 gated replay plugs in
    check      tracecheck.judge()   conformance over the trace (delegated)
    verdict    tracefmt.make_verdict / write_verdict_artifact (delegated)

"run" is a SEAM, not a black box: the production runner is the W3 gated replay
(twopc-java\\build.ps1 -What replay, or the -Empirical variant), which is what
actually spawns the JVM. The empirical plane itself stays pure stdlib and
read-only -- with the default runner=None it never spawns anything; it only
judges the trace file that was produced.

Soundness-first (inherited from tracefmt/tracecheck): only a DEFINITE invariant
violation yields NON-CONFORMANT; malformed/incomplete/missing evidence yields
INCONCLUSIVE (an explicit refinement REQUEST is embedded in the artifact --
never a crash, never a silent pass, never a fake CONFORMANT).

Verdict ladder (CI exit codes, via rot.tracefmt.verdict_exit_code):
    CONFORMANT      -> 0
    NON-CONFORMANT  -> 10
    INCONCLUSIVE    -> 20   (2 = usage error)

NEVER-REFINES: this module -- and the tracefmt/tracecheck modules it composes
-- must NOT import rot.cegar, rot.abstraction, rot.pipeline, or rot.modelfind.
Refinement is a Phase 1 (formal) concern reached only through the explicit
refinement-request artifact. The guard below makes that machine-checkable: a
static scan of the empirical-plane source plus a runtime canary over sys.modules.

Usage:
    python -m rot.empirical <trace.jsonl> [schedule.jsonl] [--json] [--out DIR]
    python -m rot.empirical --guard

Pure stdlib, Python 3.6 compatible (no f-strings, no dataclasses).
"""
from __future__ import print_function

import io
import json
import os
import re
import shutil
import sys

try:
    from . import tracefmt
    from . import tracecheck
    from . import schedulecheck
except ImportError:  # flat script context (python rot/empirical.py)
    import tracefmt
    import tracecheck
    import schedulecheck

__all__ = [
    "FORBIDDEN_MODULES",
    "EmpiricalResult",
    "check_schedule",
    "run",
    "report_lines",
    "render",
    "exit_code",
    "forbidden_imports",
    "refinement_canaries_loaded",
    "assert_no_refinement_imports",
    "main",
]

# The four formal-plane modules the empirical plane must never import. The
# dotted names are what the runtime canary looks for in sys.modules; the bare
# base names are what the static source scan matches on import lines.
FORBIDDEN_MODULES = (
    "rot.cegar",
    "rot.abstraction",
    "rot.pipeline",
    "rot.modelfind",
)
_FORBIDDEN_BASE = frozenset(m.split(".")[-1] for m in FORBIDDEN_MODULES)

# The empirical-plane modules whose source the never-refines guard scans.
_PLANE_MODULES = ("rot.tracefmt", "rot.tracecheck", "rot.empirical")

# Property-kind vocabulary carried on empirical records (Phase 6). Kept local
# and string-valued so the empirical plane stays independent of the formal
# plane (never-refines guard): the values mirror the formal plane's
# "safety" / "liveness" kinds without importing them.
_PROPERTY_KINDS = ("safety", "liveness")


class EmpiricalResult(object):
    """Structured outcome of one empirical-plane judgement.

    Carries the verdict, the deterministic artifact path, the invariant table,
    the (optional) schedule-contract status, the surfaced target/property, the
    (optional) property kind, and the CI exit code. Read-only over the trace:
    it never mutates the trace and never triggers any refinement -- it only
    reports and points at the verdict artifact.
    """

    def __init__(self, trace, schedule, verdict, artifact, invariants,
                 violations, reasons, target, property_name, exit_code,
                 schedule_ok, schedule_errors, property_kind=None):
        if property_kind is not None and property_kind not in _PROPERTY_KINDS:
            raise ValueError("bad property kind %r" % (property_kind,))
        self.trace = trace
        self.schedule = schedule
        self.verdict = verdict
        self.artifact = artifact
        self.invariants = list(invariants or [])
        self.violations = list(violations or [])
        self.reasons = list(reasons or [])
        self.target = target
        self.property = property_name
        self.exit_code = int(exit_code)
        self.schedule_ok = bool(schedule_ok)
        self.schedule_errors = list(schedule_errors or [])
        self.property_kind = property_kind

    @property
    def conformant(self):
        return self.verdict == tracefmt.CONFORMANT

    @property
    def nonconformant(self):
        return self.verdict == tracefmt.NON_CONFORMANT

    @property
    def inconclusive(self):
        return self.verdict == tracefmt.INCONCLUSIVE

    def as_dict(self):
        return {
            "trace": self.trace,
            "schedule": self.schedule,
            "verdict": self.verdict,
            "artifact": self.artifact,
            "invariants": self.invariants,
            "violations": self.violations,
            "reasons": self.reasons,
            "target": self.target,
            "property": self.property,
            "exit_code": self.exit_code,
            "schedule_ok": self.schedule_ok,
            "schedule_errors": self.schedule_errors,
            "property_kind": self.property_kind,
        }

    def report_lines(self):
        return report_lines(self)

    def __repr__(self):
        return ("EmpiricalResult(verdict=%r, exit_code=%r, target=%r)"
                % (self.verdict, self.exit_code, self.target))


# ------------------------------------------------------------- schedule step --

def check_schedule(schedule_path):
    """The "schedule" pipeline step: validate a W3 replay schedule.

    Delegates to rot.schedulecheck (load_schedule + check_schedule).
    Soundness-first: returns (ok, errors) and NEVER raises -- a missing or
    malformed schedule is reported as an error, not a crash, and a bad schedule
    alone does NOT by itself force a NON-CONFORMANT verdict.
    """
    try:
        header, steps, errors = schedulecheck.load_schedule(schedule_path)
    except Exception as exc:  # defensive: load_schedule is documented not to raise
        return False, ["schedule check raised: %s" % exc]
    if errors:
        return False, list(errors)
    if header is None:
        return False, ["no schedule header (_meta=rotn-schedule)"]
    try:
        ok, _lines, check_errors = schedulecheck.check_schedule(header, steps)
    except Exception as exc:
        return False, ["schedule check raised: %s" % exc]
    if check_errors:
        return False, list(check_errors)
    return bool(ok), []


# ------------------------------------------------------------- run + check ----

def run(trace_path, schedule_path=None, runner=None, property_kind=None):
    """Orchestrate one empirical-plane judgement: schedule -> run -> check.

    trace_path     path to a v1 replay trace (.jsonl).
    schedule_path  optional path to the W3 replay schedule; when given it is
                   validated by check_schedule (status surfaced in the result).
    runner         the "run" seam: optional callable runner(trace_path,
                   schedule_path). The W3 gated replay plugs in here; with the
                   default None the plane stays pure-stdlib/read-only and never
                   spawns the JVM.
    property_kind  optional property plane ("safety" / "liveness") surfaced in
                   the result and the report (Phase 6 verdict metadata).

    Returns an EmpiricalResult. Never raises on bad input: malformed or missing
    evidence degrades to an INCONCLUSIVE verdict with a refinement request.
    """
    schedule_ok, schedule_errors = True, []
    if schedule_path is not None:
        schedule_ok, schedule_errors = check_schedule(schedule_path)

    if runner is not None:
        try:
            runner(trace_path, schedule_path)
        except Exception as exc:  # a failing replay is reported, never a crash
            schedule_errors.append("runner raised: %s" % exc)

    # check -> verdict (delegated; judge is documented to never raise)
    try:
        verdict, artifact = tracecheck.judge(trace_path, schedule_path)
    except Exception as exc:
        verdict = tracefmt.make_verdict(
            tracefmt.INCONCLUSIVE, trace_path, schedule_path, [], [],
            ["empirical plane: judge raised unexpectedly: %s" % exc])
        artifact = tracecheck.verdict_artifact_path(trace_path)
        try:
            tracefmt.write_verdict_artifact(artifact, verdict)
        except Exception:
            artifact = None

    return EmpiricalResult(
        trace=trace_path,
        schedule=schedule_path,
        verdict=verdict["verdict"],
        artifact=artifact,
        invariants=verdict.get("invariants", []),
        violations=verdict.get("violations", []),
        reasons=verdict.get("reasons", []),
        target=verdict.get("target"),
        property_name=verdict.get("property"),
        exit_code=tracefmt.verdict_exit_code(verdict["verdict"]),
        schedule_ok=schedule_ok,
        schedule_errors=schedule_errors,
        property_kind=property_kind,
    )


def exit_code(verdict):
    """CI exit code for a verdict name (0 / 10 / 20). Thin wrapper over tracefmt."""
    return tracefmt.verdict_exit_code(verdict)


def report_lines(result):
    """Human-readable, one-section report for an EmpiricalResult.

    Deterministic ordering (fixed field order; invariant order preserved) so the
    report is stable across runs -- matching the artifact's timestamp-free,
    byte-stable contract.
    """
    out = ["[W4 empirical] %s" % result.trace]
    out.append("  pipeline: schedule -> run -> check -> verdict")
    out.append("  verdict: %-16s (exit %d)" % (result.verdict, result.exit_code))
    out.append("  target: %s   property: %s" % (result.target, result.property))
    if getattr(result, "property_kind", None):
        out.append("  property kind: %s" % result.property_kind)

    if result.schedule:
        out.append("  schedule: %s  ->  %s"
                   % (result.schedule, "ok" if result.schedule_ok else "MALFORMED"))
        for err in result.schedule_errors:
            out.append("    schedule ERROR: %s" % err)
    else:
        out.append("  schedule: (none supplied)")

    if result.invariants:
        out.append("  invariants:")
        for rec in result.invariants:
            out.append("    %-20s %-8s  (%s)"
                       % (rec.get("name"), rec.get("status"), rec.get("evidence")))
    else:
        out.append("  invariants: (none evaluated)")

    for reason in result.reasons:
        out.append("  - " + reason)

    if result.inconclusive:
        out.append("  refinement request embedded in the verdict artifact "
                   "(INCONCLUSIVE is a request, not a failure)")
    if result.artifact:
        out.append("  verdict artifact: %s" % result.artifact)
    return out


def render(result):
    """The report as a single newline-joined string."""
    return "\n".join(report_lines(result))


# ----------------------------------------------------------- never-refines ----

def _line_imports_forbidden(line):
    """True if an import/from line references a forbidden formal-plane module.

    Whole-identifier (token) matching, so 'cegar' matches but 'cegar_tools'
    does not -- no false positives on longer names.
    """
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", line)
    return any(t in _FORBIDDEN_BASE for t in tokens)


def forbidden_imports(module_names=_PLANE_MODULES):
    """Static never-refines scan of the empirical plane.

    Returns {module_name: [offending import lines]} for any plane module whose
    source contains an import/from line referencing a forbidden formal-plane
    module. An empty dict means the guard passes.
    """
    hits = {}
    for name in module_names:
        mod = sys.modules.get(name)
        if mod is None or not getattr(mod, "__file__", None):
            continue
        try:
            with io.open(mod.__file__, "r", encoding="utf-8") as f:
                text = f.read()
        except (IOError, OSError, UnicodeDecodeError):
            continue
        bad = []
        for raw in text.splitlines():
            line = raw.strip()
            if not (line.startswith("import ") or line.startswith("from ")):
                continue
            if _line_imports_forbidden(line):
                bad.append(line)
        if bad:
            hits[name] = bad
    return hits


def refinement_canaries_loaded():
    """Runtime canary: which forbidden modules are currently loaded.

    In a shared interpreter that has also exercised Phase 1 these may be present
    even though the empirical plane never imports them; this is informational,
    not a guard failure (the static scan is the authoritative check for the
    plane's own source).
    """
    loaded = set()
    for m in FORBIDDEN_MODULES:
        if m in sys.modules or m.split(".")[-1] in sys.modules:
            loaded.add(m)
    return sorted(loaded)


def assert_no_refinement_imports():
    """Machine-check the NEVER-REFINES invariant (static source scan).

    Raises AssertionError if any empirical-plane module imports a forbidden
    formal-plane module. Returns True on success.
    """
    hits = forbidden_imports()
    assert not hits, "NEVER-REFINES violated (static scan): %s" % hits
    return True


# ----------------------------------------------------------------------- CLI --

_USAGE = (
    "usage: python -m rot.empirical <trace.jsonl> [schedule.jsonl] "
    "[--json] [--out DIR]\n"
    "       python -m rot.empirical --guard\n\n"
    "  Judge a W3 2PC replay trace against the W4 invariants and write the\n"
    "  deterministic, timestamp-free verdict artifact <trace>.verdict.json.\n\n"
    "Exit codes: 0 = CONFORMANT, 10 = NON-CONFORMANT, 20 = INCONCLUSIVE\n"
    "(2 = usage error). The empirical plane is read-only and NEVER-REFINES:\n"
    "it may emit a refinement request, but never triggers CEGAR/pipeline."
)


def main(argv):
    """CLI entry point. Returns a process exit code (caller does sys.exit)."""
    args = list(argv)
    as_json = False
    guard = False
    out_dir = None
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--json", "-j"):
            as_json = True
        elif a == "--guard":
            guard = True
        elif a == "--out":
            i += 1
            if i >= len(args):
                print(_USAGE)
                return 2
            out_dir = args[i]
        elif a in ("--help", "-h"):
            print(_USAGE)
            return 2
        elif a.startswith("--"):
            print("unknown option: %s" % a)
            print(_USAGE)
            return 2
        else:
            positional.append(a)
        i += 1

    if guard:
        try:
            assert_no_refinement_imports()
        except AssertionError as exc:
            print("GUARD FAIL: %s" % exc)
            return 1
        print("GUARD OK: empirical plane never imports refinement "
              "(cegar/abstraction/pipeline/modelfind)")
        loaded = refinement_canaries_loaded()
        if loaded:
            print("  note: refinement canaries already loaded in this "
                  "interpreter: %s" % ", ".join(loaded))
        return 0

    if len(positional) not in (1, 2):
        print(_USAGE)
        return 2

    trace = positional[0]
    sched = positional[1] if len(positional) == 2 else None
    res = run(trace, sched)
    for line in report_lines(res):
        print(line)

    if as_json and res.artifact and os.path.exists(res.artifact):
        with io.open(res.artifact, "r", encoding="utf-8") as f:
            doc = json.load(f)
        print(json.dumps(doc, indent=2, sort_keys=True))

    if out_dir and res.artifact and os.path.exists(res.artifact):
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        dst = os.path.join(out_dir, os.path.basename(res.artifact))
        shutil.copyfile(res.artifact, dst)
        print("  artifact copied: %s" % dst)

    return res.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

