# -*- coding: utf-8 -*-
"""Test the W4 empirical-plane layer (rot.empirical) -- the "schedule -> run ->
check -> verdict artifact" orchestration that COMPOSES tracefmt + tracecheck +
schedulecheck (it reimplements none of them).

Soundness-first expectations:
  * correct trace        -> CONFORMANT      (exit 0)
  * buggy trace+schedule -> NON-CONFORMANT  (exit 10), target/property surfaced
  * missing trace        -> INCONCLUSIVE    (exit 20), refinement request
  * malformed schedule   -> REPORTED (schedule_ok False), not a crash, and by
                            itself does NOT force NON-CONFORMANT (no fake pass
                            AND no fake fail)
  * "run" runner seam    -> the injected runner is invoked with (trace, schedule);
                            a raising runner is REPORTED, never a crash
  * NEVER-REFINES        -> the plane never imports cegar/abstraction/pipeline/
                            modelfind (static guard passes; a violating module
                            is detected)

Run:  python rot/tests/test_phase2_w4_empirical.py
Exit: 0 = all pass, 1 = failure. Pure stdlib.
"""
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

try:
    from rot import tracefmt
    from rot import empirical
except ImportError:  # flat script context
    import tracefmt
    import empirical

_PASS = 0
_FAIL = 0
_FAILED = []


def run(label, fn):
    global _PASS, _FAIL
    try:
        fn()
        _PASS += 1
        print("  [PASS] %s" % label)
    except AssertionError as exc:
        _FAIL += 1
        _FAILED.append(label)
        print("  [FAIL] %s -- %s" % (label, exc))
    except Exception as exc:  # a crash is a failure, not a verdict
        _FAIL += 1
        _FAILED.append(label)
        print("  [FAIL] %s -- unexpected %s: %s" % (label, type(exc).__name__, exc))


def _repo_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _trace(name):
    path = os.path.join(_repo_root(), "twopc-java", "build", name)
    assert os.path.exists(path), "missing fixture: %s" % path
    return path


def T1_correct_trace_conformant():
    """A well-formed correct trace judges CONFORMANT (exit 0)."""
    trace = _trace("replay-correct-1.jsonl")
    res = empirical.run(trace)
    assert res.verdict == tracefmt.CONFORMANT, res.verdict
    assert res.exit_code == 0, res.exit_code
    assert res.conformant and not res.nonconformant and not res.inconclusive
    assert res.schedule_ok, res.schedule_errors
    assert res.invariants and all(r["status"] == "holds" for r in res.invariants)
    assert res.artifact and os.path.exists(res.artifact)
    with io.open(res.artifact, "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["verdict"] == tracefmt.CONFORMANT
    assert doc.get("refinement_request") is None  # no request when conformant


def T2_buggy_trace_nonconformant():
    """A buggy trace + its schedule judges NON-CONFORMANT (exit 10), surfacing
    the target/property from the schedule (not by inventing them)."""
    trace = _trace("replay-buggy-1.jsonl")
    sched = _trace("schedule-buggy.jsonl")
    res = empirical.run(trace, sched)
    assert res.verdict == tracefmt.NON_CONFORMANT, res.verdict
    assert res.exit_code == 10, res.exit_code
    assert res.nonconformant and not res.conformant
    assert any(r["status"] == "violated" for r in res.invariants)
    assert res.violations, "expected non-empty violations"
    assert res.target and res.property, (res.target, res.property)
    assert res.schedule_ok, res.schedule_errors
    with io.open(res.artifact, "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["verdict"] == tracefmt.NON_CONFORMANT
    assert doc.get("refinement_request") is None  # definite violation, not a request
    assert doc["violations"]


def T3_missing_trace_inconclusive():
    """A missing trace is INCONCLUSIVE (exit 20) -- never a crash, never a pass."""
    missing = os.path.join(tempfile.gettempdir(), "rotn_empirical_nope.jsonl")
    if os.path.exists(missing):
        os.remove(missing)
    res = empirical.run(missing)
    assert res.verdict == tracefmt.INCONCLUSIVE, res.verdict
    assert res.exit_code == 20, res.exit_code
    assert res.inconclusive and not res.conformant and not res.nonconformant
    with io.open(res.artifact, "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["verdict"] == tracefmt.INCONCLUSIVE
    req = doc.get("refinement_request")
    assert req and req["_meta"] == tracefmt.REFINEMENT_META
    assert req.get("reasons"), req
    if os.path.exists(res.artifact):
        os.remove(res.artifact)


def T4_malformed_schedule_reported_not_crash():
    """A malformed schedule is REPORTED (schedule_ok False), not a crash, and a
    bad schedule alone does NOT force NON-CONFORMANT: a good trace still judges
    CONFORMANT (no fake pass AND no fake fail)."""
    trace = _trace("replay-correct-1.jsonl")
    bad = os.path.join(tempfile.gettempdir(), "rotn_empirical_bad_schedule.jsonl")
    with io.open(bad, "w", encoding="utf-8") as f:
        f.write(json.dumps({"step": 1, "action": "gate"}) + "\n")

    # check_schedule surfaces the error
    ok, errors = empirical.check_schedule(bad)
    assert not ok, "malformed schedule should not be ok"
    assert errors, "expected schedule errors"

    # ...but judging the (correct) trace with it still yields CONFORMANT,
    # with the schedule problem surfaced, never a NON-CONFORMANT false fail.
    res = empirical.run(trace, bad)
    assert res.verdict == tracefmt.CONFORMANT, res.verdict
    assert not res.schedule_ok
    assert res.schedule_errors
    os.remove(bad)


def _boom(trace, schedule):
    raise RuntimeError("boom (simulated runner failure)")


def T5_runner_raise_reported_not_crash():
    """A runner that RAISES is reported in schedule_errors, never a crash; the
    judgement still proceeds (a good trace still judges CONFORMANT)."""
    trace = _trace("replay-correct-1.jsonl")
    res = empirical.run(trace, runner=_boom)
    assert res.verdict == tracefmt.CONFORMANT, res.verdict
    # the failure is REPORTED in schedule_errors (schedule_ok reflects the
    # schedule file, which was not supplied) -- never a crash, never swallowed
    assert any("runner raised" in e for e in res.schedule_errors), res.schedule_errors


def T6_runner_invoked_with_trace_and_schedule():
    """The runner seam is called with (trace, schedule) exactly."""
    trace = _trace("replay-correct-1.jsonl")
    sched = _trace("schedule-buggy.jsonl")
    seen = {}

    def _capture(trace_path, schedule_path):
        seen["t"] = trace_path
        seen["s"] = schedule_path

    empirical.run(trace, sched, runner=_capture)
    assert seen.get("t") == trace, seen
    assert seen.get("s") == sched, seen


def T7_never_refines_guard_passes():
    """The empirical plane never imports a forbidden formal-plane module."""
    hits = empirical.forbidden_imports()
    assert not hits, "unexpected forbidden imports: %s" % hits
    assert empirical.assert_no_refinement_imports() is True
    assert set(empirical.FORBIDDEN_MODULES) == {
        "rot.cegar", "rot.abstraction", "rot.pipeline", "rot.modelfind"}


def T8_never_refines_guard_detects_violation():
    """The static guard DETECTS a module that imports a forbidden formal-plane
    module (proving the scan is real, not a no-op)."""
    import types
    tmp = os.path.join(tempfile.gettempdir(), "rotn_empirical_badplane.py")
    with io.open(tmp, "w", encoding="utf-8") as f:
        f.write("import rot.cegar\n")
    name = "rotn_empirical_badplane"
    mod = types.ModuleType(name)
    mod.__file__ = tmp
    sys.modules[name] = mod
    try:
        hits = empirical.forbidden_imports((name,))
        assert name in hits, "guard should flag the violating module"
        assert any("cegar" in ln for ln in hits[name])
        # whole-identifier matching: 'cegar' is flagged, 'cegar_tools' is not
        assert empirical._line_imports_forbidden("import cegar")
        assert not empirical._line_imports_forbidden("import cegar_tools")
    finally:
        sys.modules.pop(name, None)
        if os.path.exists(tmp):
            os.remove(tmp)


def T9_result_shape_and_render():
    """EmpiricalResult exposes a stable shape, report_lines(), and render()."""
    trace = _trace("replay-correct-1.jsonl")
    res = empirical.run(trace)
    d = res.as_dict()
    for key in ("trace", "schedule", "verdict", "artifact", "invariants",
                "violations", "reasons", "target", "property", "exit_code",
                "schedule_ok", "schedule_errors"):
        assert key in d, "missing key %s" % key
    lines = res.report_lines()
    assert isinstance(lines, list) and lines
    assert all(isinstance(x, str) for x in lines)
    assert any("CONFORMANT" in x for x in lines)
    text = empirical.render(res)
    assert isinstance(text, str) and "agreement" in text
    # exit-code mapping is the verdict ladder
    assert empirical.exit_code(tracefmt.CONFORMANT) == 0
    assert empirical.exit_code(tracefmt.NON_CONFORMANT) == 10
    assert empirical.exit_code(tracefmt.INCONCLUSIVE) == 20


def T10_cli_exit_codes():
    """main() returns the verdict-ladder exit codes (and 2 for usage)."""
    correct = _trace("replay-correct-1.jsonl")
    buggy = _trace("replay-buggy-1.jsonl")
    sched = _trace("schedule-buggy.jsonl")
    assert empirical.main(["--guard"]) == 0
    assert empirical.main([correct]) == 0
    assert empirical.main([buggy, sched]) == 10
    assert empirical.main([]) == 2          # usage error
    assert empirical.main(["--help"]) == 2


def main():
    tests = [
        ("T1 correct trace -> CONFORMANT (exit 0)", T1_correct_trace_conformant),
        ("T2 buggy trace+schedule -> NON-CONFORMANT (exit 10)", T2_buggy_trace_nonconformant),
        ("T3 missing trace -> INCONCLUSIVE (exit 20)", T3_missing_trace_inconclusive),
        ("T4 malformed schedule reported, not a crash", T4_malformed_schedule_reported_not_crash),
        ("T5 runner raise reported, not a crash", T5_runner_raise_reported_not_crash),
        ("T6 runner invoked with (trace, schedule)", T6_runner_invoked_with_trace_and_schedule),
        ("T7 never-refines guard passes", T7_never_refines_guard_passes),
        ("T8 never-refines guard detects a violation", T8_never_refines_guard_detects_violation),
        ("T9 result shape + render + exit-code ladder", T9_result_shape_and_render),
        ("T10 CLI exit codes", T10_cli_exit_codes),
    ]
    print("W4 empirical-plane tests (schedule -> run -> check -> verdict)")
    for label, fn in tests:
        run(label, fn)
    print("----")
    print("passed=%d failed=%d" % (_PASS, _FAIL))
    if _FAIL:
        print("failed: %s" % ", ".join(_FAILED))
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())



