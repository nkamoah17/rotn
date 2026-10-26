# -*- coding: utf-8 -*-
"""Phase 2 W2 tests: probe trace emission + structural conformance.

Run:
    python rot\\tests\\test_phase2_w2.py            # build if needed + probe + check
    python rot\\tests\\test_phase2_w2.py --skip-build

Exit codes: 0 = all pass, 1 = at least one failure.

Scope (W2 exit criteria):
  T1  full build pipeline (probe agent + trace emission) succeeds
  T2  trace files exist and are non-empty (one file per run)
  T3  every line parses as JSON with header/trailer
  T4  gseq strictly monotone, 0-based, gap-free
  T5  lamport strictly monotone and dominates target seq (total order)
  T6  correct-variant trace: decision strictly before apply
  T7  buggy-variant trace: violation is visible (apply before decision)
      -- informational W1 evidence, must be present, not a failure
"""
from __future__ import print_function

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROT = os.path.join(ROOT, "rot")
TWOPC = os.path.join(ROOT, "twopc-java")
BUILD = os.path.join(TWOPC, "build")
TRACE_BUGGY = os.path.join(BUILD, "trace-buggy.jsonl")
TRACE_CORRECT = os.path.join(BUILD, "trace-correct.jsonl")
BUILD_PWSH = os.path.join(TWOPC, "build.ps1")

sys.path.insert(0, ROT)
import tracecheck  # noqa: E402

FAILURES = []


def run_test(name, fn):
    print("== %s" % name)
    try:
        fn()
        print("   PASS")
    except AssertionError as exc:
        print("   FAIL: %s" % exc)
        FAILURES.append(name)
    except Exception as exc:
        print("   ERROR: %s: %s" % (type(exc).__name__, exc))
        FAILURES.append(name)


def assert_trace_files_present():
    for p in (TRACE_BUGGY, TRACE_CORRECT):
        assert os.path.isfile(p), "missing trace file: %s" % p
        assert os.path.getsize(p) > 0, "empty trace file: %s" % p


def _events(path):
    records, errors = tracecheck.load_records(path)
    assert not errors, "parse errors in %s: %s" % (path, errors)
    assert records and records[0].get("_meta") == "rotn-probe-header", \
        "no header in %s" % path
    assert records[-1].get("_meta") == "rotn-probe-trailer", \
        "no trailer in %s" % path
    events = [r for r in records if "gseq" in r and "_meta" not in r]
    assert len(events) > 0, "no events in %s" % path
    return events


def test_build():
    if not os.path.exists(BUILD_PWSH):
        raise AssertionError("build.ps1 missing: %s" % BUILD_PWSH)
    need_build = ("--skip-build" not in sys.argv and not (
        os.path.isfile(TRACE_BUGGY) and os.path.isfile(TRACE_CORRECT)))
    if need_build:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", BUILD_PWSH, "-What", "probe"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=ROOT)
        out, _ = proc.communicate()
        text = out.decode("utf-8", "replace")
        assert proc.returncode == 0, \
            "build.ps1 -What probe failed (exit %s)\n%s" % (proc.returncode, text)
        assert "W2 probe trace emission PASS" in text, \
            "build output missing W2 PASS line\n%s" % text
    assert_trace_files_present()


def test_parse_and_structure():
    for p in (TRACE_BUGGY, TRACE_CORRECT):
        records, errors = tracecheck.load_records(p)
        assert not errors, "parse errors in %s: %s" % (p, errors)
        assert records[0].get("_meta") == "rotn-probe-header", "no header in %s" % p
        assert records[-1].get("_meta") == "rotn-probe-trailer", "no trailer in %s" % p
        events = [r for r in records if "gseq" in r and "_meta" not in r]
        assert len(events) >= 3, "suspiciously few events in %s: %d" % (p, len(events))
        assert records[-1].get("events") == len(events), \
            "trailer count mismatch in %s" % p


def test_gseq_monotone():
    for p in (TRACE_BUGGY, TRACE_CORRECT):
        events = _events(p)
        for i, ev in enumerate(events):
            assert ev["gseq"] == i, \
                "%s: event %d has gseq=%r (expected %d)" % (p, i, ev["gseq"], i)


def test_lamport_total_order():
    for p in (TRACE_BUGGY, TRACE_CORRECT):
        events = _events(p)
        prev = None
        for i, ev in enumerate(events):
            lp, s = ev["lamport"], ev["seq"]
            assert isinstance(lp, int) and isinstance(s, int), \
                "%s: event %d lamport/seq not integers" % (p, i)
            if prev is not None:
                assert lp > prev, \
                    "%s: event %d lamport %d not > previous %d" % (p, i, lp, prev)
            assert lp >= s, \
                "%s: event %d lamport %d must dominate seq %d" % (p, i, lp, s)
            prev = lp

def _decision_apply_index(path):
    events = _events(path)
    dec = None
    app = None
    for i, ev in enumerate(events):
        if ev.get("kind") != "SPEC":
            continue
        a = ev.get("action") or ""
        if a == "decide" and dec is None:
            dec = i
        if a.startswith("apply_") and app is None:
            app = i
    return dec, app


def test_correct_decision_before_apply():
    dec, app = _decision_apply_index(TRACE_CORRECT)
    assert dec is not None, "correct trace has no decision event"
    assert app is not None, "correct trace has no apply event"
    assert dec < app, "correct trace: decision@%s not before apply@%s" % (dec, app)


def test_buggy_violation_visible():
    dec, app = _decision_apply_index(TRACE_BUGGY)
    assert dec is not None, "buggy trace has no decision event"
    assert app is not None, "buggy trace has no apply event"
    assert app < dec, \
        "buggy trace should exhibit apply-before-decision (got decision@%s apply@%s)" \
        % (dec, app)
    print("   (W1 evidence confirmed: apply@%d precedes decision@%d)" % (app, dec))


def main():
    run_test("T1 build + trace emission", test_build)
    if FAILURES:
        return _finish()
    run_test("T2/T3 trace files parse, header/trailer, counts", test_parse_and_structure)
    run_test("T4 gseq strictly monotone (0-based, gap-free)", test_gseq_monotone)
    run_test("T5 lamport total order (strictly monotone, dominates seq)", test_lamport_total_order)
    run_test("T6 correct trace: decision before apply", test_correct_decision_before_apply)
    run_test("T7 buggy trace: violation visible", test_buggy_violation_visible)
    return _finish()


def _finish():
    print("")
    total = 7
    passed = total - len(FAILURES)
    print("W2 TESTS: %d/%d passed" % (passed, total))
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL W2 TESTS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
