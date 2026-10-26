# -*- coding: utf-8 -*-
"""Phase 2 W3 tests: deterministic gated replay + conformance verdicts.

Run:
    python rot\\tests\\test_phase2_w3.py            # build if needed + replay + check
    python rot\\tests\\test_phase2_w3.py --skip-build

Exit codes: 0 = all pass, 1 = at least one failure.

Scope (W3 exit criteria):
  T1  full build + replay pipeline (build.ps1 -What replay) succeeds
  T2  buggy replay triple byte-identical (same schedule, 3 runs)
  T3  correct replay triple byte-identical
  T4  buggy and correct replay traces differ
  T5  buggy replay verdict NON-CONFORMANT (applied values disagree in trace)
  T6  correct replay verdict CONFORMANT (applied values agree in trace)
  T7  replay traces are deterministic-shaped (header format v1, stable run
      id, single thread "main", gap-free gseq, no timestamp fields)
  T8  invalid schedules rejected (n_steps mismatch, step gap, missing
      header, wrong format) by both schedulecheck and the Java gate
  T9  mismatched schedules rejected by the Java gate (structurally valid
      but semantically wrong: schedule says vote_1_no, participant votes yes)
  T10 infeasible schedules rejected (apply before decide, duplicate vote,
      unknown action) by both schedulecheck and the Java gate

Determinism basis: the replay driver is single-threaded ("main"), never
sleeps, and every gate action is consumed in schedule order; traces carry
stable run ids (-Drotn.probe.run), gap-free gseq/seq/lamport, and no
timestamps or random ids, so repeated replays are byte-identical.

If the replay trace files already exist the build step is skipped (same
convention as test_phase2_w2.py); delete twopc-java\\build to force a
fresh end-to-end run.
"""
from __future__ import print_function

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROT = os.path.join(ROOT, "rot")
TWOPC = os.path.join(ROOT, "twopc-java")
BUILD = os.path.join(TWOPC, "build")
BUILD_PWSH = os.path.join(TWOPC, "build.ps1")
CLASSES = os.path.join(BUILD, "classes")
PROBE_AGENT_JAR = os.path.join(BUILD, "probe-agent.jar")
SCHEDULE_BUGGY = os.path.join(BUILD, "schedule-buggy.jsonl")
REPLAY_BUGGY = [os.path.join(BUILD, "replay-buggy-%d.jsonl" % i) for i in (1, 2, 3)]
REPLAY_CORRECT = [os.path.join(BUILD, "replay-correct-%d.jsonl" % i) for i in (1, 2, 3)]

sys.path.insert(0, ROT)
import schedulecheck  # noqa: E402

FAILURES = []

_APPLIED_RE = re.compile(r"applied_(\d+)=(\S+)")
_TS_KEYS = ("ts", "timestamp", "time", "datetime", "epoch")


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


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest().upper()


def _events(path):
    records = []
    with io.open(path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if raw:
                records.append(json.loads(raw))
    assert records and records[0].get("_meta") == "rotn-probe-header", \
        "no probe header in %s" % path
    assert records[-1].get("_meta") == "rotn-probe-trailer", \
        "no probe trailer in %s" % path
    events = [r for r in records if "gseq" in r]
    assert events, "no events in %s" % path
    return records, events


def _applied_from_trace(path):
    """applied_<i> values from the SPEC payloads of a replay trace."""
    _, events = _events(path)
    applied = {}
    for ev in events:
        if ev.get("kind") != "SPEC":
            continue
        m = _APPLIED_RE.search(ev.get("payload") or "")
        if m:
            applied[int(m.group(1))] = m.group(2)
    return applied


# ---------------------------------------------------------------- T1 build --

def test_build_and_replay():
    if not os.path.exists(BUILD_PWSH):
        raise AssertionError("build.ps1 missing: %s" % BUILD_PWSH)
    traces = REPLAY_BUGGY + REPLAY_CORRECT
    skip = "--skip-build" in sys.argv
    need_build = (not skip) and not all(os.path.isfile(p) for p in traces)
    if need_build:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", BUILD_PWSH, "-What", "replay"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=ROOT)
        out, _ = proc.communicate(timeout=600)
        text = out.decode("utf-8", "replace")
        assert proc.returncode == 0, \
            "build.ps1 -What replay failed (exit %s)\n%s" % (proc.returncode, text)
        assert "W3 replay determinism PASS" in text, \
            "build output missing W3 PASS line\n%s" % text
    for p in traces:
        assert os.path.isfile(p) and os.path.getsize(p) > 0, \
            "missing/empty replay trace: %s" % p


# ----------------------------------------------------- T2-T4 byte identity --

def test_buggy_triple_byte_identical():
    h = [sha256(p) for p in REPLAY_BUGGY]
    assert len(set(h)) == 1, "buggy replay triple not byte-identical: %s" % ", ".join(h)
    print("   buggy   sha256 = %s" % h[0])


def test_correct_triple_byte_identical():
    h = [sha256(p) for p in REPLAY_CORRECT]
    assert len(set(h)) == 1, "correct replay triple not byte-identical: %s" % ", ".join(h)
    print("   correct sha256 = %s" % h[0])


def test_variants_differ():
    hb = sha256(REPLAY_BUGGY[0])
    hc = sha256(REPLAY_CORRECT[0])
    assert hb != hc, "buggy and correct replay traces are identical (unexpected)"


# --------------------------------------------------- T5/T6 verdicts (trace) --

def test_buggy_nonconformant():
    applied = _applied_from_trace(REPLAY_BUGGY[0])
    assert set(applied) == {1, 2}, \
        "buggy trace: expected both participants to apply, got %r" % applied
    assert applied[1] != applied[2], \
        "buggy trace: applied values %r do not show the disagreement bug" % applied
    print("   (buggy evidence: applied=%s -- agreement violated)" % applied)


def test_correct_conformant():
    applied = _applied_from_trace(REPLAY_CORRECT[0])
    assert set(applied) == {1, 2}, \
        "correct trace: expected both participants to apply, got %r" % applied
    assert applied[1] == applied[2], "correct trace: applied values %r disagree" % applied
    print("   (correct evidence: applied=%s -- agreement held)" % applied)


# ------------------------------------------------------- T7 deterministic --

def test_deterministic_shape():
    expected_run = {REPLAY_BUGGY[0]: "w3-buggy", REPLAY_CORRECT[0]: "w3-correct"}
    for path, run_id in sorted(expected_run.items()):
        records, events = _events(path)
        header, trailer = records[0], records[-1]
        assert header.get("format") == "v1", \
            "%s: header format %r" % (path, header.get("format"))
        assert header.get("run") == run_id, \
            "%s: header run id %r (expected %r)" % (path, header.get("run"), run_id)
        for k in _TS_KEYS:
            assert k not in header and k not in trailer, \
                "%s: nondeterministic field %r in header/trailer" % (path, k)
        prev_lp = None
        for i, ev in enumerate(events):
            for k in _TS_KEYS:
                assert k not in ev, \
                    "%s: nondeterministic field %r in event %d" % (path, k, ev["gseq"])
            assert ev["gseq"] == i, \
                "%s: event %d has gseq=%r" % (path, i, ev["gseq"])
            assert ev.get("thread") == "main", \
                "%s: event %d thread %r (expected 'main')" % (path, i, ev.get("thread"))
            assert ev["lamport"] >= ev["seq"], \
                "%s: event %d lamport %d must dominate seq %d" % (path, i, ev["lamport"], ev["seq"])
            if prev_lp is not None:
                assert ev["lamport"] > prev_lp, \
                    "%s: event %d lamport not strictly increasing" % (path, i)
            prev_lp = ev["lamport"]
        assert trailer.get("events") == len(events), \
            "%s: trailer events=%r but %d events present" % (path, trailer.get("events"), len(events))


# ------------------------------------------- T8-T10 schedule rejection -----

def find_java():
    c = shutil.which("javac") or shutil.which("java")
    if c:
        cand = os.path.join(os.path.dirname(c), "java.exe")
        if os.path.isfile(cand):
            return cand
    bases = [
        r"C:\Program Files\Eclipse Adoptium",
        r"C:\Program Files (x86)\Eclipse Adoptium",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Eclipse Adoptium"),
    ]
    for base in bases:
        if os.path.isdir(base):
            for d in sorted(os.listdir(base)):
                cand = os.path.join(base, d, "bin", "java.exe")
                if os.path.isfile(cand):
                    return cand
    raise AssertionError("java not found on PATH or under Eclipse Adoptium")


BASE_STEPS = [
    ("participant_1", "vote_1_yes"),
    ("participant_2", "vote_2_no"),
    ("coordinator", "decide"),
    ("participant_1", "apply_1"),
    ("participant_2", "apply_2"),
]


def _steps(pairs):
    return [{"owner": o, "action": a, "step": i} for i, (o, a) in enumerate(pairs)]


def _header(n_steps=None, pairs=None, **over):
    pairs = pairs if pairs is not None else BASE_STEPS
    h = {"_meta": "rotn-schedule", "format": "v1", "target": "buggy",
         "property": "agreement", "n": 2,
         "witness_path": [a for _, a in pairs],
         "n_steps": len(pairs) if n_steps is None else n_steps}
    h.update(over)
    return h


def write_schedule(dirpath, name, lines):
    path = os.path.join(dirpath, name + ".jsonl")
    with io.open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")
    return path


def run_replay(java, sched_path, trace_path):
    cmd = [java,
           "-javaagent:%s" % PROBE_AGENT_JAR,
           "-Drotn.probe.trace=%s" % trace_path,
           "-Drotn.probe.run=w3-rej",
           "-cp", CLASSES, "com.rot.n.demo.ReplayDemo", "buggy", sched_path]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=TWOPC)
    out, _ = proc.communicate(timeout=120)
    return proc.returncode, out.decode("utf-8", "replace")


def assert_rejected(case_name, lines, expect_check_invalid):
    """Write one fixture schedule, expect the Java gate to exit 20
    (REJECTED) and, when structurally broken, schedulecheck to say INVALID."""
    tmp = tempfile.mkdtemp(prefix="rotn-w3-sched-")
    sched = write_schedule(tmp, case_name, lines)
    trace = os.path.join(tmp, "trace.jsonl")
    java = find_java()
    exit_code, text = run_replay(java, sched, trace)
    assert exit_code == 20, \
        "%s: expected Java exit 20 (REJECTED), got %d\n%s" % (case_name, exit_code, text)
    ok, _check_lines = schedulecheck.check_file(sched)
    if expect_check_invalid:
        assert not ok, "%s: schedulecheck should flag the schedule INVALID" % case_name
    else:
        assert ok, "%s: schedulecheck should accept the structurally valid schedule" % case_name


def test_invalid_schedules_rejected():
    # (a) header n_steps does not match the step records
    assert_rejected("invalid-nsteps",
                    [_header(n_steps=6)] + _steps(BASE_STEPS),
                    expect_check_invalid=True)
    # (b) step numbers not 0-based consecutive (gap after step 1)
    gap = _steps(BASE_STEPS)
    for s in gap[2:]:
        s["step"] = s["step"] + 1
    assert_rejected("invalid-gap", [_header()] + gap, expect_check_invalid=True)
    # (c) no header record at all
    assert_rejected("invalid-noheader", _steps(BASE_STEPS), expect_check_invalid=True)
    # (d) wrong format version
    assert_rejected("invalid-format", [_header(format="v2")] + _steps(BASE_STEPS),
                    expect_check_invalid=True)


def test_mismatched_schedule_rejected():
    # Structurally valid, but participant_1 (canCommit=true) actually votes
    # yes while the schedule demands vote_1_no -> gate mismatch at step 0.
    pairs = [("participant_1", "vote_1_no")] + BASE_STEPS[1:]
    assert_rejected("mismatched-vote", [_header(pairs=pairs)] + _steps(pairs),
                    expect_check_invalid=False)


def test_infeasible_schedules_rejected():
    # (a) apply before the coordinator has decided (no DECISION in flight)
    pairs = [("participant_1", "vote_1_yes"),
             ("participant_2", "vote_2_no"),
             ("participant_1", "apply_1"),
             ("participant_2", "apply_2"),
             ("coordinator", "decide")]
    assert_rejected("infeasible-apply-first", [_header(pairs=pairs)] + _steps(pairs),
                    expect_check_invalid=True)
    # (b) duplicated gate step: participant_1 votes twice (no second ASK)
    pairs = [("participant_1", "vote_1_yes"),
             ("participant_1", "vote_1_yes"),
             ("participant_2", "vote_2_no"),
             ("coordinator", "decide"),
             ("participant_1", "apply_1"),
             ("participant_2", "apply_2")]
    assert_rejected("infeasible-dup-vote", [_header(pairs=pairs)] + _steps(pairs),
                    expect_check_invalid=True)
    # (c) action outside the gate vocabulary
    pairs = [("participant_1", "teleport")] + BASE_STEPS[1:]
    assert_rejected("infeasible-unknown-action", [_header(pairs=pairs)] + _steps(pairs),
                    expect_check_invalid=True)


def main():
    run_test("T1 build + gated replay pipeline", test_build_and_replay)
    if FAILURES:
        return _finish()
    run_test("T2 buggy replay triple byte-identical", test_buggy_triple_byte_identical)
    run_test("T3 correct replay triple byte-identical", test_correct_triple_byte_identical)
    run_test("T4 buggy and correct traces differ", test_variants_differ)
    run_test("T5 buggy replay NON-CONFORMANT (applied disagree)", test_buggy_nonconformant)
    run_test("T6 correct replay CONFORMANT (applied agree)", test_correct_conformant)
    run_test("T7 replay traces deterministic-shaped", test_deterministic_shape)
    run_test("T8 invalid schedules rejected", test_invalid_schedules_rejected)
    run_test("T9 mismatched schedules rejected", test_mismatched_schedule_rejected)
    run_test("T10 infeasible schedules rejected", test_infeasible_schedules_rejected)
    return _finish()


def _finish():
    total = 10
    passed = total - len(FAILURES)
    print("")
    print("W3 TESTS: %d/%d passed" % (passed, total))
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL W3 TESTS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

