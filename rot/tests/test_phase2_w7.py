# -*- coding: utf-8 -*-
"""Phase 2 W7 -- minimal logging-policy optimizer: acceptance tests.

Self-contained tests for rot.logpolicy (pure stdlib) plus the end-to-end
Java pipeline that consumes the policy via the probe agent property
``-Drotn.probe.filter`` (Probe.java reads it, see logpolicy.AGENT_PROPERTY).

    T1  policy_document is minimal + deterministic: all three W4 obligations
        require only SPEC; SEND/RECV disabled; cost = 1.0; digest stable
        across repeated derivations; agent property/value exact
    T2  digest sensitivity: same inputs -> same digest; different weights or
        different obligations -> different digest
    T3  error handling: unknown obligation / unknown weight class raise
        PolicyError (never a crash)
    T4  trace<->policy consistency: a full W3 replay trace is consistent with
        an all-classes policy but INCONSISTENT with the SPEC-only minimal
        policy (it records disabled SEND/RECV events)
    T5  a structurally valid trace with NO SPEC events violates the
        'agreement' obligation (verdict would be INCONCLUSIVE, never definite)
    T6  malformed trace: check reports problems, never raises
    T7  CLI: derive --json/--out byte-deterministic; check exit codes
        0 = consistent, 1 = inconsistent, 2 = usage error
    T8  end-to-end (Java): ReplayDemo with -Drotn.probe.filter=SPEC records
        ONLY SPEC events; gseq 0-based gap-free; W2 structural gate passes;
        W4 verdict unchanged (buggy NON-CONFORMANT exit 10, correct
        CONFORMANT exit 0); triple byte-identical; logpolicy check consistent
    T9  W6Bench recording-cost demo: the same workload records every event
        without the policy filter and ZERO events with SPEC-only (W6Bench
        emits only SEND/RECV transport events)

NEVER-REFINES: the W7 layer only derives a policy and checks traces against
it; it does not import rot.cegar / rot.abstraction / rot.pipeline / modelfind.

Run:  python rot\tests\test_phase2_w7.py
Exit codes: 0 all pass, 1 failure, 2 environment/usage.
"""

from __future__ import print_function

import json
import os
import shutil
import subprocess
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from rot import logpolicy  # noqa: E402
from rot import tracefmt  # noqa: E402

BUILD = os.path.join(_REPO_ROOT, "twopc-java", "build")
CLASSES = os.path.join(BUILD, "classes")
PROBE_AGENT_JAR = os.path.join(BUILD, "probe-agent.jar")
SCHEDULE = os.path.join(BUILD, "schedule-buggy.jsonl")
BUGGY_TRACE = os.path.join(BUILD, "replay-buggy-1.jsonl")
CORRECT_TRACE = os.path.join(BUILD, "replay-correct-1.jsonl")

# The W3 replay traces are the acceptance fixtures; they are produced by
# twopc-java\build.ps1 -What replay (see test_phase2_w3.py).
_REQUIRED = (CLASSES, PROBE_AGENT_JAR, SCHEDULE, BUGGY_TRACE, CORRECT_TRACE)

OBLIGATIONS = ("agreement", "validity", "decision_before_apply")


def _check_env():
    missing = [p for p in _REQUIRED if not os.path.exists(p)]
    if missing:
        print("W7 fixture missing: %s" % missing)
        print("run first:  cd twopc-java ; .\\build.ps1 -What replay")
        sys.exit(2)



# ------------------------------------------------------------ trace builder --

def _build(path, run_id, events, trailer=None):
    """Write a v1 trace file (header + events + trailer) deterministically."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        header = {"_meta": tracefmt.HEADER_META, "format": tracefmt.FORMAT,
                  "run": run_id, "w7-test": "synthetic"}
        f.write(json.dumps(header, separators=(",", ":")) + "\n")
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")
        if trailer is None:
            trailer = {"_meta": tracefmt.TRAILER_META,
                       "events": len(events),
                       "last_gseq": len(events) - 1}
        f.write(json.dumps(trailer, separators=(",", ":")) + "\n")
    return path


def _event(i, kind, actor="coordinator"):
    return {"gseq": i, "seq": i, "lamport": i + 1, "actor": actor,
            "thread": "main", "kind": kind,
            "action": "send_" + kind.lower(),
            "payload": kind.lower() + " " + str(i)}


# ------------------------------------------------------------------- T1 ----

def T1_minimal_and_deterministic():
    d1 = logpolicy.policy_document(OBLIGATIONS)
    d2 = logpolicy.policy_document(list(OBLIGATIONS))
    assert d1["format"] == logpolicy.FORMAT
    assert d1["enabled"] == ["SPEC"], d1["enabled"]
    assert sorted(d1["disabled"]) == ["RECV", "SEND"], d1["disabled"]
    assert d1["cost"]["total"] == 1.0, d1["cost"]
    assert d1["cost"]["enabled_classes"] == 1
    assert d1["cost"]["total_classes"] == 3
    # requirement map: every obligation is justified by SPEC alone
    for o in OBLIGATIONS:
        assert d1["requirement"][o] == ["SPEC"], (o, d1["requirement"])
    # the exact agent hook the Java probe consumes
    assert d1["agent"]["property"] == "rotn.probe.filter"
    assert d1["agent"]["value"] == "SPEC"
    # digest: sha256 of canonical content, stable across derivations
    assert d1["digest"].startswith("sha256:")
    assert d1["digest"] == d2["digest"], "digest not deterministic"
    assert d1 == d2, "policy document not deterministic"
    print("T1 OK  policy minimal (SPEC only) + deterministic: digest=%s..."
          % d1["digest"][:20])



# ------------------------------------------------------------------- T2 ----

def T2_digest_sensitivity():
    base = logpolicy.policy_document(OBLIGATIONS)
    # same content, different argument shape -> same digest
    same = logpolicy.policy_document(["agreement", "validity",
                                     "decision_before_apply"])
    assert same["digest"] == base["digest"]
    # different obligations -> different digest
    one = logpolicy.policy_document(["agreement"])
    assert one["digest"] != base["digest"]
    # different weights -> different digest (weights are content)
    heavy = logpolicy.policy_document(OBLIGATIONS, {"SPEC": 2.0})
    assert heavy["digest"] != base["digest"]
    assert heavy["cost"]["total"] == 2.0
    # weights do not change the minimal class set here (SPEC is required)
    assert heavy["enabled"] == ["SPEC"]
    print("T2 OK  digest: stable on identical inputs, sensitive to "
          "obligations and weights")


# ------------------------------------------------------------------- T3 ----

def T3_error_handling():
    try:
        logpolicy.derive_policy(["bogus_obligation"])
        raise AssertionError("unknown obligation did not raise")
    except logpolicy.PolicyError:
        pass
    try:
        logpolicy.policy_document(["agreement"], {"NOPE": 1.0})
        raise AssertionError("unknown weight class did not raise")
    except logpolicy.PolicyError:
        pass
    # empty obligations: nothing required -> nothing recorded (log nothing)
    d = logpolicy.policy_document([])
    assert d["enabled"] == [], d["enabled"]
    assert d["cost"]["total"] == 0.0
    assert d["agent"]["value"] == ""
    # obligation names are case/space-insensitive but must be known
    d = logpolicy.policy_document([" Agreement ", "validity"])
    assert "agreement" in d["obligations"]
    print("T3 OK  unknown obligation / weight / empty input raise PolicyError")




# ------------------------------------------------------------------- T4 ----

def T4_trace_policy_consistency():
    all_doc = {"format": "v1", "enabled": ["SEND", "RECV", "SPEC"],
               "obligations": list(OBLIGATIONS)}
    spec_doc = logpolicy.policy_document(OBLIGATIONS)
    # a full W3 trace records SEND/RECV/SPEC: consistent with the all-doc...
    ok, problems = logpolicy.check_trace_against_policy(
        all_doc, CORRECT_TRACE)
    assert ok, problems
    # ...but INCONSISTENT with the minimal SPEC-only policy (it records
    # disabled SEND/RECV events).
    ok, problems = logpolicy.check_trace_against_policy(
        spec_doc, CORRECT_TRACE)
    assert not ok, "full trace must violate the SPEC-only policy"
    joined = " ".join(problems)
    assert "SEND" in joined and "RECV" in joined, problems
    assert "disabled" in joined, problems
    print("T4 OK  full trace vs SPEC-only policy: %d problem(s) "
          "(disabled SEND/RECV surfaced)" % len(problems))


# ------------------------------------------------------------------- T5 ----

def T5_spec_absent_violates_obligation(tmp):
    # structurally valid trace, but only SEND/RECV: no SPEC events at all.
    p = _build(os.path.join(tmp, "no-spec.jsonl"), "w7-no-spec",
               [_event(0, "SEND", "coordinator"),
                _event(1, "RECV", "participant_1"),
                _event(2, "SEND", "coordinator")])
    doc = logpolicy.policy_document(["agreement"])
    ok, problems = logpolicy.check_trace_against_policy(doc, p)
    assert not ok, "SPEC-less trace must be inconsistent with 'agreement'"
    joined = " ".join(problems)
    assert "agreement" in joined and "SPEC" in joined, problems
    assert "INCONCLUSIVE" in joined, problems
    print("T5 OK  SPEC-less trace: obligation 'agreement' unmet -> "
          "INCONCLUSIVE flagged, never a definite verdict")


# ------------------------------------------------------------------- T6 ----

def T6_malformed_trace_never_raises(tmp):
    p = os.path.join(tmp, "garbage.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write("this is not json at all\n")
        f.write("{broken\n")
        f.write('{"_meta": "rotn-probe-trailer", "events": 0}\n')
    doc = logpolicy.policy_document(["agreement"])
    ok, problems = logpolicy.check_trace_against_policy(doc, p)
    assert not ok, "garbage trace must be inconsistent"
    joined = " ".join(problems).lower()
    assert "parse" in joined, problems
    assert "header" in joined, problems
    print("T6 OK  malformed trace: no crash, problems reported: %s"
          % problems[0])


# ------------------------------------------------------------------- T7 ----

def _run_cli(args):
    proc = subprocess.Popen([sys.executable, "-m", "rot.logpolicy"] + args,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=_REPO_ROOT)
    out, _ = proc.communicate(timeout=60)
    return proc.returncode, out.decode("utf-8", "replace")


def T7_cli():
    tmp = tempfile.mkdtemp(prefix="rotn_w7_cli_")
    try:
        pol1 = os.path.join(tmp, "policy1.json")
        pol2 = os.path.join(tmp, "policy2.json")
        rc, out = _run_cli(["derive", "--obligations",
                            ",".join(OBLIGATIONS), "--out", pol1])
        assert rc == 0, (rc, out)
        rc, out = _run_cli(["derive", "--obligations",
                            ",".join(OBLIGATIONS), "--json", "--out", pol2])
        assert rc == 0, (rc, out)
        # --json stdout is a parseable policy document, identical to --out
        doc_stdout = json.loads(out[out.index("{"):])
        with open(pol2, "r", encoding="utf-8") as f:
            doc_file = json.load(f)
        assert doc_stdout == doc_file
        # byte-deterministic policy files
        assert open(pol1, "rb").read() == open(pol2, "rb").read()
        # bare form (no subcommand) is derive
        rc, out = _run_cli(["--obligations", ",".join(OBLIGATIONS)])
        assert rc == 0, (rc, out)
        assert "W7 policy" in out and "rotn.probe.filter=SPEC" in out, out

        # check: exit 1 inconsistent (full trace vs SPEC-only policy)...
        rc, out = _run_cli(["check", "--policy", pol1,
                            "--trace", CORRECT_TRACE])
        assert rc == 1, (rc, out)
        assert "INCONSISTENT" in out
        # ...exit 0 consistent (all-classes policy)...
        all_pol = os.path.join(tmp, "policy-all.json")
        all_doc = {"format": "v1", "enabled": ["SEND", "RECV", "SPEC"],
                   "obligations": list(OBLIGATIONS)}
        with open(all_pol, "w", encoding="utf-8") as f:
            json.dump(all_doc, f)
        rc, out = _run_cli(["check", "--policy", all_pol,
                            "--trace", CORRECT_TRACE])
        assert rc == 0, (rc, out)
        assert "CONSISTENT" in out
        # ...exit 2 usage error (missing policy file / unknown obligation)
        rc, out = _run_cli(["check", "--policy",
                            os.path.join(tmp, "missing.json"),
                            "--trace", CORRECT_TRACE])
        assert rc == 2, (rc, out)
        rc, out = _run_cli(["derive", "--obligations", "bogus"])
        assert rc == 2, (rc, out)
        print("T7 OK  CLI derive/check: exit 0/1/2, byte-deterministic "
              "policy files, --json matches --out")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
# ============================================================ T8 (2026-10) --
# End-to-end: filtered replay through the real Java pipeline. Runs the W3
# ReplayDemo with -Drotn.probe.filter=SPEC (the W7 agent value) and asserts
# the recorded trace contains ONLY SPEC events while the W2 structural gate
# and the W4 judgment stay exactly as in W3.

def _find_java():
    """Locate java.exe (PATH first, then Temurin install dirs)."""
    try:
        out = subprocess.check_output(
            ["where", "java"], stderr=subprocess.STDOUT, timeout=20)
        first = out.decode("utf-8", "replace").strip().splitlines()[0]
        if os.path.isfile(first):
            return first
    except Exception:
        pass
    for base in (os.path.join(os.environ.get("ProgramFiles", ""),
                              "Eclipse Adoptium"),
                 os.path.join(os.environ.get("ProgramFiles(x86)", ""),
                              "Eclipse Adoptium"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""),
                              "Programs", "Eclipse Adoptium")):
        if not base or not os.path.isdir(base):
            continue
        for d in sorted(os.listdir(base)):
            cand = os.path.join(base, d, "bin", "java.exe")
            if os.path.isfile(cand):
                return cand
    raise EnvironmentError("java not found -- install Temurin JDK 11 first")


def _run_filtered_replay(java, variant, trace_path, run_id):
    """Run ReplayDemo with the W7 SPEC-only probe filter. Returns (exit, out)."""
    cmd = [java, "-javaagent:" + PROBE_AGENT_JAR,
           "-Drotn.probe.trace=" + trace_path,
           "-Drotn.probe.run=" + run_id,
           "-Drotn.probe.filter=SPEC",
           "-cp", CLASSES, "com.rot.n.demo.ReplayDemo",
           variant, SCHEDULE]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=180)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _read_events(path):
    """(header, events, trailer) from a JSONL trace file."""
    recs = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                recs.append(json.loads(ln))
    header = recs[0] if recs and recs[0].get("_meta") == tracefmt.HEADER_META \
        else None
    trailer = recs[-1] if recs and recs[-1].get("_meta") == tracefmt.TRAILER_META \
        else None
    events = [r for r in recs if r.get("_meta") not in
              (tracefmt.HEADER_META, tracefmt.TRAILER_META)]
    return header, events, trailer

def T8_end_to_end_filtered_replay(tmp):
    """W7 acceptance: SPEC-only replay trace, W2 gate + W4 judgment unchanged."""
    java = _find_java()
    doc = logpolicy.policy_document(OBLIGATIONS)
    filter_val = doc["agent"]["value"]
    assert filter_val == "SPEC", "W7 agent filter must be SPEC"
    tb = os.path.join(tmp, "w7-buggy.jsonl")
    tc = os.path.join(tmp, "w7-correct.jsonl")
    rc_b, out_b = _run_filtered_replay(java, "buggy", tb, "w7-buggy")
    assert rc_b == 10, "buggy replay must exit 10, got %d\n%s" % (rc_b, out_b)
    assert "W3 VERDICT: NON-CONFORMANT" in out_b, out_b
    rc_c, out_c = _run_filtered_replay(java, "correct", tc, "w7-correct")
    assert rc_c == 0, "correct replay must exit 0, got %d\n%s" % (rc_c, out_c)
    assert "W3 VERDICT: CONFORMANT" in out_c, out_c
    for path, expect_verdict in ((tb, "NON-CONFORMANT"), (tc, "CONFORMANT")):
        header, events, trailer = _read_events(path)
        assert header is not None, "missing header in %s" % path
        assert header.get("filter") == "SPEC", \
            "header must record the W7 filter, got %r" % header.get("filter")
        assert len(events) > 0, "filtered replay trace must record SPEC events"
        assert all(e.get("kind") == "SPEC" for e in events), \
            "filtered trace must contain ONLY SPEC events (SEND/RECV dropped)"
        for i, ev in enumerate(events):
            assert ev.get("gseq") == i, \
                "filtered trace gseq must be 0-based gapless (event %d)" % i
        assert trailer is not None and trailer.get("events") == len(events)
        assert trailer.get("last_gseq") == len(events) - 1
        # W2 structural gate must still pass on the filtered trace
        from rot import tracecheck
        ok, report = tracecheck.check_file(path)
        assert ok, "W2 structural gate failed on filtered trace:\n%s" \
            % "\n".join(report)
        # W4 judgment unchanged: same verdict as the unfiltered W3 run
        rc = subprocess.call([sys.executable,
                              os.path.join(_REPO_ROOT, "rot", "tracecheck.py"),
                              "--conformance", path, SCHEDULE],
                             stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
                             timeout=120)
        want = 0 if expect_verdict == "CONFORMANT" else 10
        assert rc == want, "W4 exit %d (want %d) for %s" % (rc, want, path)
        v = json.load(open(path + ".verdict.json", encoding="utf-8"))
        assert v.get("verdict") == expect_verdict, v
        # The trace is consistent with the policy the run used
        ok2, probs = logpolicy.check_trace_against_policy(doc, path)
        assert ok2 and not probs, "filtered trace must match its policy: %s" \
            % probs
    hb, evb, _ = _read_events(tb)
    _full_hb, full_ev, _ = _read_events(BUGGY_TRACE)
    assert len(evb) < len(full_ev), \
        "filtered trace (%d) must be smaller than unfiltered (%d)" \
        % (len(evb), len(full_ev))
    print("T8 OK  filtered replay: SPEC-only events, 0-based gapless gseq, "
          "W2 PASS, W4 verdict/exit unchanged (0/10), policy-consistent")

def T9_w6bench_filtered_zero_events(tmp):
    """W7 acceptance: W6Bench emits only SEND/RECV transport events, so the
    SPEC-only policy records ZERO events; unfiltered records all of them."""
    java = _find_java()
    records = 20000
    warmup = 20000  # W6Bench.java fixed warmup before the timed loop
    tu = os.path.join(tmp, "w7-w6-unfiltered.jsonl")
    tf = os.path.join(tmp, "w7-w6-filtered.jsonl")
    def _w6(trace, run_id, filtered):
        cmd = [java, "-javaagent:" + PROBE_AGENT_JAR,
               "-Drotn.probe.trace=" + trace,
               "-Drotn.probe.run=" + run_id]
        if filtered:
            cmd.append("-Drotn.probe.filter=SPEC")
        cmd += ["-cp", CLASSES, "com.rot.n.demo.W6Bench", str(records)]
        return subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=300)
    proc_u = _w6(tu, "w7-w6u", False)
    assert proc_u.returncode == 0, proc_u.stdout.decode("utf-8", "replace")
    proc_f = _w6(tf, "w7-w6f", True)
    assert proc_f.returncode == 0, proc_f.stdout.decode("utf-8", "replace")
    _, evu, tru = _read_events(tu)
    _, evf, trf = _read_events(tf)
    assert len(evu) == warmup + records, \
        "unfiltered must record ALL emitted events, got %d (want %d)" \
        % (len(evu), warmup + records)
    assert all(e.get("kind") in ("SEND", "RECV") for e in evu), \
        "W6Bench emits only transport events"
    assert len(evf) == 0, \
        "filtered (SPEC-only) run must record zero events, got %d" % len(evf)
    assert trf.get("events") == 0, "filtered trailer must say events=0"
    assert tru.get("events") == len(evu)
    print("T9 OK  W6Bench cost: unfiltered %d events -> filtered (SPEC) 0 "
          "events" % len(evu))

def main():
    _check_env()
    tmp = tempfile.mkdtemp(prefix="rotn_w7_")
    try:
        T1_minimal_and_deterministic()
        T2_digest_sensitivity()
        T3_error_handling()
        T4_trace_policy_consistency()
        T5_spec_absent_violates_obligation(tmp)
        T6_malformed_trace_never_raises(tmp)
        T7_cli()
        T8_end_to_end_filtered_replay(tmp)
        T9_w6bench_filtered_zero_events(tmp)
        print("PASS  W7: minimal logging policy + filtered replay (T1-T9)")
        return 0
    except EnvironmentError as e:
        print("ENV   W7: %s" % (e or "environment/fixture error"))
        return 2
    except AssertionError as e:
        print("FAIL  W7: %s" % (e or "(assertion failed)"))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
