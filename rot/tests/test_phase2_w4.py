# -*- coding: utf-8 -*-
"""Phase 2 W4 -- conformance verdicts, refinement requests, verdict artifacts.

Self-contained acceptance tests for the W4 layer on top of the W3 replay
traces (twopc-java/build):

    T1  tracefmt formalizes the v1 spec; the Java replay traces use it
    T2  W3 replay traces (correct + buggy) pass structure + normalization
    T3  verdict ladder: buggy = NON-CONFORMANT, correct = CONFORMANT,
        INCONCLUSIVE is a legitimate third verdict (not a crash)
    T4  buggy replay trace: NON-CONFORMANT, exit 10, agreement violated,
        decision-before-apply holds, schedule target/property surfaced
    T5  correct replay trace: CONFORMANT, exit 0, all invariants hold
    T6  incomplete trace (structurally valid, one applied value missing):
        INCONCLUSIVE, exit 20, refinement request embedded
    T7  malformed trace: never raises; INCONCLUSIVE + reasons + exit 20
    T8  verdict artifact: written next to the trace, v1 verdict format,
        deterministic -- repeated judgements byte-identical
    T9  W2 structural gate still passes on both W3 replay traces (regression)
    T10 buggy vs correct artifacts: same schema, different verdict +
        invariants evidence (never byte-identical)

The W4 layer is read-only over the trace (NEVER-REFINES): it reports a
verdict and, for INCONCLUSIVE, embeds a refinement request -- it never
imports rot.cegar / rot.abstraction / rot.pipeline / modelfind.

Run:  python rot\\tests\\test_phase2_w4.py
Exit codes: 0 all pass, 1 failure, 2 environment/usage.
Pure stdlib.
"""
from __future__ import print_function

import json
import os
import re
import shutil
import sys
import tempfile

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from rot import tracefmt  # noqa: E402
from rot import tracecheck  # noqa: E402

BUILD = os.path.join(_REPO_ROOT, "twopc-java", "build")
CORRECT_TRACE = os.path.join(BUILD, "replay-correct-1.jsonl")
BUGGY_TRACE = os.path.join(BUILD, "replay-buggy-1.jsonl")
SCHEDULE = os.path.join(BUILD, "schedule-buggy.jsonl")

# The two W3 replay traces are the acceptance fixtures; they are produced
# by twopc-java\build.ps1 -What replay (see test_phase2_w3.py).
_REQUIRED = (CORRECT_TRACE, BUGGY_TRACE, SCHEDULE)


def _check_env():
    missing = [p for p in _REQUIRED if not os.path.exists(p)]
    if missing:
        print("W4 fixture missing: %s" % missing)
        print("run first:  cd twopc-java ; .\\build.ps1 -What replay")
        sys.exit(2)


# ------------------------------------------------------------ trace builder --

def _build(path, run_id, events, trailer=None, raw_tail=None):
    """Write a v1 trace file (header + events + trailer) deterministically.

    `raw_tail` is appended verbatim after the trailer (for malformed tests).
    Returns (path, n_events).
    """
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        header = {"_meta": tracefmt.HEADER_META, "format": tracefmt.FORMAT,
                  "run": run_id, "w4-test": "synthetic"}
        f.write(json.dumps(header, separators=(",", ":")) + "\n")
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")
        if trailer is None:
            trailer = {"_meta": tracefmt.TRAILER_META,
                       "events": len(events),
                       "last_gseq": len(events) - 1,
                       "last_lamport": events[-1]["lamport"]}
        f.write(json.dumps(trailer, separators=(",", ":")) + "\n")
        if raw_tail:
            f.write(raw_tail)
    return path, len(events)


def _ev(gseq, kind, actor, action, payload):
    return {"gseq": gseq, "seq": gseq, "lamport": gseq + 1,
            "actor": actor, "thread": "main", "kind": kind,
            "action": action, "payload": payload}


# -------------------------------------------------------------------- tests --

def T1_spec_and_replay_trace_shape():
    """v1 spec constants are coherent; the W3 replay trace uses the spec."""
    assert tracefmt.FORMAT == "v1"
    assert set(tracefmt.KINDS) == {"SEND", "RECV", "SPEC"}
    assert tracefmt.HEADER_META and tracefmt.TRAILER_META
    assert tracefmt.CONFORMANT == "CONFORMANT"
    assert tracefmt.NON_CONFORMANT == "NON-CONFORMANT"
    assert tracefmt.INCONCLUSIVE == "INCONCLUSIVE"
    assert tracefmt.VERDICT_META and tracefmt.REFINEMENT_META

    for path in (CORRECT_TRACE, BUGGY_TRACE):
        trace = tracefmt.load_trace(path)
        assert not trace["parse_errors"], trace["parse_errors"]
        assert trace["header"] is not None
        assert trace["header"]["format"] == tracefmt.FORMAT
        assert re.match(tracefmt.STABLE_ID_RE.pattern, trace["header"]["run"])
        assert trace["trailer"] is not None
        kinds = {ev["kind"] for ev in trace["events"]}
        assert kinds <= set(tracefmt.KINDS), kinds
        # stable main thread (W3 property, kept for W4)
        threads = {ev.get("thread") for ev in trace["events"]}
        assert threads == {"main"}, threads
    print("T1 OK  tracefmt v1 spec; replay traces use it (SEND/RECV/SPEC, main)")


def T2_replay_traces_pass_structure_and_normalization():
    for path in (CORRECT_TRACE, BUGGY_TRACE):
        trace = tracefmt.load_trace(path)
        struct = tracefmt.check_structure(trace)
        assert struct == [], struct
        norm = tracefmt.check_normalization(trace)
        assert norm == [], norm
    print("T2 OK  W3 replay traces pass W2 structure + normalization gates")


def T3_verdict_ladder_three_way():
    """CONFORMANT / NON-CONFORMANT / INCONCLUSIVE are all reachable."""
    codes = {tracefmt.CONFORMANT, tracefmt.NON_CONFORMANT,
             tracefmt.INCONCLUSIVE}
    assert len(codes) == 3
    assert tracefmt.verdict_exit_code(tracefmt.CONFORMANT) == 0
    assert tracefmt.verdict_exit_code(tracefmt.NON_CONFORMANT) == 10
    assert tracefmt.verdict_exit_code(tracefmt.INCONCLUSIVE) == 20

    buggy = tracecheck.conformance(BUGGY_TRACE, SCHEDULE)
    correct = tracecheck.conformance(CORRECT_TRACE, SCHEDULE)
    assert buggy["verdict"] == tracefmt.NON_CONFORMANT, buggy["verdict"]
    assert correct["verdict"] == tracefmt.CONFORMANT, correct["verdict"]
    # INCONCLUSIVE is a legitimate verdict (T6 exercises it concretely).
    req = tracefmt.refinement_request(["no decision observed"])
    assert req["_meta"] == tracefmt.REFINEMENT_META
    assert req["reasons"], req
    print("T3 OK  verdict ladder: buggy=NON-CONFORMANT, correct=CONFORMANT, "
          "INCONCLUSIVE reachable (exit 0/10/20)")


def T4_buggy_nonconformant():
    v = tracecheck.conformance(BUGGY_TRACE, SCHEDULE)
    assert v["verdict"] == tracefmt.NON_CONFORMANT
    assert tracefmt.verdict_exit_code(v["verdict"]) == 10
    names = {r["name"]: r for r in v["invariants"]}
    assert names["agreement"]["status"] == "violated", names["agreement"]
    assert names["decision_before_apply"]["status"] == "holds", names
    assert "agreement" in v["violations"]
    assert v.get("refinement_request") is None  # not INCONCLUSIVE
    # schedule context is surfaced on the verdict
    assert v["target"] == "buggy", v.get("target")
    assert v["property"] == "agreement", v.get("property")
    print("T4 OK  buggy: NON-CONFORMANT (exit 10), agreement violated "
          "(p1=commit vs p2=abort), d_b_a holds, target/property surfaced")


def T5_correct_conformant():
    v = tracecheck.conformance(CORRECT_TRACE, SCHEDULE)
    assert v["verdict"] == tracefmt.CONFORMANT
    assert tracefmt.verdict_exit_code(v["verdict"]) == 0
    for r in v["invariants"]:
        assert r["status"] == "holds", r
    assert v["violations"] == []
    assert v.get("refinement_request") is None
    print("T5 OK  correct: CONFORMANT (exit 0), agreement + d_b_a hold")


def T6_incomplete_inconclusive_with_refinement(tmp):
    """Structurally valid but incomplete (missing applied_2) -> INCONCLUSIVE."""
    events = [
        _ev(0, "SEND", "coordinator", "send_ASK", "ASK to 1,2"),
        _ev(1, "RECV", "participant_1", "recv_ASK", "ASK"),
        _ev(2, "RECV", "participant_2", "recv_ASK", "ASK"),
        _ev(3, "SEND", "participant_1", "send_VOTE", "VOTE yes from 1"),
        _ev(4, "RECV", "coordinator", "recv_VOTE", "VOTE yes from 1"),
        _ev(5, "SEND", "participant_2", "send_VOTE", "VOTE no from 2"),
        _ev(6, "RECV", "coordinator", "recv_VOTE", "VOTE no from 2"),
        _ev(7, "SPEC", "coordinator", "decide",
            "decision=commit votes={1=yes, 2=no}"),
        _ev(8, "SEND", "coordinator", "send_DEC", "DECISION commit"),
        _ev(9, "RECV", "participant_1", "recv_DEC", "DECISION commit"),
        _ev(10, "RECV", "participant_2", "recv_DEC", "DECISION commit"),
        _ev(11, "SPEC", "participant_1", "apply_1", "applied_1=commit"),
        # NOTE: no apply_2 -- participant_2's outcome is missing evidence.
    ]
    path, _ = _build(os.path.join(tmp, "incomplete.jsonl"),
                     "w4-incomplete", events)
    trace = tracefmt.load_trace(path)
    assert tracefmt.check_structure(trace) == []
    assert tracefmt.check_normalization(trace) == []

    v = tracecheck.conformance(path, SCHEDULE)
    assert v["verdict"] == tracefmt.INCONCLUSIVE, v["verdict"]
    assert tracefmt.verdict_exit_code(v["verdict"]) == 20
    req = v["refinement_request"]
    assert req is not None and req["_meta"] == tracefmt.REFINEMENT_META
    assert req["reasons"], req
    assert any("participant(s) [2]" in r for r in req["reasons"]), req
    print("T6 OK  incomplete trace: INCONCLUSIVE (exit 20) + refinement "
          "request (needs applied value for participant 2)")


def T7_malformed_never_raises(tmp):
    """Malformed input is INCONCLUSIVE material, never a crash."""
    p = os.path.join(tmp, "malformed.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"_meta": tracefmt.HEADER_META,
                            "format": tracefmt.FORMAT,
                            "run": "w4-malformed"}) + "\n")
        f.write("{ this is not json\n")  # broken line
        f.write(json.dumps(_ev(0, "SPEC", "coordinator", "decide",
                               "decision=commit")) + "\n")
        # no trailer at all
    try:
        v = tracecheck.conformance(p, SCHEDULE)
    except Exception as e:  # pragma: no cover - contract: never raises
        raise AssertionError("conformance raised on malformed input: %r" % e)
    assert v["verdict"] == tracefmt.INCONCLUSIVE, v["verdict"]
    assert tracefmt.verdict_exit_code(v["verdict"]) == 20
    assert v["refinement_request"] is not None
    assert v["refinement_request"]["reasons"]
    print("T7 OK  malformed trace: no crash, INCONCLUSIVE (exit 20) + "
          "refinement request")


def T8_verdict_artifact_deterministic(tmp):
    """judge() writes <trace>.verdict.json, v1 format, byte-identical repeats."""
    src = os.path.join(tmp, "artifact.jsonl")
    shutil.copyfile(CORRECT_TRACE, src)
    v1, art1 = tracecheck.judge(src, SCHEDULE)
    assert art1 == tracecheck.verdict_artifact_path(src)
    assert os.path.exists(art1)

    # verdict artifact format (v1)
    with open(art1, "r", encoding="utf-8") as f:
        doc = json.load(f)
    assert doc["_meta"] == tracefmt.VERDICT_META
    assert doc["format"] == tracefmt.FORMAT
    assert doc["verdict"] == tracefmt.CONFORMANT
    assert doc["invariants"], doc
    assert doc["target"] == "buggy" and doc["property"] == "agreement"
    assert "refinement_request" not in doc  # CONFORMANT: none embedded

    # determinism: repeated judgements are byte-identical (no timestamps)
    raw1 = open(art1, "rb").read()
    v2, art2 = tracecheck.judge(src, SCHEDULE)
    assert art2 == art1
    raw2 = open(art1, "rb").read()
    assert raw1 == raw2, "verdict artifact is not deterministic"
    assert v1["verdict"] == v2["verdict"]

    # no nondeterministic field names anywhere in the artifact
    text = raw1.decode("utf-8")
    for name in ("ts", "timestamp", "time", "datetime",
                 "date", "epoch", "wall_time", "wallclock",
                 "uuid", "nonce", "random", "seed"):
        assert ('"%s"' % name) not in text, name
    print("T8 OK  verdict artifact: %s (v1 format, deterministic, "
          "byte-identical repeats)" % os.path.basename(art1))


def T9_w2_gate_regression():
    """The W2 structural gate still passes on both W3 replay traces."""
    for path in (CORRECT_TRACE, BUGGY_TRACE):
        ok, report = tracecheck.check_file(path)
        assert ok, (path, report)
        assert any("verdict: PASS" in ln for ln in report), report
    print("T9 OK  W2 structural gate regression: both W3 traces pass")


def T10_buggy_vs_correct_distinct(tmp):
    """Same schema, different verdicts -- never byte-identical artifacts."""
    b = os.path.join(tmp, "b.jsonl")
    c = os.path.join(tmp, "c.jsonl")
    shutil.copyfile(BUGGY_TRACE, b)
    shutil.copyfile(CORRECT_TRACE, c)
    vb, ab = tracecheck.judge(b, SCHEDULE)
    vc, ac = tracecheck.judge(c, SCHEDULE)
    assert vb["verdict"] == tracefmt.NON_CONFORMANT
    assert vc["verdict"] == tracefmt.CONFORMANT
    rb = open(ab, "rb").read()
    rc = open(ac, "rb").read()
    assert rb != rc, "buggy and correct artifacts must differ"
    # same schema (identical top-level key sets)
    db = json.loads(rb.decode("utf-8"))
    dc = json.loads(rc.decode("utf-8"))
    assert set(db) == set(dc), (sorted(db), sorted(dc))
    assert db["_meta"] == dc["_meta"] == tracefmt.VERDICT_META
    print("T10 OK  buggy vs correct: distinct verdicts + artifacts, "
          "same schema")


# --------------------------------------------------------------------- main --

def main():
    _check_env()
    tmp = tempfile.mkdtemp(prefix="rotn_w4_")
    try:
        T1_spec_and_replay_trace_shape()
        T2_replay_traces_pass_structure_and_normalization()
        T3_verdict_ladder_three_way()
        T4_buggy_nonconformant()
        T5_correct_conformant()
        T6_incomplete_inconclusive_with_refinement(tmp)
        T7_malformed_never_raises(tmp)
        T8_verdict_artifact_deterministic(tmp)
        T9_w2_gate_regression()
        T10_buggy_vs_correct_distinct(tmp)
        print("PASS  W4: conformance verdicts, refinement requests, "
              "verdict artifacts (T1-T10)")
        return 0
    except AssertionError as e:
        print("FAIL  W4: %s" % (e or "(assertion failed)"))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())