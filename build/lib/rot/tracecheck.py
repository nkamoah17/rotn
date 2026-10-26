# -*- coding: utf-8 -*-
"""W2 structural trace checker (Python-side conformance, structural half).

Reads one or more probe trace files (JSONL: one JSON object per line,
header + trailer as _meta records) and verifies the W2 exit criteria:

  * every line parses as JSON
  * first record is the probe header, last is the trailer
  * trailer event count matches the number of event records
  * each event carries gseq, seq, lamport, actor, thread, kind, action,
    payload; actor/kind/action are non-empty strings, seq fields are ints
  * gseq is strictly monotone, 0-based, gap-free
  * lamport is strictly monotone and strictly dominates the target seq
    (lamport[i] > lamport[i-1] and lamport[i] > seq[i]) -- this is the
    total-order metadata check: lamport is a valid total-order extension
    of the lock sequence
  * event kind is one of SEND/RECV/SPEC; SPEC events carry the model
    action name ("vote_<i>_yes|no", "decide", "apply_<i>"), SEND/RECV
    carry the transport label ("send_<T>", "recv_<T>")

Deliberately NOT checked here (that is W4 conformance): agreement
between coordinator decision and participant outcomes. Ordering between
decision and apply is reported as INFO only, so the buggy trace still
PASSES this structural gate.

Usage:
    python rot\\tracecheck.py <trace.jsonl> [more.jsonl ...]
    python rot\\tracecheck.py --conformance <trace.jsonl> [schedule.jsonl]

Exit codes:
    structural mode:  0 = all files pass, 1 = at least one file fails,
                      2 = usage error
    --conformance:    0 = CONFORMANT, 10 = NON-CONFORMANT,
                      20 = INCONCLUSIVE (refinement request embedded)
                      Writes <trace>.verdict.json deterministically
"""
from __future__ import print_function

import io
import json
import os
import sys

REQUIRED_EVENT_FIELDS = ("gseq", "seq", "lamport", "actor", "kind", "action")
# Event classes (TraceEvent.Kind in twopc-java). The model action name
# lives in "action": SPEC -> "vote_<i>_yes|no" | "decide" | "apply_<i>";
# SEND/RECV -> "send_<T>" | "recv_<T>" (transport, audit only).
KNOWN_KINDS = set(["SEND", "RECV", "SPEC"])


def load_records(path):
    """Return (records, errors). records = list of parsed JSON objects."""
    records = []
    errors = []
    try:
        f = io.open(path, "r", encoding="utf-8")
    except (IOError, OSError) as exc:
        return records, ["cannot open %s: %s" % (path, exc)]
    try:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except ValueError as exc:
                errors.append("line %d: invalid JSON: %s" % (lineno, exc))
                continue
            if not isinstance(obj, dict):
                errors.append("line %d: record is not a JSON object" % lineno)
                continue
            records.append(obj)
    finally:
        f.close()
    return records, errors


def is_event(rec):
    return "_meta" not in rec and "gseq" in rec

def check_file(path):
    """Run all structural checks on one trace file.
    Returns (ok, lines) where lines are printable report lines."""
    lines = []
    records, errors = load_records(path)
    lines.append("  parse: %d records" % len(records))
    if errors:
        lines.extend("  parse ERROR: %s" % e for e in errors)
    if not records:
        return False, lines

    header = records[0]
    trailer = records[-1]
    events = [r for r in records if is_event(r)]
    if header.get("_meta") != "rotn-probe-header":
        errors.append("first record is not the probe header")
        lines.append("  header: MISSING")
    else:
        lines.append("  header: ok (format=%s)" % header.get("format"))
    if trailer.get("_meta") != "rotn-probe-trailer":
        errors.append("last record is not the probe trailer")
        lines.append("  trailer: MISSING")
    else:
        if trailer.get("events") != len(events):
            errors.append("trailer events=%s != %d event records"
                          % (trailer.get("events"), len(events)))
            lines.append("  trailer: count MISMATCH (%s vs %d)"
                         % (trailer.get("events"), len(events)))
        else:
            lines.append("  trailer: ok (events=%d)" % len(events))

    gseq_ok = True
    lamport_ok = True
    lamport_dominates = True
    kinds_ok = True
    prev_lamport = None
    for i, ev in enumerate(events):
        for fld in REQUIRED_EVENT_FIELDS:
            if fld not in ev:
                errors.append("event %d: missing field %r" % (i, fld))
        for fld in ("gseq", "seq", "lamport"):
            if fld in ev and not isinstance(ev[fld], int):
                errors.append("event %d: %s is not an integer: %r"
                              % (i, fld, ev.get(fld)))
        for fld in ("actor", "kind", "action"):
            if fld in ev and (not isinstance(ev[fld], str) or ev[fld] == ""):
                errors.append("event %d: %s must be a non-empty string: %r"
                              % (i, fld, ev.get(fld)))
        if ev.get("gseq") != i:
            gseq_ok = False
            if i < 3:
                errors.append("event %d: gseq=%r (expected %d)"
                              % (i, ev.get("gseq"), i))
        lp = ev.get("lamport")
        if isinstance(lp, int):
            if prev_lamport is not None and lp <= prev_lamport:
                lamport_ok = False
                errors.append("event %d: lamport %d not strictly increasing"
                              % (i, lp))
            prev_lamport = lp
            if not isinstance(ev.get("seq"), int) or lp <= ev["seq"]:
                lamport_dominates = False
                errors.append("event %d: lamport %s must strictly dominate seq %s"
                              % (i, lp, ev.get("seq")))
        kind = ev.get("kind")
        if kind not in KNOWN_KINDS:
            kinds_ok = False
            errors.append("event %d: unknown kind %r" % (i, kind))

    lines.append("  gseq_monotone_0based: %s" % ("ok" if gseq_ok else "FAIL"))
    lines.append("  lamport_strictly_monotone: %s" % ("ok" if lamport_ok else "FAIL"))
    lines.append("  lamport_dominates_seq: %s" % ("ok" if lamport_dominates else "FAIL"))
    lines.append("  kinds_known: %s" % ("ok" if kinds_ok else "FAIL"))

    # INFO only (W4 territory): decision vs apply ordering.
    # decision = first SPEC event with action "decide" (coordinator);
    # apply    = first SPEC event with action "apply_<i>" (participant).
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
    if dec is not None and app is not None:
        order = "ok" if dec < app else "VIOLATION (apply precedes decision)"
        lines.append("  INFO decision@%d apply@%d order=%s" % (dec, app, order))

    ok = not errors
    lines.append("  verdict: %s" % ("PASS" if ok else "FAIL"))
    return ok, lines


def main(argv):
    paths = argv[1:]
    if not paths:
        print(__doc__)
        return 2
    all_ok = True
    for path in paths:
        print("[trace] %s" % os.path.abspath(path))
        ok, lines = check_file(path)
        for ln in lines:
            print(ln)
        all_ok = all_ok and ok
    print("")
    if all_ok:
        print("W2 STRUCTURAL TRACECHECK: PASS (%d/%d files)" % (len(paths), len(paths)))
        return 0
    print("W2 STRUCTURAL TRACECHECK: FAIL")
    return 1


# ============================================================ W4 (2026-10)
# Conformance layer: invariants over a v1 trace + the verdict ladder.
# This section targets the W3/W4 REPLAY trace shape (SEND/RECV/SPEC,
# model action in the SPEC payload) -- the W2 structural gate above intentionally
# does not check agreement; that is W4's job (see its docstring).
#
# NEVER-REFINES: this layer only READS the trace and REPORTS the verdict.
# INCONCLUSIVE yields a refinement-request artifact (tracefmt); it never
# imports or calls rot.cegar / rot.abstraction / rot.pipeline / modelfind.

import re

try:  # package context (import rot.tracecheck)
    from . import tracefmt
    from . import schedulecheck
except ImportError:  # flat script context (python rot/tracecheck.py)
    import tracefmt
    import schedulecheck

APPLIED_RE = re.compile(r"^applied_(\d+)=(\S+)")
DECISION_RE = re.compile(r"\b(decision=|decide\b)")
PARTICIPANT_RE = re.compile(r"participant_(\d+)")


def applied_from_events(events):
    """{participant_index: applied_value} from SPEC apply events
    (payload 'applied_<i>=<value> ...')."""
    out = {}
    for ev in events:
        if ev.get("kind") != "SPEC":
            continue
        m = APPLIED_RE.match(ev.get("payload") or "")
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


def expected_participants(events, schedule_path=None):
    """The participant set a CONFORMANT verdict must cover. Preferred
    source: the schedule (owner participant_<i>). Fallback: any
    participant_<i> actor in the trace."""
    idx = set()
    if schedule_path and os.path.exists(schedule_path):
        _header, steps, _errors = schedulecheck.load_schedule(schedule_path)
        for step in steps:
            m = PARTICIPANT_RE.search(str(step.get("owner") or ""))
            if m:
                idx.add(int(m.group(1)))
    if not idx:
        for ev in events:
            m = PARTICIPANT_RE.search(str(ev.get("actor") or ""))
            if m:
                idx.add(int(m.group(1)))
    return idx


def _decide_gseq(events):
    for i, ev in enumerate(events):
        if ev.get("kind") == "SPEC" and DECISION_RE.search(ev.get("payload") or ""):
            return i
    return None


def _decision_value(events):
    """The decision value (payload 'decision=<value>'), or None."""
    for ev in events:
        if ev.get("kind") == "SPEC" and DECISION_RE.search(ev.get("payload") or ""):
            m = re.search(r"decision=(\S+)", ev.get("payload") or "")
            return m.group(1) if m else None
    return None


def invariant_results(events, expected):
    """Evaluate the two 2PC invariants. Each result:
    {"name", "status": "holds"|"violated"|"incomplete", "evidence"}.
    'violated' is only ever a DEFINITE violation (soundness-first).
    agreement = every participant applied the same value, and that value
    matches the coordinator's decision when one is observed (this catches
    the W3 buggy case: decision=abort while both applied commit)."""
    applied = applied_from_events(events)
    decide = _decide_gseq(events)
    dec_val = _decision_value(events)
    results = []

    # 1) agreement: applied values agree with each other and with the
    #    decision (when observed).
    if not applied:
        results.append({
            "name": "agreement", "status": "incomplete",
            "evidence": "no participant has applied",
        })
    else:
        missing = sorted(expected - set(applied))
        values = sorted(set(applied.values()))
        if dec_val is not None:
            if any(v != dec_val for v in values):
                results.append({
                    "name": "agreement", "status": "violated",
                    "evidence": "applied values %s do not match "
                                "decision=%s" % (applied, dec_val),
                })
            elif missing:
                results.append({
                    "name": "agreement", "status": "incomplete",
                    "evidence": "no applied value yet for participant(s) %s"
                                % missing,
                })
            else:
                results.append({
                    "name": "agreement", "status": "holds",
                    "evidence": "all applied values match decision=%s: %s"
                                % (dec_val, applied),
                })
        else:
            if len(values) > 1:
                results.append({
                    "name": "agreement", "status": "violated",
                    "evidence": "participants applied different values: %s"
                                % applied,
                })
            elif missing:
                results.append({
                    "name": "agreement", "status": "incomplete",
                    "evidence": "no applied value yet for participant(s) %s"
                                % missing,
                })
            else:
                results.append({
                    "name": "agreement", "status": "holds",
                    "evidence": "all applied values identical: %s "
                                "(no decision observed)" % applied,
                })

    # 2) decision-before-apply: no participant applies before the
    #    coordinator's decision. Definite (violated) only when the
    #    decision IS observed; an apply with no decision at all is an
    #    incomplete run, not a definite violation (soundness-first).
    applies = [i for i, ev in enumerate(events)
               if ev.get("kind") == "SPEC"
               and APPLIED_RE.match(ev.get("payload") or "")]
    if not applies:
        results.append({
            "name": "decision_before_apply", "status": "incomplete",
            "evidence": "no apply events observed",
        })
    elif decide is None:
        results.append({
            "name": "decision_before_apply", "status": "incomplete",
            "evidence": "apply at gseq %d but no decision observed "
                        "(incomplete run)" % events[applies[0]]["gseq"],
        })
    elif decide > min(applies):
        results.append({
            "name": "decision_before_apply", "status": "violated",
            "evidence": "decision at gseq %d after apply at gseq %d"
                        % (events[decide]["gseq"], events[min(applies)]["gseq"]),
        })
    else:
        results.append({
            "name": "decision_before_apply", "status": "holds",
            "evidence": "decision at gseq %d precedes all applies"
                        % events[decide]["gseq"],
        })
    return results


def _schedule_target_property(schedule_path):
    """(target, property) from the schedule header record, or (None, None)."""
    if schedule_path and os.path.exists(schedule_path):
        header, _steps, _errors = schedulecheck.load_schedule(schedule_path)
        if header:
            return header.get("target"), header.get("property")
    return None, None


def conformance(path, schedule_path=None):
    """The W4 verdict ladder over a v1 trace (see tracefmt for the format):
      structurally invalid           -> INCONCLUSIVE (structural errors)
      definite invariant violation   -> NON-CONFORMANT
      complete, no violation         -> CONFORMANT
      incomplete, no violation       -> INCONCLUSIVE (refinement request)
    Never raises; malformed input is INCONCLUSIVE, never a crash.
    """
    trace = tracefmt.load_trace(path)
    struct = tracefmt.check_structure(trace)
    events = trace["events"]
    target, prop = _schedule_target_property(schedule_path)
    if struct:
        reasons = ["structurally invalid trace: %s" % e for e in struct]
        return tracefmt.make_verdict(tracefmt.INCONCLUSIVE, path, schedule_path,
                                     [], [], reasons,
                                     target=target, property_name=prop)
    expected = expected_participants(events, schedule_path)
    results = invariant_results(events, expected)
    violations = [r["name"] for r in results if r["status"] == "violated"]
    applied = applied_from_events(events)
    decide = _decide_gseq(events)
    if violations:
        return tracefmt.make_verdict(tracefmt.NON_CONFORMANT, path, schedule_path,
                                     results, violations,
                                     ["invariant violated: %s" % v
                                      for v in violations],
                                     target=target, property_name=prop)
    if not expected:
        reasons = ["no expected participants could be established "
                   "(no schedule and no participant actors)"]
        return tracefmt.make_verdict(tracefmt.INCONCLUSIVE, path, schedule_path,
                                     results, [], reasons,
                                     target=target, property_name=prop)
    missing = sorted(expected - set(applied))
    if decide is None or missing:
        reasons = []
        if decide is None:
            reasons.append("no decision observed")
        if missing:
            reasons.append("no applied value for participant(s) %s" % missing)
        return tracefmt.make_verdict(tracefmt.INCONCLUSIVE, path, schedule_path,
                                     results, [], reasons,
                                     target=target, property_name=prop)
    return tracefmt.make_verdict(tracefmt.CONFORMANT, path, schedule_path,
                                 results, [],
                                 ["agreement holds; decision precedes apply; "
                                  "all expected participants applied"],
                                 target=target, property_name=prop)


def verdict_artifact_path(trace_path):
    """The W4 verdict artifact lives next to the trace: <trace>.verdict.json.
    Written deterministically (sorted keys, no timestamps), so repeated
    judgements of the same inputs are byte-identical."""
    return trace_path + ".verdict.json"


def judge(trace_path, schedule_path=None):
    """W4 judging: conformance verdict + deterministic artifact write.

    Returns (verdict_dict, artifact_path).  Never raises on malformed
    input: malformed or incomplete traces yield an INCONCLUSIVE verdict
    (with the embedded refinement request), never a crash.
    """
    v = conformance(trace_path, schedule_path)
    artifact = verdict_artifact_path(trace_path)
    tracefmt.write_verdict_artifact(artifact, v)
    return v, artifact


def report_lines(v):
    """Human-readable one-section report (verdict + invariant table)."""
    out = ["[W4 conformance] %s: %s" % (v["trace"], v["verdict"])]
    for r in v["invariants"]:
        out.append("  invariant %-20s %s  (%s)"
                   % (r["name"], r["status"], r["evidence"]))
    for reason in v["reasons"]:
        out.append("  - " + reason)
    if v["verdict"] == tracefmt.INCONCLUSIVE:
        out.append("  refinement request embedded in the verdict artifact "
                   "(INCONCLUSIVE is not a failure)")
    return out


def main_conformance(argv):
    """CLI: tracecheck.py --conformance <trace.jsonl> [schedule.jsonl].
    Writes the deterministic verdict artifact <trace>.verdict.json.
    Exit codes: 0 = CONFORMANT, 10 = NON-CONFORMANT, 20 = INCONCLUSIVE."""
    args = [a for a in argv if a != "--conformance"]
    if not args or len(args) > 2:
        print("usage: tracecheck.py --conformance <trace.jsonl> [schedule.jsonl]")
        return 2
    path = args[0]
    sched = args[1] if len(args) == 2 else None
    v, artifact = judge(path, sched)
    for line in report_lines(v):
        print(line)
    print("  verdict artifact: %s" % artifact)
    return tracefmt.verdict_exit_code(v["verdict"])


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--conformance":
        sys.exit(main_conformance(sys.argv[2:]))
    if len(sys.argv) != 2:
        print("usage: tracecheck.py <records.jsonl> [more.jsonl ...]")
        print("       tracecheck.py --conformance <trace.jsonl> "
              "[schedule.jsonl]")
        sys.exit(2)
    sys.exit(main(sys.argv))
