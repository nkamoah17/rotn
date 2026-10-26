# -*- coding: utf-8 -*-
"""Phase 2 W4 -- formal v1 trace format (schema, normalization, verdicts).

This is the single source of truth for what a ROTN empirical trace is:

  * structure    -- header / events / trailer layout, required fields,
                    0-based gapless gseq, lamport dominance (the W2 rules,
                    formalized into one checkable predicate)
  * normalization-- deterministic-shape rules: no wall-clock timestamps,
                    no random ids, stable run/thread identifiers.
                    (True cross-run stability is proven behaviorally --
                    byte-identical replay triples -- the rules here only
                    reject *obviously* nondeterministic shapes.)
  * verdicts     -- CONFORMANT / NON-CONFORMANT / INCONCLUSIVE, the
                    verdict artifact format, and the refinement-request
                    artifact emitted (and ONLY emitted) for INCONCLUSIVE.

Verdict semantics (soundness-first):
  CONFORMANT     -- structurally valid trace, complete evidence (a decision
                    and every expected participant applied), no invariant
                    violated (agreement held, decision preceded apply).
  NON-CONFORMANT -- structurally valid trace with at least one DEFINITE
                    violation (conflicting applied values, or an apply with
                    no preceding decision).
  INCONCLUSIVE   -- structural defects OR incomplete evidence with no
                    definite violation. Deliberately NOT a failure: it
                    produces a refinement-request artifact (never a crash,
                    never a silent pass) so the formal plane MAY --
                    optionally -- refine.

NEVER-REFINES: this module must not import rot.cegar, rot.abstraction,
rot.pipeline, or rot.modelfind (nor anything that transitively does). The
empirical plane only READS traces and REPORTS verdicts; refinement is a
Phase 1 (formal) concern reached only through the explicit
refinement-request artifact. Enforced by tests/test_tracecheck.py
(import-graph check + refinement canary).

Pure stdlib, Python 3.6 compatible (no f-strings, no dataclasses).
"""

import json
import os
import re

__all__ = [
    "FORMAT",
    "HEADER_META",
    "TRAILER_META",
    "VERDICT_META",
    "REFINEMENT_META",
    "KINDS",
    "HEADER_REQUIRED_FIELDS",
    "EVENT_REQUIRED_FIELDS",
    "TRAILER_REQUIRED_FIELDS",
    "NONDET_FIELD_NAMES",
    "STABLE_ID_RE",
    "CONFORMANT",
    "NON_CONFORMANT",
    "INCONCLUSIVE",
    "load_trace",
    "check_structure",
    "check_normalization",
    "make_verdict",
    "refinement_request",
    "write_verdict_artifact",
    "verdict_exit_code",
]

# ---------------------------------------------------------------- schema --

FORMAT = "v1"
HEADER_META = "rotn-probe-header"
TRAILER_META = "rotn-probe-trailer"
VERDICT_META = "rotn-verdict"
REFINEMENT_META = "rotn-refinement-request"

KINDS = ("SEND", "RECV", "SPEC")

HEADER_REQUIRED_FIELDS = ("format", "run")
EVENT_REQUIRED_FIELDS = ("gseq", "seq", "lamport", "actor", "kind")
TRAILER_REQUIRED_FIELDS = ("events", "last_gseq", "last_lamport")

# Exact field names that are always nondeterministic (wall-clock / random).
NONDET_FIELD_NAMES = frozenset([
    "ts", "timestamp", "time", "datetime", "date", "epoch",
    "wall_time", "wallclock", "uuid", "nonce", "random", "seed",
])

# String values that are obviously nondeterministic (ISO-8601 timestamps,
# UUIDs, JVM thread numbers like "Thread-3").
_NONDET_VALUE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"|Thread-\d+)"
)

# Stable identifier shape (run ids, thread names): lower-case slug.
STABLE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")

# --------------------------------------------------------------- verdicts --

CONFORMANT = "CONFORMANT"
NON_CONFORMANT = "NON-CONFORMANT"
INCONCLUSIVE = "INCONCLUSIVE"

_EXIT_CODES = {CONFORMANT: 0, NON_CONFORMANT: 10, INCONCLUSIVE: 20}


def verdict_exit_code(verdict):
    """Process exit code for a verdict: 0 / 10 / 20 (2 = usage error)."""
    try:
        return _EXIT_CODES[verdict]
    except KeyError:
        return 2


# ---------------------------------------------------------------- reader --

def load_trace(path):
    """Parse a v1 JSONL trace. Returns a dict:
        {"records": [...], "header": {...}|None, "events": [...],
         "trailer": {...}|None, "parse_errors": [...]}
    Never raises on malformed input (that is INCONCLUSIVE material,
    not a crash).
    """
    records = []
    parse_errors = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError as e:
                    parse_errors.append("line %d: invalid JSON: %s" % (i + 1, e))
                    continue
                if not isinstance(obj, dict):
                    parse_errors.append("line %d: not a JSON object" % (i + 1))
                    continue
                records.append(obj)
    except IOError as e:
        parse_errors.append("cannot read %s: %s" % (path, e))
        return {"records": [], "header": None, "events": [],
                "trailer": None, "parse_errors": parse_errors}
    header = (records[0] if records
              and records[0].get("_meta") == HEADER_META else None)
    trailer = (records[-1] if records
               and records[-1].get("_meta") == TRAILER_META else None)
    events = [r for r in records
              if r.get("_meta") not in (HEADER_META, TRAILER_META)]
    return {"records": records, "header": header, "events": events,
            "trailer": trailer, "parse_errors": parse_errors}


# ------------------------------------------------------------- structure --

def check_structure(trace):
    """Formalized W2 structural rules. Returns a list of error strings
    (empty == structurally valid). `trace` is a load_trace() dict."""
    errs = list(trace["parse_errors"])
    records, header, events, trailer = (trace["records"], trace["header"],
                                        trace["events"], trace["trailer"])
    if not records:
        errs.append("no records")
        return errs
    if header is None:
        errs.append("first record is not a %s header" % HEADER_META)
    else:
        if header.get("format") != FORMAT:
            errs.append("header format %r (expected %r)"
                        % (header.get("format"), FORMAT))
        run = header.get("run")
        if not isinstance(run, str) or not run:
            errs.append("header run id missing/empty")
    if trailer is None:
        errs.append("last record is not a %s trailer" % TRAILER_META)
    else:
        if trailer.get("events") != len(events):
            errs.append("trailer events=%r but %d events present"
                        % (trailer.get("events"), len(events)))
        if trailer.get("last_gseq") != (len(events) - 1):
            errs.append("trailer last_gseq=%r but %d events present"
                        % (trailer.get("last_gseq"), len(events)))
    prev_lamport = None
    for i, ev in enumerate(events):
        for k in EVENT_REQUIRED_FIELDS:
            if ev.get(k) is None:
                errs.append("event %d missing field %r" % (i, k))
        g = ev.get("gseq")
        if not isinstance(g, int) or isinstance(g, bool):
            errs.append("event %d gseq %r is not an integer" % (i, g))
        elif g != i:
            errs.append("event %d gseq=%r (expected %d: 0-based gapless)"
                        % (i, g, i))
        lp = ev.get("lamport")
        seq = ev.get("seq")
        if (isinstance(lp, int) and not isinstance(lp, bool)
                and isinstance(seq, int) and lp < seq):
            errs.append("event %d lamport %d must dominate seq %d" % (i, lp, seq))
        if prev_lamport is not None and isinstance(lp, int) and lp <= prev_lamport:
            errs.append("event %d lamport %d not strictly increasing" % (i, lp))
        if isinstance(lp, int) and not isinstance(lp, bool):
            prev_lamport = lp
    if trailer is not None and events:
        last = events[-1]
        if (isinstance(trailer.get("last_lamport"), int)
                and isinstance(last.get("lamport"), int)
                and trailer["last_lamport"] != last["lamport"]):
            errs.append("trailer last_lamport=%r but last event lamport=%r"
                        % (trailer.get("last_lamport"), last.get("lamport")))
    return errs


def _scan_record(record, where, errs):
    for k, v in record.items():
        if k in NONDET_FIELD_NAMES:
            errs.append("%s: nondeterministic field name %r" % (where, k))
        if isinstance(v, str) and _NONDET_VALUE_RE.search(v):
            errs.append("%s: field %r holds a nondeterministic value %r"
                        % (where, k, v))


def check_normalization(trace):
    """W4 deterministic-shape rules (on top of structure). Returns a list
    of violation strings (empty == normalized)."""
    errs = []
    header, events, trailer = trace["header"], trace["events"], trace["trailer"]
    if header is not None:
        _scan_record(header, "header", errs)
        run = header.get("run")
        if isinstance(run, str) and not STABLE_ID_RE.match(run):
            errs.append("header run id %r is not a stable identifier" % run)
    if trailer is not None:
        _scan_record(trailer, "trailer", errs)
    for i, ev in enumerate(events):
        _scan_record(ev, "event %d" % i, errs)
        th = ev.get("thread")
        if th is not None and not (isinstance(th, str) and STABLE_ID_RE.match(th)):
            errs.append("event %d thread %r is not a stable identifier" % (i, th))
    return errs


# -------------------------------------------------------------- verdicts --

def refinement_request(reasons):
    """The refinement-request artifact body (INCONCLUSIVE only). This is a
    REQUEST, not an effect: the formal plane may act on it, but nothing in
    the empirical path imports or calls it."""
    return {
        "_meta": REFINEMENT_META,
        "requested": ("complete the evidence (decision + every expected "
                      "participant applied) or refine the abstraction so "
                      "the witness path is feasible and fully observable"),
        "reasons": list(reasons),
    }


def make_verdict(verdict, trace_path, schedule_path, invariants,
                 violations, reasons, target=None, property_name=None):
    """Build the verdict artifact dict (deterministic: no timestamps)."""
    d = {
        "_meta": VERDICT_META,
        "format": FORMAT,
        "verdict": verdict,
        "target": target,
        "property": property_name,
        "trace": os.path.abspath(trace_path) if trace_path else None,
        "schedule": os.path.abspath(schedule_path) if schedule_path else None,
        "invariants": invariants,
        "violations": list(violations),
        "reasons": list(reasons),
    }
    if verdict == INCONCLUSIVE:
        d["refinement_request"] = refinement_request(reasons)
    return d


def write_verdict_artifact(path, verdict_dict):
    """Write the verdict artifact as deterministic JSON (sorted keys,
    2-space indent, trailing newline; NO generated-at timestamp, so
    repeated runs over the same inputs are byte-identical)."""
    d = {k: v for k, v in verdict_dict.items() if v is not None}
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, sort_keys=True)
        f.write("\n")
    return path