# -*- coding: utf-8 -*-
"""schedulecheck.py -- W3: validate a witness replay schedule (the replay contract).

A schedule is the JSONL emitted by ``rot.witness.write_schedule``: one header
record (``_meta: rotn-schedule``) followed by one step record per gate action
(``{"owner": ..., "action": ..., "step": ...}``). The Java ReplayGate consumes
exactly this contract, so this module is its Python-side checker:

  * header first, ``_meta == "rotn-schedule"``, ``format == "v1"``,
    ``n_steps`` equals the number of step records
  * steps are 0-based, strictly increasing, gap-free
  * action names match the gate vocabulary and their owner is implied:
      vote_<i>_yes|no -> participant_<i>; decide -> coordinator; apply_<i> -> participant_<i>
  * no duplicated gate step
  * every participant voted before decide; every apply comes after decide
  * header ``witness_path`` (when present) matches the step action sequence
    with non-gate steps (init/done) removed

Exit codes: 0 = valid, 1 = invalid, 2 = usage error.
Pure stdlib, Python 3.6 compatible.
"""
from __future__ import print_function

import io
import json
import os
import re
import sys

SCHEDULE_META = "rotn-schedule"

_VOTE_RE = re.compile(r"vote_(\d+)(?:_yes|_no)$")
_APPLY_RE = re.compile(r"apply_(\d+)$")


def _owner_for_action(action):
    """Model owner implied by a gate action, or None if not a gate action."""
    if not isinstance(action, str):
        return None
    m = _VOTE_RE.match(action)
    if m:
        return "participant_%s" % m.group(1)
    if action == "decide":
        return "coordinator"
    m = _APPLY_RE.match(action)
    if m:
        return "participant_%s" % m.group(1)
    return None


def load_schedule(path):
    """Parse one schedule file. Returns (header, steps, errors)."""
    header = None
    steps = []
    errors = []
    try:
        f = io.open(path, "r", encoding="utf-8")
    except (IOError, OSError) as exc:
        return header, steps, ["cannot open %s: %s" % (path, exc)]
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
            if obj.get("_meta") == SCHEDULE_META:
                if header is not None:
                    errors.append("line %d: duplicate header" % lineno)
                header = obj
                continue
            if header is None:
                errors.append("line %d: step before header" % lineno)
                continue
            owner = obj.get("owner")
            action = obj.get("action")
            if not isinstance(owner, str) or owner == "":
                errors.append("line %d: missing/invalid owner" % lineno)
            if not isinstance(action, str) or action == "":
                errors.append("line %d: missing/invalid action" % lineno)
            if not isinstance(obj.get("step"), int):
                errors.append("line %d: missing/invalid step number" % lineno)
            steps.append(obj)
    finally:
        f.close()
    return header, steps, errors


def check_schedule(header, steps):
    """Validate header+steps. Returns (ok, lines, errors)."""
    errors = []
    if header is None:
        return False, ["  header: MISSING"], ["no header record (_meta=rotn-schedule)"]
    if header.get("_meta") != SCHEDULE_META:
        errors.append("header _meta is %r, want %r" % (header.get("_meta"), SCHEDULE_META))
    if header.get("format") != "v1":
        errors.append("header format is %r, want 'v1'" % (header.get("format"),))
    if not isinstance(header.get("n_steps"), int):
        errors.append("header n_steps missing/invalid")
    elif header["n_steps"] != len(steps):
        errors.append("header n_steps=%d but file has %d step records"
                      % (header["n_steps"], len(steps)))

    seen = set()
    vote_idx = {}
    decide_at = None
    apply_at = {}
    for i, s in enumerate(steps):
        owner = s.get("owner")
        action = s.get("action")
        step = s.get("step")
        if isinstance(step, int) and step != i:
            errors.append("step %d: step number %r out of order (expected %d)"
                          % (i, step, i))
        if not isinstance(owner, str) or not isinstance(action, str):
            continue
        expected_owner = _owner_for_action(action)
        if expected_owner is None:
            errors.append("step %d: unknown gate action %r" % (i, action))
        elif owner != expected_owner:
            errors.append("step %d: action %r owned by %s, schedule says %s"
                          % (i, action, expected_owner, owner))
        key = (owner, action)
        if key in seen:
            errors.append("step %d: duplicated gate step (%s, %s)" % (i, owner, action))
        seen.add(key)
        m = _VOTE_RE.match(action)
        if m:
            vote_idx[int(m.group(1))] = i
        if action == "decide":
            if decide_at is not None:
                errors.append("step %d: duplicated decide" % i)
            else:
                decide_at = i
        m = _APPLY_RE.match(action)
        if m:
            apply_at[int(m.group(1))] = i

    if decide_at is None:
        errors.append("no decide step: infeasible for the replay demo")
    else:
        for p in sorted(apply_at):
            if apply_at[p] < decide_at:
                errors.append("participant_%d applies before decide (infeasible)" % p)
        participants = set(list(vote_idx) + list(apply_at))
        for p in sorted(participants):
            if p not in vote_idx or vote_idx[p] > decide_at:
                errors.append("participant_%d did not vote before decide" % p)

    wp = header.get("witness_path")
    if isinstance(wp, list):
        gate_only = [a for a in wp if isinstance(a, str)
                     and _owner_for_action(a) is not None]
        actual = [s.get("action") for s in steps if isinstance(s.get("action"), str)]
        if gate_only != actual:
            errors.append("witness_path gate actions %r != step actions %r"
                          % (gate_only, actual))

    ok = not errors
    lines = ["  checks: %d step(s)" % len(steps)]
    for e in errors:
        lines.append("  ERROR: %s" % e)
    lines.append("  verdict: %s" % ("VALID" if ok else "INVALID"))
    return ok, lines, errors


def check_file(path):
    """Convenience: load + check one schedule file. Returns (ok, lines)."""
    header, steps, errors = load_schedule(path)
    lines = ["  parse: %d step record(s)" % len(steps)]
    for e in errors:
        lines.append("  parse ERROR: %s" % e)
    if header is None and not steps:
        return False, lines
    ok, check_lines, _ = check_schedule(header, steps)
    return ok, lines + check_lines


def main(argv):
    paths = argv[1:]
    if not paths:
        print(__doc__)
        return 2
    all_ok = True
    for path in paths:
        print("[schedule] %s" % os.path.abspath(path))
        ok, lines = check_file(path)
        for ln in lines:
            print(ln)
        all_ok = all_ok and ok
    print("")
    if all_ok:
        print("W3 SCHEDULE CHECK: PASS (%d/%d)" % (len(paths), len(paths)))
        return 0
    print("W3 SCHEDULE CHECK: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

