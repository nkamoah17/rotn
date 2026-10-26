# -*- coding: utf-8 -*-
"""witness.py -- witness *path* extraction + W3 replay schedule emission.

Phase 1 verdicts (out/*.json) carry a counterexample *state*. Phase 2 W3 needs
more: the *sequence of model actions* that reaches it, because the Java
scheduler gate (twopc-java ReplayGate) replays that sequence as a total order
of (owner, action) steps.

Pipeline (all deterministic, declared-action-order, so results are stable):

    targets.build(target, n)          -- ProtocolIR (rot.twopc)
      --(linearize, rot.linearization)--> LinearModel
      --(find_witness_path, this module)--> ordered action-name path
      --(witness_to_schedule)--> [(owner, action), ...]
      --(write_schedule)--> JSONL schedule file (Java ReplayGate input)

Only model actions that have a Java gate point become steps:
vote_<i>_yes|no, decide, apply_<i>.  Actions without a Java gate point
(init, done) are listed in the header for audit but are no-ops at replay
time.  The gate consumes steps strictly in file order.

Usage (module form; the relative imports require -m):
    python -m rot.witness --target buggy --n 2 --property agreement \
                          --out out\\schedule-buggy.jsonl

Exit codes: 0 = witness found + schedule written, 1 = no witness, 2 = usage.
Pure stdlib, Python 3.6 compatible.
"""
from __future__ import print_function

import argparse
import json
import os

import rot.targets as targets
from .linearization import linearize
from .ir import Expr

UNDEF = Expr.UNDEF


def find_witness_path(model, prop_expr, max_states=200000):
    """Breadth-first search over the LinearModel for a definite violation.

    Returns (path, state) where ``path`` is the ordered list of action names
    (excluding init, which is already applied in ``model.init_state``) leading
    to ``state``, a state in which ``prop_expr`` evaluates to a definite False.

    Determinism: actions are tried in declared order (model.actions), and the
    search is a plain BFS over concrete states -- so the first witness found
    is stable across runs. Returns (None, None) if no definite violation is
    reachable within the budget.
    """
    init = dict(model.init_state)
    if prop_expr.eval(init) is False:
        return ([], init)
    seen = {frozenset(init.items())}
    queue = [(init, [])]
    i = 0
    while i < len(queue) and len(seen) < max_states:
        state, path = queue[i]
        i += 1
        for a in model.actions:
            try:
                g = a.guard.eval(state)
            except Exception:
                g = UNDEF
            if g is not True:
                continue  # guard not definitely enabled (False or UNDEF)
            ns = model._apply_effects(state, a.effects)
            if prop_expr.eval(ns) is False:
                return (path + [a.name], ns)
            # True or UNDEF: keep exploring (UNDEF must not prune)
            k = frozenset(ns.items())
            if k not in seen:
                seen.add(k)
                queue.append((ns, path + [a.name]))
    return (None, None)


def find_witness(target, prop, n=3, max_states=200000):
    """Resolve target/property and run the witness search.

    Returns dict: target, property, n, path (list|None), state (dict|None).
    """
    ir = targets.build(target, n=n)
    inv = targets.get_property(target, prop, n=n)
    model = linearize(ir)
    path, state = find_witness_path(model, inv.expression, max_states)
    return {
        "target": target,
        "property": prop,
        "n": int(n),
        "path": path,
        "state": state,
    }


# -- schedule emission ------------------------------------------------------
def _step_for_action(action):
    """Map a model action name to a Java gate step (owner, action), or None
    if the action has no Java gate point (init, done)."""
    if action.startswith("vote_"):
        rest = action[len("vote_"):]
        i, _, vote = rest.partition("_")
        if not i or not vote:
            return None
        return ("participant_%s" % i, action)
    if action == "decide":
        return ("coordinator", "decide")
    if action.startswith("apply_"):
        i = action[len("apply_"):]
        if not i:
            return None
        return ("participant_%s" % i, action)
    return None  # init, done, unknown


def witness_to_schedule(path):
    """Ordered [(owner, action)] steps for the Java replay gate.

    Actions without a Java gate point (init, done) are skipped; the resulting
    schedule must still be a feasible order for the Java program under the
    gate (the gate only enforces relative order at its gate points).
    """
    steps = []
    for action in path:
        s = _step_for_action(action)
        if s is not None:
            steps.append(s)
    return steps


def write_schedule(out_path, result, steps):
    """Write the JSONL schedule file (header + one step object per line)."""
    d = os.path.dirname(os.path.abspath(out_path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    header = {
        "_meta": "rotn-schedule",
        "format": "v1",
        "target": result["target"],
        "property": result["property"],
        "n": result["n"],
        "witness_path": list(result["path"] or []),
        "violating_state": result["state"],
        "n_steps": len(steps),
    }
    lines = [json.dumps(header, sort_keys=False)]
    for idx, (owner, action) in enumerate(steps):
        lines.append(json.dumps(
            {"owner": owner, "action": action, "step": idx},
            sort_keys=False))
    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return out_path


def load_schedule(path):
    """Parse a schedule file. Returns (header, steps, errors)."""
    errors = []
    header = None
    steps = []
    with open(path, "r") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except ValueError as exc:
                errors.append("line %d: invalid JSON: %s" % (lineno, exc))
                continue
            if obj.get("_meta") == "rotn-schedule":
                header = obj
            elif "owner" in obj and "action" in obj:
                steps.append((obj["owner"], obj["action"]))
            else:
                errors.append("line %d: not a header or step record" % lineno)
    if header is None:
        errors.append("no rotn-schedule header")
    return header, steps, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="buggy", choices=["correct", "buggy"])
    ap.add_argument("--n", type=int, default=2)
    ap.add_argument("--property", dest="prop", default="agreement")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-states", type=int, default=200000)
    args = ap.parse_args(argv)

    result = find_witness(args.target, args.prop, n=args.n,
                          max_states=args.max_states)
    if result["path"] is None:
        print("WITNESS: not found for target=%s property=%s n=%d"
              % (args.target, args.prop, args.n))
        return 1
    steps = witness_to_schedule(result["path"])
    if not steps:
        print("WITNESS: found but maps to zero Java gate steps: %r"
              % result["path"])
        return 1
    out = write_schedule(args.out, result, steps)
    print("WITNESS: target=%s property=%s n=%d" % (args.target, args.prop, args.n))
    print("  path    : %s" % " -> ".join(result["path"]))
    print("  state   : %s" % json.dumps(result["state"], sort_keys=True))
    print("  steps   : %d" % len(steps))
    print("  schedule: %s" % out)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
