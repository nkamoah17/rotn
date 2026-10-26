# -*- coding: utf-8 -*-
"""Phase 2 W7 -- minimal logging-policy optimizer.

The probe (twopc-java) can emit every event unconditionally (W2 default) or a
policy-selected subset. This module DERIVES that policy from the replay/verdict
obligations (the W4 invariant names) at minimum recording cost, and CHECKS that
a produced trace is consistent with the policy.

Contract
--------
Input:
  obligations  -- subset of the W4 invariant names:
                   agreement, validity, decision_before_apply
  weights      -- optional per-class recording cost (default 1.0 each)

Output: a deterministic v1 policy document (JSON):
  enabled / disabled event classes, the requirement map that justified them,
  the cost, a stable content digest (sha256, no timestamps), and the exact
  agent property the Java probe consumes (rotn.probe.filter).

Evidence basis (derived, documented here on purpose so this module stays
decoupled from the formal plane): the W4 judge (rot.tracecheck) reasons ONLY
about SPEC events -- 'applied_<i>=<value>', 'decision=<value>' payloads and
their gseq ordering (see tracecheck.applied_from_events / _decide_gseq /
_decision_value; TraceEvent.java: "the trace checker (W4) reasons only about
SPEC events"). SEND/RECV are environment detail kept for auditability; no
minimal obligation in the current set requires them.

Solver: the class universe is tiny (3), so "minimum cost covering set" is
solved by exhaustive subset search in canonical order -- exact and
provably minimal, and trivially general if the requirement map grows.

Determinism: no timestamps, no randomness; identical inputs -> byte-identical
policy documents (verified by test_phase2_w7).

NEVER-REFINES: read-only optimizer over obligation names; it does not import
rot.cegar / rot.abstraction / rot.pipeline / modelfind / tracecheck.

CLI (pure stdlib):
  python -m rot.logpolicy derive --obligations a,v,dba [--weights SPEC=2.0]
         [--out out/policy.json] [--json]
  python -m rot.logpolicy check --policy out/policy.json --trace trace.jsonl

Exit codes: 0 ok/consistent, 1 failure (bad policy check), 2 usage error.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys

try:  # package context (python -m rot.logpolicy)
    from . import tracefmt
except ImportError:  # flat script context (python rot/logpolicy.py)
    import tracefmt

FORMAT = "v1"

# Event classes in the probe vocabulary (TraceEvent.Kind).
CLASSES = ("SEND", "RECV", "SPEC")

# obligation -> event classes whose recording it REQUIRES.
# Derived from the W4 judge's evidence extraction (see module docstring).
REQUIREMENTS = {
    "agreement": ("SPEC",),
    "validity": ("SPEC",),
    "decision_before_apply": ("SPEC",),
}

DEFAULT_WEIGHTS = {c: 1.0 for c in CLASSES}

# The exact Java probe hook that consumes the policy (Probe.java reads it).
AGENT_PROPERTY = "rotn.probe.filter"


class PolicyError(ValueError):
    """Unknown obligation / class / weight key, or unsatisfiable policy."""


def _norm_classes(value, what):
    if isinstance(value, str):
        value = [value]
    out = []
    for v in value:
        s = str(v).strip().upper()
        if s not in CLASSES:
            raise PolicyError("unknown %s: %r (allowed: %s)"
                              % (what, v, ", ".join(CLASSES)))
        if s not in out:
            out.append(s)
    return out


def _canonical_weights(weights):
    """Dict of weights covering all classes (defaults filled in)."""
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        for k, v in weights.items():
            s = str(k).strip().upper()
            if s not in CLASSES:
                raise PolicyError("unknown weight class: %r" % (k,))
            w[s] = float(v)
    return w


def _covers(classes, obligations):
    req = set()
    for o in obligations:
        req.update(REQUIREMENTS[o])
    return req <= set(classes)


def _subsets(items, r):
    items = list(items)
    if r == 0:
        yield ()
        return
    if r > len(items):
        return
    for i in range(len(items) - r + 1):
        for tail in _subsets(items[i + 1:], r - 1):
            yield (items[i],) + tail


def min_cost_enabled(obligations, weights):
    """The minimum-cost class set covering every obligation.

    Exhaustive subset search over CLASSES (2^3 subsets), canonical order:
    ascending cost, then ascending tuple. Exact for any requirement map.
    Returns (enabled_sorted, cost, requirement_map).
    """
    req_map = {o: sorted(set(REQUIREMENTS[o])) for o in sorted(obligations)}
    w = _canonical_weights(weights)
    req_all = set()
    for o in obligations:
        req_all.update(REQUIREMENTS[o])
    if not req_all:
        return [], 0.0, req_map
    best = None
    for r in range(len(CLASSES) + 1):
        for combo in _subsets(CLASSES, r):
            if not _covers(combo, obligations):
                continue
            cost = sum(w[c] for c in combo)
            key = (cost, combo)
            if best is None or key < best[0]:
                best = (key, combo)
    if best is None:
        raise PolicyError("no class set satisfies the obligations: %s"
                          % sorted(obligations))
    return sorted(best[1]), sum(w[c] for c in best[1]), req_map


def derive_policy(obligations, weights=None):
    """Validate obligations and compute the minimal policy.

    Returns (enabled, cost, requirement_map). Raises PolicyError on unknown
    obligation names. Deterministic for identical inputs.
    """
    if isinstance(obligations, str):
        obligations = [obligations]
    norm = []
    for o in obligations:
        o = str(o).strip().lower()
        if o not in REQUIREMENTS:
            raise PolicyError("unknown obligation: %r (allowed: %s)"
                              % (o, ", ".join(sorted(REQUIREMENTS))))
        if o not in norm:
            norm.append(o)
    return min_cost_enabled(norm, weights)


def canonical_content(obligations, enabled, weights):
    """The exact content the digest is computed over (canonical JSON)."""
    w = _canonical_weights(weights)
    if isinstance(obligations, str):
        obligations = [obligations]
    return json.dumps(
        {"format": FORMAT,
         "obligations": sorted(str(o).strip().lower() for o in obligations),
         "enabled": sorted(str(c).strip().upper() for c in enabled),
         "weights": {k: float(w[k]) for k in sorted(w)}},
        sort_keys=True, separators=(",", ":"))


def policy_document(obligations, weights=None):
    """Build the deterministic v1 policy document (dict, JSON-encodable)."""
    if isinstance(obligations, str):
        obligations = [obligations]
    enabled, cost, req_map = derive_policy(obligations, weights)
    w = _canonical_weights(weights)
    disabled = [c for c in CLASSES if c not in enabled]
    return {
        "format": FORMAT,
        "obligations": sorted(set(str(o).strip().lower() for o in obligations)),
        "enabled": enabled,
        "disabled": disabled,
        "requirement": {o: req_map[o] for o in sorted(req_map)},
        "cost": {
            "weight": {c: float(w[c]) for c in CLASSES},
            "total": cost,
            "enabled_classes": len(enabled),
            "total_classes": len(CLASSES),
        },
        "digest": "sha256:" + hashlib.sha256(
            canonical_content(obligations, enabled, weights).encode("utf-8")
            ).hexdigest(),
        "agent": {
            "property": AGENT_PROPERTY,
            "value": ",".join(enabled) if enabled else "",
        },
    }


def write_policy(path, doc):
    """Write the policy document deterministically (byte-stable)."""
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(doc, sort_keys=True, indent=2) + "\n")
    return path


def load_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise PolicyError("not a v1 policy document: %s" % path)
    if not isinstance(doc.get("enabled"), list):
        raise PolicyError("policy document has no 'enabled' list: %s" % path)
    return doc


def check_trace_against_policy(doc, trace_path, max_examples=5):
    """Cross-check a produced trace against the policy.

    Returns (ok, problems) where problems is a list of human-readable strings:
      * any recorded event whose kind is not policy-enabled (lists gseqs)
      * any obligation whose required class is absent from the trace
        (the W4 judge would then be INCONCLUSIVE, not a definite verdict)
    Structurally invalid traces are reported, never raised.
    """
    problems = []
    enabled = _norm_classes(doc.get("enabled"), "policy enabled")
    enabled_set = set(enabled)
    trace = tracefmt.load_trace(trace_path)
    if trace["parse_errors"]:
        problems.append("trace parse errors: %s"
                        % "; ".join(trace["parse_errors"][:3]))
    if trace["header"] is None or trace["trailer"] is None:
        problems.append("trace is missing header or trailer")
    events = trace["events"]

    offenders = [ev for ev in events
                 if str(ev.get("kind", "")).upper() not in enabled_set]
    if offenders:
        gs = ", ".join(str(ev.get("gseq")) for ev in offenders[:max_examples])
        more = "" if len(offenders) <= max_examples else " (and %d more)" % (
            len(offenders) - max_examples)
        bad = sorted({str(ev.get("kind")).upper() for ev in offenders})
        problems.append("trace records %d event(s) of disabled class(es) %s "
                        "at gseq %s%s"
                        % (len(offenders), ",".join(bad), gs, more))

    obligations = doc.get("obligations") or []
    if isinstance(obligations, str):
        obligations = [obligations]
    present = {str(ev.get("kind", "")).upper() for ev in events}
    for o in sorted(obligations):
        o = str(o).strip().lower()
        if o not in REQUIREMENTS:
            problems.append("policy has unknown obligation: %s" % o)
            continue
        for cls in REQUIREMENTS[o]:
            if cls not in present:
                problems.append("obligation '%s' requires class %s but the "
                                "trace records none (verdict would be "
                                "INCONCLUSIVE, never a definite verdict)"
                                % (o, cls))
    return (not problems), problems


# ----------------------------------------------------------------------- CLI --

def _cmd_derive(args):
    weights = {}
    for item in (args.weights or []):
        if "=" not in item:
            raise PolicyError("bad --weights entry %r (want CLASS=number)" % item)
        k, v = item.split("=", 1)
        weights[k] = float(v)
    obligations = [o for o in (args.obligations or "").split(",") if o.strip()]
    if not obligations:
        raise PolicyError("no obligations given (use --obligations a,b,c)")
    doc = policy_document(obligations, weights or None)
    if args.json:
        print(json.dumps(doc, sort_keys=True, indent=2))
    else:
        print("W7 policy: obligations=%s enabled=%s disabled=%s cost=%.2f "
              "digest=%s agent: -D%s=%s"
              % (",".join(doc["obligations"]), ",".join(doc["enabled"]),
                 ",".join(doc["disabled"]) or "(none)", doc["cost"]["total"],
                 doc["digest"], doc["agent"]["property"],
                 doc["agent"]["value"] or "(log nothing)"))
    if args.out:
        write_policy(args.out, doc)
        if not args.json:
            print("wrote %s" % args.out)
    return 0


def _cmd_check(args):
    doc = load_policy(args.policy)
    ok, problems = check_trace_against_policy(doc, args.trace)
    if ok:
        print("W7 check: CONSISTENT -- trace %s satisfies policy %s "
              "(enabled=%s, obligations=%s)"
              % (args.trace, args.policy, ",".join(doc["enabled"]),
                 ",".join(doc["obligations"])))
        return 0
    print("W7 check: INCONSISTENT (%d problem(s))" % len(problems))
    for p in problems:
        print("  - " + p)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rot.logpolicy",
        description="Phase 2 W7 minimal logging-policy optimizer")
    sub = parser.add_subparsers(dest="cmd")
    d = sub.add_parser("derive", help="derive the minimal policy (default)")
    d.add_argument("--obligations", default="",
                   help="comma-separated: agreement,validity,decision_before_apply")
    d.add_argument("--weights", action="append", default=[],
                   help="per-class cost CLASS=number (repeatable; default 1.0)")
    d.add_argument("--out", default=None, help="write the policy document here")
    d.add_argument("--json", action="store_true", help="print JSON to stdout")
    c = sub.add_parser("check",
                       help="check a trace against a policy document")
    c.add_argument("--policy", required=True)
    c.add_argument("--trace", required=True)

    # Bare form (no subcommand) = derive, for shell convenience.
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] not in ("derive", "check", "-h", "--help"):
        argv = ["derive"] + list(argv)
    args = parser.parse_args(argv)
    if args.cmd == "check":
        try:
            return _cmd_check(args)
        except (PolicyError, OSError) as exc:
            print("W7 check: ERROR: %s" % exc)
            return 2
    try:
        return _cmd_derive(args)
    except (PolicyError, ValueError) as exc:
        print("W7 derive: ERROR: %s" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())