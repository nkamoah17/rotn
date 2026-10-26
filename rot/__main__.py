# -*- coding: utf-8 -*-
"""rot -- ROTN temporal policy verification engine, product CLI.

Subcommands
-----------
  rot check     Verify a policy (safety / realizability / liveness); on
                VIOLATED emit a narrative + an auditable attack.jsonl.
  rot replay    Re-derive a recorded attack.jsonl against a policy -- the
                verification loop that proves the counterexample is real.
  rot ci        CI gate: verdict + JUnit XML + SARIF artifacts.
  rot demo      The 5-phase spend-cap demo (PROVEN / VIOLATED / K-sweep /
                replay), exit-code aware like demo.sh.
  rot corpus    Run the AWS Dogwood spend-cap corpus; emit a coverage matrix.

Exit codes
----------
  0  PROVEN / PASS
  1  VIOLATED / BLOCK
  2  UNKNOWN
  3  ERROR

Pure stdlib; Python 3.6+.
"""

from __future__ import print_function

import argparse
import json
import os
import sys

import rot

EXIT_PROVEN = 0
EXIT_VIOLATED = 1
EXIT_UNKNOWN = 2
EXIT_ERROR = 3

_BAR = "=" * 74


def _repo_root():
    """Absolute path of the repository root (parent of the rot package)."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build_ir(policy_path, args):
    """Build a ProtocolIR from a policy file (narrow-waist front-end)."""
    import rot.frontends.policy as fe
    return fe.build_ir(
        policy_path,
        n_steps=1,
        kind=getattr(args, "kind", None),
        max_inflight=getattr(args, "max_inflight", None),
        amount=getattr(args, "amount", None),
        cap=getattr(args, "cap", None),
    )


def _verify(ir, args):
    """Check the IR's pinned property.

    Returns ``(status, witness, note)`` where status is one of
    ``"proven" | "violated" | "unknown"`` and witness is the violating
    state dict (or None). Mirrors the dispatch in pipeline._cmd_policy.
    """
    from rot.modelfind import ModelFinder, SAT, UNSAT

    kind = ir.metadata.get("property_kind") or "safety"
    prop_name = ir.metadata.get("property_name") or "policy_property"
    pred = lambda s: ir.pinned_property.eval(s)

    if kind == "liveness":
        from rot.config import Config
        from rot.invariants import Invariant, KIND_LIVENESS
        from rot.linearization import linearize
        from rot.symbolic import SymbolicEngine
        from rot.cegar import cegar_liveness

        horizon = getattr(args, "liveness_horizon", None) or 12
        cfg = Config(max_states=200000, liveness_horizon=horizon)
        prop = Invariant(
            name=prop_name,
            description="bounded liveness goal pinned by the policy front-end",
            expression=ir.pinned_property,
            kind=KIND_LIVENESS)
        reach = (SymbolicEngine(linearize(ir), max_states=cfg.max_states)
                 .reach_within(prop.expression, cfg.liveness_horizon,
                               max_states=cfg.max_states))
        verdict = cegar_liveness(reach, prop, cfg, "symbolic")
        witness = (verdict.evidence or {}).get("path")
        return verdict.status, witness, verdict.note or ""

    mf = ModelFinder.from_ir(ir)
    if kind == "realizability":
        result, witness = mf.exists_reachable(pred)
        if result == SAT:
            return "proven", None, ""
        if result == UNSAT:
            return "violated", witness, ""
        return "unknown", None, ""

    result, witness = mf.forall_reachable(pred)
    if result is True:
        return "proven", None, ""
    if result is False:
        return "violated", witness, ""
    return "unknown", None, ""


def _witness_steps(ir, witness):
    """Recover the BFS step path to a violating state.

    Returns a list of ``{"step", "action", "state"}`` records (state = the
    state after that step). Empty list if the path cannot be recovered.
    """
    from rot.modelfind import ModelFinder, ProductTooLarge

    mf = ModelFinder.from_ir(ir)
    try:
        steps = mf.path_to(witness)
    except ProductTooLarge:
        return []
    out = []
    for i, (before, action, delta) in enumerate(steps):
        after = dict(before)
        for k, v in delta.items():
            after[k] = v
        out.append({"step": i, "action": action.name, "state": after})
    return out


def _ensure_dir(path):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d)
    return d


def _write_attack_jsonl(path, meta, steps, violating_state):
    """Write the auditable counterexample file (JSONL, one record per line).

    Layout: a ``rotn-attack`` header, one record per attack step, then a
    ``rotn-attack-end`` trailer carrying the violating state.
    """
    _ensure_dir(path)
    head = dict(_meta="rotn-attack", format="v1")
    head.update(meta)
    lines = [json.dumps(head, sort_keys=True)]
    for s in steps:
        lines.append(json.dumps(s, sort_keys=True))
    lines.append(json.dumps({"_meta": "rotn-attack-end",
                             "violating_state": violating_state},
                            sort_keys=True))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _read_attack(path):
    """Parse an attack.jsonl. Returns (header, steps, trailer) or None."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                pass
    header = next((r for r in records if r.get("_meta") == "rotn-attack"),
                  None)
    if header is None:
        return None
    steps = [r for r in records if "step" in r and "action" in r]
    trailer = next((r for r in records
                    if r.get("_meta") == "rotn-attack-end"), None)
    return header, steps, trailer


def _narrative(policy, target, prop, kind, status, witness, steps,
               note, report_path, attack_path):
    """Print the human-readable verdict block."""
    print(_BAR)
    print("  ROTN verdict: %s" % status.upper())
    print(_BAR)
    print("  policy    : %s" % policy)
    print("  target    : %s" % target)
    print("  property  : %s (%s)" % (prop, kind))
    if note:
        print("  note      : %s" % note)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  witness   : %s" % w)
    if steps:
        print("  attack path (%d step%s):" % (len(steps),
                                              "s" if len(steps) != 1 else ""))
        for s in steps:
            try:
                st = json.dumps(s["state"], sort_keys=True)
            except (TypeError, ValueError):
                st = repr(s["state"])
            print("    %2d. %-16s %s" % (s["step"], s["action"], st))
    if report_path:
        print("  report    : %s" % report_path)
    if attack_path:
        print("  attack    : %s" % attack_path)
    print(_BAR)


def _code_for(status):
    return {"proven": EXIT_PROVEN, "violated": EXIT_VIOLATED,
            "unknown": EXIT_UNKNOWN}.get(status, EXIT_ERROR)



# ---------------------------------------------------------------------------
# rot check
# ---------------------------------------------------------------------------

def cmd_check(args):
    """Verify a policy; on VIOLATED emit narrative + attack.jsonl."""
    policy = args.policy
    import rot.frontends.policy as fe
    try:
        ir = _build_ir(policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()

    kind = ir.metadata.get("property_kind") or "safety"
    prop = ir.metadata.get("property_name") or "policy_property"
    target = "policy-" + os.path.basename(policy)
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    steps = []
    attack_path = None
    if status == "violated" and witness is not None:
        steps = _witness_steps(ir, witness)
        out_dir = args.out or os.path.join(_repo_root(), "out")
        attack_path = os.path.join(out_dir, "attack.jsonl")
        _write_attack_jsonl(attack_path, {
            "policy": policy,
            "target": target,
            "property": prop,
            "kind": kind,
            "verdict": "violated",
            "engine": "symbolic",
        }, steps, witness)

    report_path = None
    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        report_path = os.path.join(args.out, "report.json")
        report = {
            "target": target,
            "property_name": prop,
            "property_kind": kind,
            "verdict": status,
            "policy_source": ir.metadata.get("policy_source"),
            "witness": witness,
            "attack_path": steps,
        }
        if ir.metadata.get("max_inflight") is not None:
            report["max_inflight"] = ir.metadata["max_inflight"]
        if note:
            report["note"] = note
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True)

    if not args.quiet:
        _narrative(policy, target, prop, kind, status, witness, steps,
                   note, report_path, attack_path)
    return code


# ---------------------------------------------------------------------------
# rot replay
# ---------------------------------------------------------------------------

def cmd_replay(args):
    """Re-derive a recorded attack.jsonl against a policy.

    Without ``--policy`` this is a record-only inspection (prints the
    recorded attack). With ``--policy`` it re-runs the sound core and
    reports whether the counterexample reproduces -- the verification loop
    that closes the "is this attack real?" question.
    """
    path = args.attack
    if not os.path.isfile(path):
        print("ERROR: attack file not found: %s" % path, file=sys.stderr)
        return EXIT_ERROR
    parsed = _read_attack(path)
    if parsed is None:
        print("ERROR: not a rotn attack file (missing rotn-attack header): %s"
              % path, file=sys.stderr)
        return EXIT_ERROR
    header, steps, trailer = parsed
    recorded = trailer.get("violating_state") if trailer else None
    prop = header.get("property") or "policy_property"

    if not args.policy:
        print(_BAR)
        print("  ROTN replay (record-only -- no --policy given)")
        print(_BAR)
        print("  attack    : %s" % path)
        print("  property  : %s" % prop)
        print("  steps     : %d" % len(steps))
        if recorded is not None:
            try:
                r = json.dumps(recorded, sort_keys=True)
            except (TypeError, ValueError):
                r = repr(recorded)
            print("  violating : %s" % r)
        print(_BAR)
        return EXIT_VIOLATED

    import rot.frontends.policy as fe
    try:
        ir = _build_ir(args.policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    print(_BAR)
    print("  ROTN replay")
    print(_BAR)
    print("  attack    : %s" % path)
    print("  policy    : %s" % args.policy)
    print("  property  : %s" % prop)
    if recorded is not None:
        try:
            r = json.dumps(recorded, sort_keys=True)
        except (TypeError, ValueError):
            r = repr(recorded)
        print("  recorded  : %s" % r)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  re-derived: %s" % w)
    if status == "violated" and recorded is not None and witness == recorded:
        print("  result    : REPRODUCED -- the counterexample still holds")
    elif status == "violated":
        print("  result    : VIOLATED -- the policy is still unsafe "
              "(witness may differ)")
    elif status == "proven":
        print("  result    : NOT REPRODUCED -- the policy now proves safe")
    else:
        print("  result    : UNKNOWN -- the bounded search was inconclusive")
    if note:
        print("  note      : %s" % note)
    print(_BAR)
    return code



# ---------------------------------------------------------------------------
# rot ci
# ---------------------------------------------------------------------------

def _junit_xml(status, prop, witness):
    """Minimal JUnit XML (stdlib xml.sax.saxutils for escaping)."""
    import xml.sax.saxutils as sx
    n_fail = 1 if status == "violated" else 0
    if status == "violated":
        try:
            body = sx.escape(json.dumps(witness, sort_keys=True))
        except (TypeError, ValueError):
            body = sx.escape(repr(witness))
        case = ('    <testcase name="%s" classname="rot" time="0.0">\n'
                '      <failure message="%s" type="ROTNViolation">%s'
                '</failure>\n'
                '    </testcase>'
                % (sx.escape(prop), sx.escape("VIOLATED: %s" % prop), body))
    else:
        case = ('    <testcase name="%s" classname="rot" time="0.0"/>'
                % sx.escape(prop))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<testsuites name="rotn" tests="1" failures="%d" errors="0" '
            'skipped="0">\n'
            '  <testsuite name="rotn" tests="1" failures="%d" errors="0" '
            'skipped="0">\n'
            '%s\n'
            '  </testsuite>\n'
            '</testsuites>\n' % (n_fail, n_fail, case))


def _sarif(status, prop, witness, policy):
    """SARIF 2.1.0 result for the verdict (stdlib json only)."""
    level = {"proven": "note", "violated": "error",
             "unknown": "warning"}.get(status, "warning")
    text = "%s: %s" % (status.upper(), prop)
    if witness is not None:
        try:
            text += "  witness=" + json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            text += "  witness=" + repr(witness)
    return {
        "$schema": ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                    "master/Schemata/sarif-schema-2.1.0.json"),
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ROTN", "version": "0.1.0"}},
            "artifacts": [{"location": {"uri": "file://"
                                        + policy.replace("\\", "/")}}],
            "results": [{"ruleId": "rotn.%s" % prop,
                         "level": level,
                         "message": {"text": text}}],
        }],
    }


def cmd_ci(args):
    """CI gate: verdict + JUnit XML + SARIF artifacts."""
    policy = args.policy
    import rot.frontends.policy as fe
    try:
        ir = _build_ir(policy, args)
    except fe.PolicyFrontendError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    ir.validate()

    kind = ir.metadata.get("property_kind") or "safety"
    if kind != "safety":
        print("ERROR: rot ci supports safety policies only (got %r)" % kind,
              file=sys.stderr)
        return EXIT_ERROR
    prop = ir.metadata.get("property_name") or "policy_property"
    status, witness, note = _verify(ir, args)
    code = _code_for(status)

    out_dir = args.out or "ci"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    junit_path = os.path.join(out_dir, "JUnit.xml")
    sarif_path = os.path.join(out_dir, "results.sarif")
    with open(junit_path, "w") as f:
        f.write(_junit_xml(status, prop, witness))
    with open(sarif_path, "w") as f:
        json.dump(_sarif(status, prop, witness, policy),
                  f, indent=2, sort_keys=True)

    print(_BAR)
    print("  ROTN CI: %s  (%s)" % (status.upper(), prop))
    print(_BAR)
    if witness is not None:
        try:
            w = json.dumps(witness, sort_keys=True)
        except (TypeError, ValueError):
            w = repr(witness)
        print("  witness   : %s" % w)
    if note:
        print("  note      : %s" % note)
    print("  junit     : %s" % junit_path)
    print("  sarif     : %s" % sarif_path)
    print(_BAR)
    return code



# ---------------------------------------------------------------------------
# rot demo
# ---------------------------------------------------------------------------

def cmd_demo(args):
    """The 5-phase spend-cap demo, exit-code aware (mirrors demo.sh).

    Phase 1  PROVEN    correct.dw                 -> exit 0
    Phase 2  VIOLATED  buggy.dw                   -> exit 1 (+ attack.jsonl)
    Phase 3  REPLAY    attack.jsonl vs buggy.dw   -> exit 1 (reproduced)
    Phase 5  K-SWEEP   buggy.dw K=1/2/3           -> 0 / 1 / 1
    (Phase 4 crosscheck needs TLC/Java; see ``demo.sh`` for the full run.)
    """
    root = _repo_root()
    fx = os.path.join(root, "tests", "fixtures", "aws_dogwood",
                      "spendcap", "policies")
    correct = os.path.join(fx, "spendcap-correct.dw")
    buggy = os.path.join(fx, "spendcap-buggy.dw")
    for p in (correct, buggy):
        if not os.path.isfile(p):
            print("ERROR: fixture not found: %s" % p, file=sys.stderr)
            return EXIT_ERROR
    out_dir = args.out or os.path.join(root, "out", "demo")
    failures = []
    bar = "-" * 66

    def run(title, policy, k, expect, out=None):
        a = argparse.Namespace(policy=policy, kind=None, max_inflight=k,
                               amount=None, cap=None, out=out, quiet=True,
                               liveness_horizon=None)
        code = cmd_check(a)
        ok = code == expect
        if not ok:
            failures.append(title)
        print("  [%s] %-52s exit=%d expected=%d"
              % ("PASS" if ok else "FAIL", title, code, expect))
        return code

    print(bar)
    print("Phase 1 -- PROVEN: spendcap-correct.dw")
    print(bar)
    run("Phase 1 PROVEN (correct.dw)", correct, None, EXIT_PROVEN)

    print(bar)
    print("Phase 2 -- VIOLATED: spendcap-buggy.dw (witness + attack.jsonl)")
    print(bar)
    code2 = run("Phase 2 VIOLATED (buggy.dw)", buggy, None, EXIT_VIOLATED,
                out=out_dir)

    if code2 == EXIT_VIOLATED:
        attack = os.path.join(out_dir, "attack.jsonl")
        if os.path.isfile(attack):
            print(bar)
            print("Phase 3 -- REPLAY: attack.jsonl vs spendcap-buggy.dw")
            print(bar)
            a = argparse.Namespace(attack=attack, policy=buggy,
                                   max_inflight=None, liveness_horizon=None)
            code = cmd_replay(a)
            ok = code == EXIT_VIOLATED
            if not ok:
                failures.append("Phase 3 REPLAY")
            print("  [%s] %-52s exit=%d expected=%d"
                  % ("PASS" if ok else "FAIL", "Phase 3 REPLAY (attack.jsonl)",
                     code, EXIT_VIOLATED))
        else:
            print("  [SKIP] no attack.jsonl produced in %s" % out_dir)

    print(bar)
    print("Phase 5 -- K-SWEEP: buggy policy vs the concurrency pool K")
    print(bar)
    run("Phase 5 K=1 masked (buggy.dw --max-inflight 1)", buggy, 1,
        EXIT_PROVEN)
    run("Phase 5 K=2 VIOLATED (buggy.dw --max-inflight 2)", buggy, 2,
        EXIT_VIOLATED)
    run("Phase 5 K=3 VIOLATED clean fire (buggy.dw --max-inflight 3)",
        buggy, 3, EXIT_VIOLATED)

    print(bar)
    if failures:
        print("DEMO FAILED: %d phase(s) deviated: %s"
              % (len(failures), ", ".join(failures)))
        return EXIT_VIOLATED
    print("DEMO OK: all phases behaved as expected. "
          "(Phase 4 crosscheck needs TLC/Java -- run demo.sh for it.)")
    return EXIT_PROVEN



# ---------------------------------------------------------------------------
# rot corpus
# ---------------------------------------------------------------------------

def cmd_corpus(args):
    """Run every .dw policy under the corpus dir; emit a coverage matrix."""
    root = _repo_root()
    corpus_dir = args.corpus_dir or os.path.join(
        root, "tests", "fixtures", "aws_dogwood", "spendcap", "corpus")
    if not os.path.isdir(corpus_dir):
        print("ERROR: corpus dir not found: %s" % corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    policies = []
    for dirpath, dirnames, filenames in os.walk(corpus_dir):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.endswith(".dw"):
                policies.append(os.path.join(dirpath, fn))
    if not policies:
        print("ERROR: no .dw policies under %s" % corpus_dir, file=sys.stderr)
        return EXIT_ERROR

    print("Discovered %d policies under %s" % (len(policies), corpus_dir))
    results = []
    for p in policies:
        name = os.path.relpath(p, corpus_dir)
        a = argparse.Namespace(policy=p, kind=None,
                               max_inflight=args.max_inflight, amount=None,
                               cap=None, out=None, quiet=True,
                               liveness_horizon=None)
        entry = {"policy": name, "property": None, "kind": None,
                 "verdict": None, "witness": None, "error": None}
        try:
            ir = _build_ir(p, a)
            ir.validate()
            entry["kind"] = (ir.metadata.get("property_kind") or "safety")
            entry["property"] = ir.metadata.get("property_name")
            if entry["kind"] == "safety":
                status, witness, _note = _verify(ir, a)
                entry["verdict"] = status
                entry["witness"] = witness
            else:
                entry["verdict"] = "unsupported"
        except Exception as exc:
            entry["error"] = str(exc)
        results.append(entry)
        v = entry["verdict"] or "ERROR"
        w = ""
        if entry.get("witness") is not None:
            try:
                w = json.dumps(entry["witness"], sort_keys=True)
            except (TypeError, ValueError):
                w = repr(entry["witness"])
        print("  %-44s %-12s %s" % (name[:44], v, w))

    summary = {}
    for r in results:
        key = r["verdict"] or "error"
        summary[key] = summary.get(key, 0) + 1

    print(_BAR)
    print("  ROTN corpus coverage matrix (%d policies)" % len(results))
    print(_BAR)
    for k in sorted(summary):
        print("  %-12s %d" % (k, summary[k]))
    print(_BAR)

    if args.out:
        if not os.path.isdir(args.out):
            os.makedirs(args.out)
        matrix_path = os.path.join(args.out, "corpus_matrix.json")
        with open(matrix_path, "w") as f:
            json.dump({"corpus_dir": corpus_dir, "summary": summary,
                       "results": results}, f, indent=2, sort_keys=True)
        print("  matrix      : %s" % matrix_path)

    if summary.get("error") or summary.get("unsupported"):
        return EXIT_ERROR
    if summary.get("violated"):
        return EXIT_VIOLATED
    if summary.get("unknown"):
        return EXIT_UNKNOWN
    return EXIT_PROVEN



# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _add_policy_opts(p):
    p.add_argument("--policy", required=True, metavar="FILE",
                   help="policy file (.dw / .cedar / .json)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap .dw policies)")
    p.add_argument("--amount", type=int, default=None, metavar="N",
                   help="per-request amount override (spend-cap .dw policies)")
    p.add_argument("--cap", type=int, default=None, metavar="N",
                   help="spend cap override (spend-cap .dw policies)")
    p.add_argument("--kind", default=None,
                   choices=["safety", "realizability", "liveness"],
                   help="property kind [default: auto-route by extension]")


def main(argv=None):
    """ROTN CLI entry point. Returns the process exit code."""
    parser = argparse.ArgumentParser(
        prog="rot",
        description="ROTN -- temporal policy verification engine "
                    "(sound core, zero dependencies).")
    parser.add_argument("--version", action="version",
                        version="rot " + rot.__version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser(
        "check", help="verify a policy; emit verdict + attack.jsonl")
    _add_policy_opts(p)
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for report.json / attack.jsonl "
                        "[default: <repo>/out]")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the human summary")

    p = sub.add_parser(
        "replay", help="re-derive a recorded attack.jsonl")
    p.add_argument("attack", metavar="ATTACK_JSONL",
                   help="attack file written by 'rot check'")
    p.add_argument("--policy", default=None, metavar="FILE",
                   help="policy to re-verify against "
                        "(record-only inspection without it)")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K (spend-cap policies)")
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")

    p = sub.add_parser(
        "ci", help="CI gate: verdict + JUnit XML + SARIF")
    _add_policy_opts(p)
    p.add_argument("--liveness-horizon", type=int, default=None, metavar="H",
                   help="bounded liveness horizon (liveness policies)")
    p.add_argument("--out", default="ci", metavar="DIR",
                   help="artifact dir [default: ci]")

    p = sub.add_parser("demo", help="the 5-phase spend-cap demo")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir [default: <repo>/out/demo]")

    p = sub.add_parser("corpus", help="run the AWS Dogwood corpus")
    p.add_argument("--corpus-dir", default=None, metavar="DIR",
                   help="corpus dir [default: "
                        "tests/fixtures/aws_dogwood/spendcap/corpus]")
    p.add_argument("--max-inflight", type=int, default=None, metavar="K",
                   help="bounded concurrency pool K")
    p.add_argument("--out", default=None, metavar="DIR",
                   help="output dir for corpus_matrix.json")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return EXIT_ERROR
    return {"check": cmd_check, "replay": cmd_replay, "ci": cmd_ci,
            "demo": cmd_demo, "corpus": cmd_corpus}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

