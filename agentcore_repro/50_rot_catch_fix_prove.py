# -*- coding: utf-8 -*-
"""50_rot_catch_fix_prove.py -- ROTN catches the bug, proves the fix.

Runs the repo's own verification pipeline (pipeline.py) against the
canonical Drupe-namespace policy files:

  * buggy   samples/spendcap-buggy.dw     -> expect exit 1 (VIOLATED)
  * correct samples/spendcap-correct.dw   -> expect exit 0 (PROVEN)

with ``--max-inflight 3`` (the clean witness: completed=0, in-flight=3,
$300 admitted), then cross-checks the local witness against the LIVE AWS
evidence captured in steps 30/40 (fire-results.json + evidence.json):

  * same shape: 3 parallel $100 fires in one session
  * same outcome: $300 admitted over the $200 cap

Writes out/rot-verdict.md -- the "ROTN catch/fix/prove" page of the story.

Pipeline exit codes (pipeline.py): 0 proven, 1 violated, 2 unknown, 3 error.

Usage:  python 50_rot_catch_fix_prove.py
"""

import json
import os
import subprocess
import sys

import common as C

REPO = C.REPO_ROOT
CANON = {
    "buggy": [
        os.path.join(REPO, "samples", "spendcap-buggy.dw"),
        os.path.join(REPO, "tests", "fixtures", "aws_dogwood", "spendcap",
                     "policies", "spendcap-buggy.dw"),
    ],
    "correct": [
        os.path.join(REPO, "samples", "spendcap-correct.dw"),
        os.path.join(REPO, "tests", "fixtures", "aws_dogwood", "spendcap",
                     "policies", "spendcap-correct.dw"),
    ],
}
MAX_INFLIGHT = 3


def pick(kind):
    for p in CANON[kind]:
        if os.path.exists(p):
            return p
    C.die("canonical %s policy not found (looked in %s)"
          % (kind, ", ".join(CANON[kind])))


def run_pipeline(policy, outdir):
    cmd = [sys.executable, os.path.join(REPO, "pipeline.py"),
           "--policy", policy,
           "--max-inflight", str(MAX_INFLIGHT),
           "--out", outdir]
    print("\n$ %s" % " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, cwd=REPO)
    out, _ = p.communicate(timeout=600)
    text = out.decode("utf-8", "replace")
    print(text[-2500:])
    return p.returncode, text


def find_witness(outdir):
    if not os.path.isdir(outdir):
        return None, None
    for fn in ("attack.jsonl", "witness.json", "counterexample.json"):
        p = os.path.join(outdir, fn)
        if os.path.exists(p):
            return p, open(p).read()[:4000]
    for root, _dirs, files in os.walk(outdir):
        for fn in files:
            if fn.endswith(".jsonl") or "witness" in fn:
                p = os.path.join(root, fn)
                return p, open(p).read()[:4000]
        # the pipeline's per-property report JSON carries the witness
        for fn in sorted(files):
            if fn.endswith(".json") and "spendcap" in fn:
                p = os.path.join(root, fn)
                try:
                    d = json.load(open(p))
                except Exception:
                    continue
                if isinstance(d, dict) and "witness" in json.dumps(d)[:2000]:
                    return p, json.dumps(d, indent=2)[:4000]
    return None, None


def load_json(name):
    p = os.path.join(C.OUT_DIR, name)
    if os.path.exists(p):
        with open(p, "r") as f:
            return json.load(f)
    return None


def main():
    print("=" * 68)
    print("50_rot_catch_fix_prove -- ROTN local verdict on the canonical policies")
    print("=" * 68)

    buggy = pick("buggy")
    correct = pick("correct")
    print("  buggy  : %s" % buggy)
    print("  correct: %s" % correct)

    # 1) buggy -> VIOLATED (exit 1) + witness
    ob = os.path.join(C.OUT_DIR, "rot-live-buggy")
    rc_b, out_b = run_pipeline(buggy, ob)
    wb, wbtext = find_witness(ob)
    # 2) correct -> PROVEN (exit 0)
    oc = os.path.join(C.OUT_DIR, "rot-live-correct")
    rc_c, out_c = run_pipeline(correct, oc)

    catch_ok = (rc_b == 1)
    prove_ok = (rc_c == 0)
    print("\n" + "-" * 68)
    print("  CATCH (buggy VIOLATED, exit 1)   : %s (got %d)"
          % ("PASS" if catch_ok else "FAIL", rc_b))
    print("  PROVE (correct PROVEN, exit 0)   : %s (got %d)"
          % ("PASS" if prove_ok else "FAIL", rc_c))
    print("-" * 68)

    # 3) cross-check local witness vs live AWS evidence
    live = load_json("fire-results.json")
    live_match = (live is not None
                  and live.get("admitted_count") == MAX_INFLIGHT
                  and live.get("committed_usd") == 300)
    print("  LIVE cross-check (3 admitted, $300 > $200 cap): %s"
          % ("PASS" if live_match else
             "FAIL (run 30_fire_parallel.py + 40_capture_evidence.py first)"))

    verdict = {
        "buggy_policy": buggy,
        "correct_policy": correct,
        "max_inflight": MAX_INFLIGHT,
        "buggy_exit_code": rc_b,
        "correct_exit_code": rc_c,
        "catch": catch_ok,
        "prove": prove_ok,
        "live_cross_check": live_match,
        "witness_file": wb,
        "witness_excerpt": wbtext,
        "live": live,
        "pipeline_tail_buggy": out_b[-1500:],
        "pipeline_tail_correct": out_c[-1500:],
        "all_green": catch_ok and prove_ok and live_match,
    }
    C.write_json("rot-verdict.json", verdict)
    C.write_text("rot-verdict.md", render_md(verdict))

    if verdict["all_green"]:
        print("\n*** ALL GREEN: ROTN caught the bug, proved the fix, and the "
              "live AWS run matches the local witness ***")
        print("Next: python 60_redeploy_correct.py")
    else:
        print("\nSome checks failed -- see out/rot-verdict.md")
        sys.exit(1)


def render_md(v):
    L = []
    L.append("# ROTN catch / fix / prove (GAP-4)")
    L.append("")
    L.append("| check | result |")
    L.append("|---|---|")
    L.append("| buggy policy VIOLATED (exit 1 expected) | %s |"
             % ("PASS" if v["catch"] else "FAIL (got %d)" % v["buggy_exit_code"]))
    L.append("| correct policy PROVEN (exit 0 expected) | %s |"
             % ("PASS" if v["prove"] else "FAIL (got %d)" % v["correct_exit_code"]))
    L.append("| live AWS: 3 admitted, $300 > $200 cap | %s |"
             % ("PASS" if v["live_cross_check"] else "FAIL"))
    L.append("")
    L.append("## Local witness (buggy, K=%d)" % v["max_inflight"])
    L.append("")
    L.append("```\n%s\n```\n" % (v["witness_excerpt"] or "(no witness file found)"))
    L.append("## Pipeline tail (buggy)\n\n```\n%s\n```\n" % v["pipeline_tail_buggy"])
    L.append("## Pipeline tail (correct)\n\n```\n%s\n```\n" % v["pipeline_tail_correct"])
    L.append("## Live evidence\n\n```\n%s\n```\n"
             % json.dumps(v["live"], indent=2)[:3000])
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()