# -*- coding: utf-8 -*-
"""run_all.py -- drive the whole GAP-4 repro in order.

Runs each step script in sequence, stopping (exit 0) at the two decision
points so a human can review before the money moves:

  00 preflight -> 10 setup -> 20 deploy buggy (E1: findings recorded)
  -> [PAUSE 1]
  31 fire 5 x $100 SEQUENTIAL (buggy baseline)
  -> 30 fire 3 x $100 PARALLEL (buggy) -> 40 evidence (buggy)
  -> 50 rot catch/fix/prove -> [PAUSE 2]
  60 redeploy fixed (E1: findings recorded) + re-fire
  -> E2 31 (corrected, 5 x $100 sequential, records events.jsonl)
  -> E3 63 (one $300 fire, fresh session)
  -> E4 64 (reference replay of E2's events -- local, no AWS)
  -> 40 evidence (final) -> 70 cleanup

A step that exits 2 (INCONCLUSIVE -- the policy did not reach ACTIVE under
FAIL_ON_ANY_FINDINGS, with the validator's findings saved to
out/validation-findings.json) halts the pipeline: the runbook reports that
outcome as inconclusive, and a rejected policy must not be fired.

Flags:
  --yes           do not pause (CI mode)
  --skip-cleanup  leave the stack up (for the video)
  --from N        resume from STEPS index N (0 = preflight; the pause
                  messages print the index to resume with)

Usage:  python run_all.py [--yes] [--skip-cleanup] [--from N]
"""

import os
import subprocess
import sys

import common as C

STEPS = [
    (0, "00_preflight.py", "preflight", True),
    (1, "10_setup.py", "setup", True),
    (2, "20_deploy_policy.py", "deploy buggy policy (E1: findings recorded)", True),
    (3, "31_fire_sequential.py", "FIRE 5 x $100 SEQUENTIAL (buggy baseline)", True),
    (4, "30_fire_parallel.py", "FIRE 3 x $100 PARALLEL (buggy)", True),
    (5, "40_capture_evidence.py", "capture evidence (buggy)", True),
    (6, "50_rot_catch_fix_prove.py", "ROTN catch/fix/prove", True),
    (7, "60_redeploy_correct.py", "FIX + re-fire (correct) + E1 findings", True),
    (8, "31_fire_sequential.py", "E2: 5 x $100 SEQUENTIAL (corrected)", True),
    (9, "63_test_single300.py", "E3: one $300 fire (corrected)", True),
    (10, "64_replay_reference.py", "E4: reference replay of E2 (local)", True),
    (11, "40_capture_evidence.py", "capture evidence (final)", True),
    (12, "70_cleanup.py", "cleanup", True),
]
PAUSE_AFTER = {2: "PAUSE 1 -- buggy policy deployed (E1 findings in "
                  "out/validation-findings.json). Review, then continue "
                  "(or run 31_fire_sequential.py yourself).",
               6: "PAUSE 2 -- ROTN verdict captured. Continue to fix+prove "
                  "(or run 60_redeploy_correct.py yourself)."}


def run_step(fname, hard=True):
    p = os.path.join(C.HERE, fname)
    print("\n" + "=" * 68)
    print("STEP: %s" % fname)
    print("=" * 68)
    r = subprocess.call([sys.executable, p])
    if r != 0 and hard:
        if r == 2:
            print("\n[run_all] step %s exited 2 = INCONCLUSIVE (the policy "
                  "did not reach ACTIVE under FAIL_ON_ANY_FINDINGS; the "
                  "validator's findings are in out/validation-findings.json). "
                  "Halting: the runbook reports this as inconclusive, not a "
                  "crash, and a rejected policy must not be fired. Inspect "
                  "the findings before reading any live behavior as an "
                  "engine bug." % fname)
        else:
            print("\n[run_all] step %s exited %d -- stopping" % (fname, r))
        sys.exit(r)
    return r


def main():
    yes = "--yes" in sys.argv
    skip_cleanup = "--skip-cleanup" in sys.argv
    start = 0
    if "--from" in sys.argv:
        start = int(sys.argv[sys.argv.index("--from") + 1])

    for (idx, fname, desc, hard) in STEPS:
        if idx < start:
            continue
        if not hard:
            continue
        if skip_cleanup and fname == "70_cleanup.py":
            print("\n[run_all] skipping cleanup (--skip-cleanup)")
            continue
        run_step(fname, hard=hard)
        if idx in PAUSE_AFTER and not yes:
            print("\n" + PAUSE_AFTER[idx])
            print("To continue: python run_all.py --from %d   (or add "
                  "--yes to run the rest without pausing)" % (idx + 1))
            sys.exit(0)
    print("\n[run_all] all steps complete.")
    print("Evidence: agentcore_repro/out/ (evidence.md, rot-verdict.md, "
          "sequential5-results.json, single300.json, e4-report.json, "
          "validation-findings.json, fire-*.json)")


if __name__ == "__main__":
    main()