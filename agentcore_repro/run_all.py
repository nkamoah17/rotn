# -*- coding: utf-8 -*-
"""run_all.py -- drive the whole GAP-4 repro in order.

Runs each step script in sequence, stopping (exit 0) at the two decision
points so a human can review before the money moves:

  00 preflight -> 10 setup -> 20 deploy buggy -> [PAUSE 1]
  30 fire      -> 40 evidence -> 50 rot catch/fix/prove -> [PAUSE 2]
  60 redeploy fixed + re-fire -> 40 evidence (final) -> 70 cleanup

Flags:
  --yes           do not pause (CI mode)
  --skip-cleanup  leave the stack up (for the video)
  --from N        resume from step N (e.g. --from 30)

Usage:  python run_all.py [--yes] [--skip-cleanup] [--from N]
"""

import os
import subprocess
import sys

import common as C

STEPS = [
    (0, "00_preflight.py", "preflight", True),
    (1, "10_setup.py", "setup", True),
    (2, "20_deploy_policy.py", "deploy buggy policy", True),
    (3, "30_fire_parallel.py", "FIRE 3 x $100 (buggy)", True),
    (4, "40_capture_evidence.py", "capture evidence (buggy)", True),
    (5, "50_rot_catch_fix_prove.py", "ROTN catch/fix/prove", True),
    (6, "60_redeploy_correct.py", "FIX + re-fire (correct)", True),
    (7, "40_capture_evidence.py", "capture evidence (final)", True),
    (8, "70_cleanup.py", "cleanup", True),
]
PAUSE_AFTER = {2: "PAUSE 1 -- buggy policy deployed. Review, then continue "
                  "(or run 30_fire_parallel.py yourself).",
               5: "PAUSE 2 -- ROTN verdict captured. Continue to fix+prove "
                  "(or run 60_redeploy_correct.py yourself)."}


def run_step(fname, hard=True):
    p = os.path.join(C.HERE, fname)
    print("\n" + "=" * 68)
    print("STEP: %s" % fname)
    print("=" * 68)
    r = subprocess.call([sys.executable, p])
    if r != 0 and hard:
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
            print("Re-run with the same --from index, or python run_all.py "
                  "--yes to continue.")
            sys.exit(0)
    print("\n[run_all] all steps complete.")
    print("Evidence: agentcore_repro/out/ (evidence.md, rot-verdict.md, "
          "fire-*.json)")


if __name__ == "__main__":
    main()