# -*- coding: utf-8 -*-
# DEPRECATED: superseded by 31_fire_sequential.py (runbook E2 control, three-way verdict); kept as a historical artifact -- its out/sequential-results.json is still cited by the runbook SS6 run 3.
"""62_test_sequential.py -- fire 3 transfers SEQUENTIALLY under the request-sum policy.

Discriminates the two explanations for the concurrent $300:
  * NON-REFLEXIVE window (semantic): sequential fires still give $300
    (fire#3 sees prior-sum 200, 200<=200 -> admitted).
  * REFLEXIVE but RACY (TOCTOU): sequential fires give $200 (fire#3 sees
    total 300 -> denied), because decisions are serialized when not concurrent.

Uses the currently-deployed policy (the request-sum "correct" twin) -- no
redeploy.  Fresh session so the 24h window starts empty.
Usage:  python 62_test_sequential.py
"""

import importlib.util
import os
import uuid

import common as C


def load_fire():
    p = os.path.join(C.HERE, "30_fire_parallel.py")
    spec = importlib.util.spec_from_file_location("fire30", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    st = C.load_state()
    if not st.get("gatewayArn") or not st.get("gatewayId"):
        C.die("run 10_setup.py first")

    fire = load_fire()
    session_id = str(uuid.uuid4())
    amount, nfires = 100, 3
    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    C.ensure_out()

    print("=" * 68)
    print("62_test_sequential -- 3 x $%d, ONE AT A TIME (session %s)"
          % (amount, session_id))
    print("=" * 68)

    results = []
    for i in range(1, nfires + 1):
        outfile = os.path.join(C.OUT_DIR, "fire-seq-%d.json" % i)
        p = fire.start_invoke(st.get("gatewayId"), session_id, i, path,
                              amount, outfile, tool)
        rc, out, err, dt = fire.wait_invoke(p)
        verdict = fire.classify(rc, outfile, out, err)
        results.append({"fire": i, "verdict": verdict, "amount": amount,
                        "exit_code": rc, "elapsed_s": round(dt, 3)})
        print("  fire %d : %-9s rc=%s (%.2fs)" % (i, verdict, rc, dt))

    admitted = [r for r in results if r["verdict"] == "ADMITTED"]
    denied = [r for r in results if r["verdict"] == "DENIED"]
    committed = sum(r["amount"] for r in admitted)
    print("\n" + "-" * 68)
    print("  ADMITTED : %d fire(s), $%d committed" % (len(admitted), committed))
    print("  DENIED   : %d fire(s)" % len(denied))
    if denied and committed <= 200:
        print("  => REFLEXIVE engine: sequential fire is capped ($200).")
        print("     The concurrent $300 was a TOCTOU race, not a semantic gap.")
    else:
        print("  => NON-REFLEXIVE window: even sequential fire overshoots ($300).")
        print("     The cap is off-by-one-request; no concurrency involved.")
    print("-" * 68)

    C.write_json("sequential-results.json", {
        "session_id": session_id, "results": results,
        "admitted_count": len(admitted), "denied_count": len(denied),
        "committed_usd": committed,
        "sequential_cap_enforced": bool(denied and committed <= 200),
    })
    print("\nwrote out/sequential-results.json")


if __name__ == "__main__":
    main()