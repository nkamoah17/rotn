# -*- coding: utf-8 -*-
"""60_redeploy_correct.py -- deploy the FIXED policy and prove the cap holds.

1. Swap the engine's policy statement from the buggy twin to the correct
   twin (one word: ::response -> ::request), via update-policy on the SAME
   policy id.  Primary syntax candidate first, alternate fallback.
   (Temporal sessions are invalidated by policy updates anyway -- 409 on
   in-flight sessions -- so a fresh session is the right way to re-test.)
2. Wait until the policy is ACTIVE.
3. Re-fire the same 3 parallel $100 transfers with a FRESH session id
   (new session = fresh 24h window).
4. Spec prediction (runbook SS2): 2 ADMITTED ($200), 1 DENIED.  The live
    runs to date (runbook SS6, runs 2-3) admitted all three ($300) instead;
    the re-fire outcome is DATA to be read against the SS5 controls and the SS7 hypotheses (A/B/C) -- not a pass/fail gate.

E1 control (evidence): update-policy already runs under the STRICT
validation-mode default (FAIL_ON_ANY_FINDINGS); this step now also records
the validator's findings.  After update-policy it polls get-policy to a
terminal state and writes {status, statusReasons (verbatim), policyId,
timestamp, validationMode} to out/validation-findings.json (last write
wins -- it overwrites the buggy-policy capture from step 20).  If the
updated policy is not ACTIVE the run is INCONCLUSIVE (exit 2) and the
re-fire is skipped.

Exit codes: 0 = fixed policy ACTIVE + re-fire recorded;
            2 = INCONCLUSIVE (fixed policy not ACTIVE, findings recorded);
            3 = hard error (common.die).

Usage:  python 60_redeploy_correct.py
"""

import importlib.util
import json
import os
import sys
import uuid

import common as C

POLICIES = os.path.join(C.HERE, "policies")
DEFAULT_ACTION = "TransferTarget___transfer"


def load_fire_module():
    """Load 30_fire_parallel.py (digit-leading filename) as a module."""
    p = os.path.join(C.HERE, "30_fire_parallel.py")
    spec = importlib.util.spec_from_file_location("fire30", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def render(fname, st):
    """Render a policy template, substituting the gateway ARN and (if
    discovered) the real Cedar action name."""
    with open(os.path.join(POLICIES, fname), "r") as f:
        src = f.read()
    out = C.render_template(src, {"GATEWAY_ARN": st.get("gatewayArn", "")})
    action = st.get("cedarAction")
    if action and action != DEFAULT_ACTION:
        out = out.replace('AgentCore::Action::"%s"' % DEFAULT_ACTION,
                          'AgentCore::Action::"%s"' % action)
    if "{{" in out:
        raise RuntimeError("unrendered placeholder in %s" % fname)
    return out


def deploy_fixed(st):
    pe_id = st["policyEngineId"]
    pol_id = st.get("policyId")
    candidates = [
        ("primary", "spendcap-correct-agentcore.dw"),
        ("alternate", "spendcap-correct-agentcore-alt.dw"),
    ]
    def_keys = ["cedar", "policy"]
    for label, fname in candidates:
        statement = render(fname, st)
        for def_key in def_keys:
            definition = json.dumps({def_key: {"statement": statement}})
            print("\n-- updating policy with %s candidate (%s) via '%s'"
                  % (label, fname, def_key))
            rc, out = C.run(
                [C.aws_exe(), "bedrock-agentcore-control", "update-policy",
                 "--policy-engine-id", pe_id, "--policy-id", pol_id,
                 "--definition", definition,
                 "--output", "json"],
                check=False)
            if rc == 0:
                return fname
            print("   rejected by validator: "
                  + out.strip().replace("\n", " ")[:400])
    C.die("all fixed-policy candidates / definition branches rejected by the "
          "real AgentCore validator -- see output above")


def main():
    st = C.load_state()
    pe_id = st.get("policyEngineId")
    gw_arn = st.get("gatewayArn")
    gw_id = st.get("gatewayId")
    if not (pe_id and gw_arn and gw_id and st.get("policyId")):
        C.die("run 10_setup.py, 20_deploy_policy.py, 30_fire_parallel.py "
              "first (state incomplete)")

    print("=" * 68)
    print("60_redeploy_correct -- swap in the FIXED policy, re-fire, prove")
    print("=" * 68)

    accepted = deploy_fixed(st)
    print("  accepted form: %s" % accepted)
    # E1: record the validator's findings (update-policy already runs under
    # the strict FAIL_ON_ANY_FINDINGS default) -- poll get-policy to a
    # terminal state and save them to out/validation-findings.json.
    record = C.capture_policy_findings(pe_id, st["policyId"])
    status = record["status"]
    print("  policy terminal status: %s" % status)
    if status != "ACTIVE":
        # UPDATE_FAILED (or any other non-ACTIVE terminal state): the run
        # is INCONCLUSIVE, not a crash -- the findings are the evidence.
        C.save_state({
            "policyAcceptedFormFixed": accepted,
            "policyStatusFixed": status,
            "phase": "inconclusive",
        })
        print("\n" + "-" * 68)
        print("  *** INCONCLUSIVE: fixed policy terminal status %s" % status)
        print("      findings saved : out/validation-findings.json")
        print("      (re-fire skipped -- the corrected policy is not ACTIVE)")
        print("-" * 68)
        sys.exit(2)

    # Re-fire with a FRESH session (policy update invalidates the old one).
    fire = load_fire_module()
    session_id = str(uuid.uuid4())
    amount = 100
    nfires = 3
    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    C.ensure_out()
    print("\n-- re-firing %d x $%d in fresh session %s (path %s, tool %s)"
          % (nfires, amount, session_id, path, tool))
    started = []
    for i in range(1, nfires + 1):
        outfile = os.path.join(C.OUT_DIR, "fire-fixed-%d.json" % i)
        p = fire.start_invoke(gw_id, session_id, i, path, amount, outfile, tool)
        started.append((i, p, outfile))

    results = []
    for (i, p, outfile) in started:
        rc, out, err, dt = fire.wait_invoke(p)
        verdict = fire.classify(rc, outfile, out, err)
        results.append({
            "fire": i, "session_id": session_id, "amount": amount,
            "exit_code": rc, "verdict": verdict, "elapsed_s": round(dt, 3),
            "response_file": outfile,
        })
        print("  fire %d : %-9s rc=%s (%.2fs)" % (i, verdict, rc, dt))

    admitted = [r for r in results if r["verdict"] == "ADMITTED"]
    denied = [r for r in results if r["verdict"] == "DENIED"]
    committed = sum(r["amount"] for r in admitted)
    print("\n" + "-" * 68)
    print("  ADMITTED : %d fire(s), $%d committed" % (len(admitted), committed))
    print("  DENIED   : %d fire(s)" % len(denied))
    enforced = (len(denied) >= 1 and committed <= 200)
    if enforced:
        print("  CAP HELD THIS RUN: $%d committed (<= $200), %d denied"
              % (committed, len(denied)))
        print("      (spec-conformant outcome -- runbook SS2 prediction)")
    else:
        print("  $%d committed -- NOT the spec prediction ($200); read "
              "against runbook SS5/SS7 (hypotheses A/B/C)" % committed)
        print("      (per-fire detail: out/fire-fixed-*.json)")
    print("-" * 68)

    C.write_json("fixed-results.json", {
        "phase": "fixed",
        "session_id": session_id,
        "amount": amount, "nfires": nfires,
        "accepted_form": accepted,
        "results": results,
        "admitted_count": len(admitted),
        "denied_count": len(denied),
        "committed_usd": committed,
        "cap_enforced": enforced,
    })
    C.save_state({
        "policyAcceptedFormFixed": accepted,
        "fixedSessionId": session_id,
        "phase": "fixed",
    })
    print("\nRe-run 40_capture_evidence.py for the final evidence bundle.")
    print("Then: python 70_cleanup.py (or keep the stack for the video).")


if __name__ == "__main__":
    main()