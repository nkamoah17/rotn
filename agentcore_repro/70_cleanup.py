# -*- coding: utf-8 -*-
"""70_cleanup.py -- tear down every resource the repro created (idempotent).

Order: policies -> gateway targets -> gateway -> policy engine ->
lambda function (permissions) -> IAM roles (inline + managed).

Safe to run when some resources are missing.  Keeps out/evidence artifacts
and rewrites state.json with ``"cleaned": true`` (so you still have the
record).  Add ``--hard`` to also delete the out/ state file.

Usage:  python 70_cleanup.py [--hard]
"""

import json
import os
import sys
import time

import common as C


def try_cmd(args, desc):
    print("  -- %s" % desc)
    rc, out = C.run([C.aws_exe()] + args + ["--output", "json"],
                    check=False)
    if rc != 0:
        first = (out or "").strip().splitlines()
        print("     (skipped: %s)" % (first[0][:120] if first else "no output"))
    return rc


def main():
    hard = "--hard" in sys.argv
    st = C.load_state()
    pe_id = st.get("policyEngineId")
    gw_id = st.get("gatewayId")
    lambda_arn = st.get("lambdaArn", "")
    lambda_name = st.get("names", {}).get("lambda", C.names()["lambda"])
    gw_role = st.get("names", {}).get("gateway_role", C.names()["gateway_role"])
    lm_role = st.get("names", {}).get("lambda_role", C.names()["lambda_role"])

    print("=" * 68)
    print("70_cleanup -- tearing down the repro stack")
    print("=" * 68)

    # 1) policies in the engine
    if pe_id:
        try:
            d = C.aws_json("bedrock-agentcore-control", "list-policies",
                           "--policy-engine-id", pe_id)
            for p in d.get("items", d.get("policies", [])):
                pid = p.get("policyId")
                if pid:
                    try_cmd(["bedrock-agentcore-control", "delete-policy",
                             "--policy-engine-id", pe_id,
                             "--policy-id", pid],
                            "delete policy %s" % pid)
        except Exception as e:
            print("  (no policy list: %s)" % str(e)[:120])

    # 2) gateway targets
    if gw_id:
        try:
            d = C.aws_json("bedrock-agentcore-control",
                           "list-gateway-targets",
                           "--gateway-identifier", gw_id)
            for t in d.get("items", d.get("targets", [])):
                tn = t.get("name")
                if tn:
                    try_cmd(["bedrock-agentcore-control",
                             "delete-gateway-target",
                             "--gateway-identifier", gw_id,
                             "--name", tn],
                            "delete target %s" % tn)
        except Exception as e:
            print("  (no target list: %s)" % str(e)[:120])

    # 3) gateway
    if gw_id:
        try_cmd(["bedrock-agentcore-control", "delete-gateway",
                 "--gateway-identifier", gw_id],
                "delete gateway %s" % gw_id)
        time.sleep(3)

    # 4) policy engine
    if pe_id:
        try_cmd(["bedrock-agentcore-control", "delete-policy-engine",
                 "--policy-engine-id", pe_id],
                "delete policy engine %s" % pe_id)
        time.sleep(2)

    # 5) lambda function
    if lambda_name:
        try:
            C.aws_raw("lambda", "remove-permission",
                      "--function-name", lambda_name,
                      "--statement-id", "rot-agentcore-gateway", check=False)
        except Exception:
            pass
        try_cmd(["lambda", "delete-function", "--function-name", lambda_name],
                "delete lambda %s" % lambda_name)

    # 6) IAM roles
    for role in (gw_role, lm_role):
        if not role:
            continue
        try:
            d = C.aws_json("iam", "list-role-policies", "--role-name", role)
            for pol in d.get("PolicyNames", []):
                C.aws_raw("iam", "delete-role-policy", "--role-name", role,
                          "--policy-name", pol, check=False)
            d = C.aws_json("iam", "list-attached-role-policies",
                           "--role-name", role)
            for a in d.get("AttachedPolicies", []):
                C.aws_raw("iam", "detach-role-policy", "--role-name", role,
                          "--policy-arn", a["PolicyArn"], check=False)
        except Exception as e:
            print("  (role %s not found: %s)" % (role, str(e)[:100]))
            continue
        try_cmd(["iam", "delete-role", "--role-name", role],
                "delete role %s" % role)
        time.sleep(1)

    # 7) state
    if hard:
        if os.path.exists(C.STATE_PATH):
            os.remove(C.STATE_PATH)
        print("\nstate.json removed (--hard)")
    else:
        C.save_state({"cleaned": True, "cleaned_utc": C.now_iso()})
        print("\nstate.json marked cleaned (evidence preserved)")

    print("\nDone. The out/ evidence bundle is kept for the record.")


if __name__ == "__main__":
    main()