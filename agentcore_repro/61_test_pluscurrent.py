# -*- coding: utf-8 -*-
"""61_test_pluscurrent.py -- deploy the `+ context.input.amount` variant and re-fire.

Purpose: determine live AgentCore's window semantics.

  * If the engine SERIALIZES decisions, `sum + current <= 200` yields
    2 admitted / 1 denied ($200) -- the non-reflexive-window fix works.
  * If the engine RACES decisions (TOCTOU), all 3 read prior-sum 0 and are
    admitted ($300) -- no sum-policy can close the concurrent gap.

Reuses 30_fire_parallel's invoke/classify and 60's deploy helpers.
Usage:  python 61_test_pluscurrent.py
"""

import importlib.util
import os
import uuid
import json

import common as C

TEMPLATE = "spendcap-pluscurrent-agentcore.dw"
DEFAULT_ACTION = "TransferTarget___transfer"


def load_mod(fname, name):
    p = os.path.join(C.HERE, fname)
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def render(st):
    with open(os.path.join(C.HERE, "policies", TEMPLATE), "r") as f:
        src = f.read()
    out = C.render_template(src, {"GATEWAY_ARN": st.get("gatewayArn", "")})
    action = st.get("cedarAction")
    if action and action != DEFAULT_ACTION:
        out = out.replace('AgentCore::Action::"%s"' % DEFAULT_ACTION,
                          'AgentCore::Action::"%s"' % action)
    if "{{" in out:
        raise RuntimeError("unrendered placeholder in %s" % TEMPLATE)
    return out


def policy_status(pe_id, pol_id):
    try:
        d = C.aws_json("bedrock-agentcore-control", "get-policy",
                       "--policy-engine-id", pe_id, "--policy-id", pol_id)
        return d.get("status", d.get("policyStatus", "?"))
    except Exception as e:
        return "ERR:" + str(e)[:80]


def main():
    st = C.load_state()
    pe_id = st["policyEngineId"]
    pol_id = st.get("policyId")
    if not (pe_id and pol_id and st.get("gatewayArn")):
        C.die("run 10_setup.py + 20_deploy_policy.py first")

    print("=" * 68)
    print("61_test_pluscurrent -- deploy `+ context.input.amount`, re-fire")
    print("=" * 68)

    statement = render(st)
    definition = json.dumps({"policy": {"statement": statement}})
    print("\n-- update-policy with %s (branch: policy)" % TEMPLATE)
    rc, out = C.run([C.aws_exe(), "bedrock-agentcore-control", "update-policy",
                     "--policy-engine-id", pe_id, "--policy-id", pol_id,
                     "--definition", definition, "--output", "json"], check=False)
    if rc != 0:
        C.die("pluscurrent policy rejected by validator: "
              + out.strip().replace("\n", " ")[:500])
    print("   accepted")
    status = C.poll("policy %s" % pol_id,
                    lambda: policy_status(pe_id, pol_id),
                    timeout=300, interval=5,
                    want={"ACTIVE", "AVAILABLE", "READY"})
    print("   policy ACTIVE: %s" % status)

    fire = load_mod("30_fire_parallel.py", "fire30")
    session_id = str(uuid.uuid4())
    amount, nfires = 100, 3
    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    C.ensure_out()
    print("\n-- re-firing %d x $%d in fresh session %s" % (nfires, amount, session_id))
    started = []
    for i in range(1, nfires + 1):
        outfile = os.path.join(C.OUT_DIR, "fire-pc-%d.json" % i)
        p = fire.start_invoke(gw_id(st), session_id, i, path, amount, outfile, tool)
        started.append((i, p, outfile))
    results = []
    for (i, p, outfile) in started:
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
        print("  *** CAP ENFORCED: serialized decisions; `+ current` is the live fix ***")
    else:
        print("  (all admitted -> TOCTOU race: decisions are not serialized)")
    print("-" * 68)

    C.write_json("pluscurrent-results.json", {
        "template": TEMPLATE, "session_id": session_id,
        "results": results, "admitted_count": len(admitted),
        "denied_count": len(denied), "committed_usd": committed,
        "cap_enforced": bool(denied and committed <= 200),
    })
    print("\nwrote out/pluscurrent-results.json")


def gw_id(st):
    return st.get("gatewayId")


if __name__ == "__main__":
    main()