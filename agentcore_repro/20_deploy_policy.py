# -*- coding: utf-8 -*-
"""20_deploy_policy.py -- deploy the BUGGY spend-cap policy (temporal).

Renders agentcore_repro/policies/spendcap-buggy-agentcore.dw with the real
gateway ARN (+ the Cedar action name confirmed by 15_discover.py, if it
differs from the conventional default), creates it in the policy engine
(enforcementMode ACTIVE), and waits until ACTIVE.  If the real AgentCore
validator rejects the primary syntax candidate, it automatically retries with
the alternate candidate (spendcap-buggy-agentcore-alt.dw) and records which
form was accepted.

The Cedar statement is submitted as the ``cedar`` member of the
``--definition`` tagged union (``{"cedar": {"statement": ...}}``); if the
API rejects that branch it retries with the ``policy`` branch.

The deployed policy is the AgentCore-namespace twin of the repo's canonical
samples/spendcap-buggy.dw (same semantics, Drupe -> AgentCore namespaces).
ROTN's local verdict on the canonical file is what step 50 checks.

Usage:  python 20_deploy_policy.py
"""

import os
import sys

import common as C

POLICIES = os.path.join(C.HERE, "policies")
DEFAULT_ACTION = "TransferTarget___transfer"


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
        raise RuntimeError("unrendered placeholder left in %s: %s" % (fname, out))
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
    pe_id = st.get("policyEngineId")
    gw_arn = st.get("gatewayArn")
    if not pe_id or not gw_arn:
        C.die("run 10_setup.py first (missing policyEngineId/gatewayArn in state)")

    print("=" * 68)
    print("20_deploy_policy -- deploy BUGGY spend-cap (temporal) policy")
    print("=" * 68)

    # Reuse an existing policy in the engine if we created one before.
    existing_pol = st.get("policyId")
    if existing_pol:
        s = policy_status(pe_id, existing_pol)
        print("  [reuse] existing policy %s (status %s)" % (existing_pol, s))
        if s == "ACTIVE":
            print("  policy already ACTIVE; nothing to do")
            return
        # A stale/inactive policy blocks a clean demo; drop it.
        try:
            C.aws_raw("bedrock-agentcore-control", "delete-policy",
                      "--policy-engine-id", pe_id, "--policy-id", existing_pol,
                      check=False)
            print("  [cleanup] deleted stale policy %s" % existing_pol)
        except Exception:
            pass

    candidates = [
        ("primary", "spendcap-buggy-agentcore.dw"),
        ("alternate", "spendcap-buggy-agentcore-alt.dw"),
    ]
    def_keys = ["cedar", "policy"]   # tagged-union branches to try, in order

    pol_id = None
    accepted = None
    def_key_used = None
    for label, fname in candidates:
        statement = render(fname, st)
        for def_key in def_keys:
            print("\n-- trying %s candidate (%s) via definition branch '%s'"
                  % (label, fname, def_key))
            print("   statement:\n" + indent(statement))
            definition = {def_key: {"statement": statement}}
            rc, out = C.run(
                [C.aws_exe(), "bedrock-agentcore-control", "create-policy",
                 "--policy-engine-id", pe_id,
                 "--name", st["names"]["policy"],
                 "--definition", json_dumps(definition),
                 "--description",
                 "ROTN GAP-4 spendcap (temporal, 24h window, cap 200) [%s/%s]"
                 % (label, def_key),
                 "--validation-mode", "IGNORE_ALL_FINDINGS",
                 "--enforcement-mode", "ACTIVE",
                 "--output", "json"],
                check=False)
            if rc == 0:
                import json as _json
                d = _json.loads(out) if out.strip() else {}
                pol_id = d.get("policyId")
                accepted = fname
                def_key_used = def_key
                break
            else:
                print("   rejected (trying next branch/candidate)")
                print("   " + out.strip().replace("\n", "\n   ")[:600])
        if pol_id:
            break

    if not pol_id:
        C.die("all syntax candidates / definition branches were rejected by "
              "the real AgentCore validator -- see output above; adjust "
              "policies/*.dw (action name, temporal form) and retry")

    status = C.poll("policy %s" % pol_id,
                    lambda: policy_status(pe_id, pol_id),
                    timeout=300, interval=5,
                    want={"ACTIVE", "AVAILABLE", "READY"})
    print("\n  policy ACTIVE: %s (accepted form: %s)" % (pol_id, accepted))

    C.save_state({
        "policyId": pol_id,
        "policyName": st["names"]["policy"],
        "policyAcceptedForm": accepted,
        "policyDefinitionBranch": def_key_used,
        "policyDeployedUtc": C.now_iso(),
        "phase": "buggy-deployed",
    })
    print("\nNext: python 30_fire_parallel.py")


def indent(text, pad="   "):
    return "\n".join(pad + line for line in text.splitlines())


def json_dumps(obj):
    import json
    return json.dumps(obj)


if __name__ == "__main__":
    main()