# -*- coding: utf-8 -*-
"""20_deploy_policy.py -- deploy the BUGGY spend-cap policy (temporal).

Renders agentcore_repro/policies/spendcap-buggy-agentcore.dw with the real
gateway ARN (+ the Cedar action name confirmed by 15_discover.py, if it
differs from the conventional default), creates it in the policy engine
(enforcementMode ACTIVE, validationMode FAIL_ON_ANY_FINDINGS), and waits
until the policy reaches a terminal state.  If the real AgentCore validator
rejects the primary syntax candidate, it automatically retries with the
alternate candidate (spendcap-buggy-agentcore-alt.dw) and records which
form was accepted.

E1 control (no suppressed findings): the deployment uses the STRICT
validation mode FAIL_ON_ANY_FINDINGS (the API default), not
IGNORE_ALL_FINDINGS.  After create-policy it polls get-policy to a
terminal state and records {status, statusReasons (verbatim), policyId,
timestamp, validationMode} to out/validation-findings.json
(common.capture_policy_findings).  If the policy ends CREATE_FAILED, the
run is INCONCLUSIVE (exit 2 -- not a crash): the findings are the
evidence, and the live behavior of a rejected policy must not be read as
an engine bug.

The Cedar statement is submitted as the ``cedar`` member of the
``--definition`` tagged union (``{"cedar": {"statement": ...}}``); if the
API rejects that branch it retries with the ``policy`` branch.

The deployed policy is the AgentCore-namespace twin of the repo's canonical
samples/spendcap-buggy.dw (same semantics, Drupe -> AgentCore namespaces).
ROTN's local verdict on the canonical file is what step 50 checks.

Exit codes: 0 = policy ACTIVE (findings recorded);
            2 = INCONCLUSIVE (terminal status != ACTIVE, findings recorded);
            3 = hard error (common.die).

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
                 "--validation-mode", "FAIL_ON_ANY_FINDINGS",
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

    # E1: poll to a TERMINAL state (ACTIVE or CREATE_FAILED) and record the
    # validator's findings verbatim to out/validation-findings.json.
    record = C.capture_policy_findings(pe_id, pol_id)
    status = record["status"]
    print("\n  policy terminal status: %s (accepted form: %s)"
          % (status, accepted))

    if status != "ACTIVE":
        # CREATE_FAILED (or any other non-ACTIVE terminal state): the run
        # is INCONCLUSIVE, not a crash -- the findings are the evidence.
        C.save_state({
            "policyId": pol_id,
            "policyName": st["names"]["policy"],
            "policyAcceptedForm": accepted,
            "policyDefinitionBranch": def_key_used,
            "policyDeployedUtc": C.now_iso(),
            "policyStatus": status,
            "phase": "inconclusive",
        })
        print("\n" + "-" * 68)
        print("  *** INCONCLUSIVE: policy terminal status %s under" % status)
        print("      validationMode=FAIL_ON_ANY_FINDINGS")
        print("      findings saved : out/validation-findings.json")
        print("      (a run with unresolved findings is reported")
        print("       inconclusive -- inspect the findings before reading")
        print("       any live behavior as an engine bug)")
        print("-" * 68)
        sys.exit(2)

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