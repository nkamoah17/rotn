# -*- coding: utf-8 -*-
"""15_discover.py -- confirm the live tool name, MCP path, and Cedar names.

Runs after 10_setup.py (gateway + target exist) and before 20_deploy_policy.py.

Two jobs, both using the official AgentCore CLI against the real gateway:

  1. tools/list  -- call the gateway's MCP ``tools/list`` to learn the exact
     tool name to use in ``tools/call`` and the working endpoint path.
     Stored in state as ``toolName`` / ``mcpPath`` (used by 30_fire_parallel).

  2. policy generate -- run AWS's own Cedar policy generator for a spend-cap
     requirement.  The returned statement is validated against the gateway's
     tool schema, so it is the ground truth for the Cedar ``::Action::`` and
     ``::Gateway::`` identifiers (used by 20_deploy_policy / 60_redeploy to
     render the temporal templates).  Stored in state as ``cedarAction`` /
     ``cedarResource`` and saved to out/policy-generated.json.

If either job fails (e.g. the generator is unavailable), the conventional
defaults are kept so the remaining steps can still run; the failure is
recorded in state as ``discover{Tool,Cedar}Ok``.

Usage:  python 15_discover.py
"""

import json
import os
import uuid

import common as C

DEFAULT_TOOL = "TransferTarget___transfer"
PATHS = ["/mcp", "/", "/tools/call"]

CAP_PROMPT = (
    "Allow calls to the transfer tool, but only while the sum of the "
    "'amount' argument over the last 24 hours for this session is at most "
    "200. Deny the call once the running 24-hour total would exceed 200."
)


def discover_tool(gw_id):
    """Try tools/list on candidate paths; return (tool, path).

    Falls back to (DEFAULT_TOOL, PATHS[0]) if none succeed.
    """
    payload = json.dumps({"jsonrpc": "2.0", "id": 0,
                          "method": "tools/list", "params": {}})
    last_err = ""
    for path in PATHS:
        C.ensure_out()
        safe = path.strip("/").replace("/", "_") or "root"
        outfile = os.path.join(C.OUT_DIR, "tools-list-%s.json" % safe)
        rc, out, err, dt = C.gateway_invoke(
            gw_id, path, "POST", payload, outfile,
            session_id=str(uuid.uuid4()))
        blob = ((out or "") + (err or "")).lower()
        if rc == 0:
            tool = None
            try:
                with open(outfile, "r", errors="replace") as f:
                    body = json.load(f)
                tools = body.get("result", {}).get("tools", [])
                if tools:
                    tool = tools[0].get("name")
            except Exception:
                tool = None
            return (tool or DEFAULT_TOOL), path
        last_err = ((out or "") + (err or ""))[-400:]
        C.log("  path %s -> rc=%s" % (path, rc))
    C.log("  tools/list failed on all paths; using defaults. last: %s" % last_err)
    return DEFAULT_TOOL, PATHS[0]


def discover_cedar(gw_id):
    """Run the AWS Cedar generator; return (action, resource) or (None, None)."""
    try:
        res = C.policy_generate(gw_id, CAP_PROMPT)
    except Exception as e:
        C.log("  policy generate failed: %s" % str(e)[:300])
        return None, None
    C.write_json("policy-generated.json", res)
    stmt = None
    try:
        stmt = res["policies"][0]["statement"]
    except Exception:
        stmt = None
    if not stmt:
        C.log("  generator returned no statement")
        return None, None
    return C.extract_cedar_names(stmt)


def main():
    st = C.load_state()
    gw_id = st.get("gatewayId")
    if not gw_id:
        C.die("run 10_setup.py first (missing gatewayId in state)")

    print("=" * 68)
    print("15_discover -- confirm live tool name, MCP path, Cedar names")
    print("=" * 68)
    print("  gateway : %s" % st.get("gatewayArn"))

    C.ensure_out()
    update = {}

    print("\n-- tools/list (MCP tool discovery)")
    tool, path = discover_tool(gw_id)
    print("  tool  : %s" % tool)
    print("  path  : %s" % path)
    update["toolName"] = tool
    update["mcpPath"] = path
    update["discoverToolOk"] = True

    print("\n-- Cedar policy generate (AWS oracle for action/resource names)")
    action, resource = discover_cedar(gw_id)
    print("  action   : %s" % (action or "(default TransferTarget___transfer)"))
    print("  resource : %s" % (resource or "(default <gateway ARN>)"))
    if action:
        update["cedarAction"] = action
    if resource:
        update["cedarResource"] = resource
    update["discoverCedarOk"] = bool(action or resource)

    C.save_state(update)
    print("\nSaved to state. Next: python 20_deploy_policy.py")


if __name__ == "__main__":
    main()