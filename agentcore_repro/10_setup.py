# -*- coding: utf-8 -*-
"""10_setup.py -- build the AWS side of the repro (idempotent).

Creates, in dependency order:
  1. IAM roles:  gateway service role (trusts bedrock-agentcore.amazonaws.com)
                 lambda execution role (+ AWSLambdaBasicExecutionRole for logs)
  2. Policy engine (temporal policies live here; the gateway points at it)
  3. Lambda function ``<p>-transfer-mock`` (the mock bank-transfer backend)
     + lambda:AddPermission so AgentCore Gateway may invoke it
  4. AgentCore Gateway (protocol MCP, authorizer AWS_IAM,
     policyEngineConfiguration = {arn, mode: ENFORCE}, exceptionLevel DEBUG)
  5. Gateway target ``TransferTarget`` (MCP lambda target, tool ``transfer``)

Every resource is looked up first by name/arn and reused if present, so the
script is safe to re-run.  Writes out/state.json for the later steps.

Usage:  python 10_setup.py
"""

import base64
import io
import json
import os
import sys
import time
import zipfile

import common as C

N = C.names()
REGION = C.region()


def iam_policy_arn(name):
    return "arn:aws:iam::aws:policy/%s" % name


def account_id():
    try:
        ident = C.aws_json("sts", "get-caller-identity")
        return ident.get("Account", "")
    except Exception:
        return ""


# ---------------------------------------------------------------- roles ---

def ensure_roles():
    print("\n-- 1/5 IAM roles")
    acct = account_id()
    if not acct:
        C.die("cannot resolve account id (sts get-caller-identity failed)")

    # --- gateway service role ---
    grole_arn = _ensure_role(
        N["gateway_role"],
        trust="bedrock-agentcore.amazonaws.com",
        inline={
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "InvokeTransferMock", "Effect": "Allow",
                 "Action": ["lambda:InvokeFunction"],
                 "Resource": "arn:aws:lambda:%s:%s:function:%s"
                             % (REGION, acct, N["lambda"])},
                # Gateway must be able to READ + EVALUATE the policy engine
                # and its policies to enforce them (CreateGateway performs a
                # GetPolicyEngine + AuthorizeAction check with this role, and
                # invoke-time enforcement needs the same).  Granted on * because
                # the engine ARN is not known until after the role is created.
                {"Sid": "PolicyEngineAccess", "Effect": "Allow",
                 "Action": ["bedrock-agentcore:*"],
                 "Resource": "*"},
            ],
        },
    )
    print("  gateway role:  %s" % grole_arn)

    # --- lambda execution role ---
    lrole_arn = _ensure_role(
        N["lambda_role"],
        trust="lambda.amazonaws.com",
        managed=[iam_policy_arn("service-role/AWSLambdaBasicExecutionRole")],
    )
    print("  lambda role:   %s" % lrole_arn)
    return grole_arn, lrole_arn


def _ensure_role(name, trust, inline=None, managed=None):
    arn = "arn:aws:iam::%s:role/%s" % (account_id(), name)
    try:
        C.aws_json("iam", "get-role", "--role-name", name)
        print("  [reuse] role %s" % name)
    except Exception:
        doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": trust},
                "Action": "sts:AssumeRole",
            }],
        }
        C.aws_raw("iam", "create-role", "--role-name", name,
                  "--assume-role-policy-document", json.dumps(doc))
        print("  [create] role %s (trust=%s)" % (name, trust))
        time.sleep(1)
    if inline:
        C.aws_raw("iam", "put-role-policy", "--role-name", name,
                  "--policy-name", name + "-inline",
                  "--policy-document", json.dumps(inline))
    for mp in (managed or []):
        C.aws_raw("iam", "attach-role-policy", "--role-name", name,
                  "--policy-arn", mp)
    return arn


# ------------------------------------------------------------- lambda ------

def ensure_lambda(lambda_role_arn):
    print("\n-- 2/5 Lambda backend (mock transfer)")
    fn = N["lambda"]
    handler_src = os.path.join(C.HERE, "lambda", "transfer_handler.py")
    make_zip(handler_src)  # writes out/transfer.zip (deployable package)
    zip_path = os.path.join(C.OUT_DIR, "transfer.zip")

    try:
        d = C.aws_json("lambda", "get-function", "--function-name", fn)
        arn = d["Configuration"]["FunctionArn"]
        print("  [reuse] function %s" % fn)
    except Exception:
        d = C.aws_json(
            "lambda", "create-function",
            "--function-name", fn,
            "--runtime", "python3.12",
            "--role", lambda_role_arn,
            "--handler", "transfer_handler.handler",
            "--zip-file", "fileb://" + zip_path.replace(os.sep, "/"),
            "--timeout", "10",
            "--memory-size", "128",
            "--description", "ROTN GAP-4 mock bank transfer (settle + receipt)",
        )
        arn = d["FunctionArn"]
        print("  [create] function %s" % fn)

    # AgentCore Gateway must be allowed to invoke this function.
    C.aws_raw(
        "lambda", "add-permission",
        "--function-name", fn,
        "--statement-id", "rot-agentcore-gateway",
        "--action", "lambda:InvokeFunction",
        "--principal", "bedrock-agentcore.amazonaws.com",
        check=False,
    )
    print("  invoke permission for bedrock-agentcore.amazonaws.com: set")
    return arn


def make_zip(handler_src):
    """Zip the handler module into an in-memory Lambda deployable package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(handler_src, "transfer_handler.py")
    data = buf.getvalue()
    C.ensure_out()
    with open(os.path.join(C.OUT_DIR, "transfer.zip"), "wb") as f:
        f.write(data)
    return data


# -------------------------------------------------------- policy engine ---

def ensure_policy_engine():
    print("\n-- 3/5 Policy engine (temporal policies live here)")
    name = N["policy_engine"]
    d = None
    # Reuse: look up by name via list-policy-engines.  (get-policy-engine-
    # summary requires --policy-engine-id, so a name lookup must go through
    # the list API.)
    try:
        lst = C.aws_json("bedrock-agentcore-control", "list-policy-engines")
        for pe in lst.get("policyEngines", []):
            if pe.get("name") == name:
                d = pe
                break
        if d:
            print("  [reuse] engine %s (%s)" % (name, d.get("policyEngineId")))
    except Exception:
        d = None
    if not d:
        d = C.aws_json(
            "bedrock-agentcore-control", "create-policy-engine",
            "--name", name,
            "--description", "ROTN GAP-4 spendcap demo engine (temporal)",
        )
        print("  [create] engine %s (%s)" % (name, d.get("policyEngineId")))
    pe_id = d["policyEngineId"]
    pe_arn = d.get("policyEngineArn") or (
        "arn:aws:bedrock-agentcore:%s:%s:policy-engine/%s"
        % (REGION, account_id(), d.get("name", name)))
    st = C.poll(
        "policy engine %s" % name,
        lambda: _pe_status(pe_id),
        timeout=300, interval=5, want={"ACTIVE", "AVAILABLE", "READY"})
    print("  engine status: %s" % st)
    return pe_id, pe_arn


def _pe_status(pe_id):
    try:
        d = C.aws_json("bedrock-agentcore-control", "get-policy-engine",
                       "--policy-engine-id", pe_id)
        return d.get("status", d.get("policyEngineStatus", "?"))
    except Exception as e:
        return "ERR:" + str(e)[:80]


# ------------------------------------------------------------ gateway -----

def ensure_gateway(gateway_role_arn, pe_id, pe_arn):
    print("\n-- 4/5 AgentCore Gateway (MCP, AWS_IAM, policy ENFORCE)")
    name = N["gateway"]
    existing = None
    try:
        d = C.aws_json("bedrock-agentcore-control", "list-gateways")
        for g in d.get("items", d.get("gateways", [])):
            if g.get("name") == name:
                existing = g
                break
    except Exception:
        pass

    if existing:
        gw_id = existing.get("gatewayId") or existing.get("id")
        arn = existing.get("arn") or existing.get("gatewayArn")
        print("  [reuse] gateway %s (%s)" % (name, gw_id))
    else:
        d = C.aws_json(
            "bedrock-agentcore-control", "create-gateway",
            "--name", name,
            "--description",
            "ROTN GAP-4 spendcap demo gateway (temporal policy ENFORCE)",
            "--role-arn", gateway_role_arn,
            "--protocol-type", "MCP",
            "--authorizer-type", "AWS_IAM",
            "--policy-engine-configuration",
            json.dumps({"arn": pe_arn, "mode": "ENFORCE"}),
            "--exception-level", "DEBUG",
        )
        gw_id = d.get("gatewayId") or d.get("id")
        arn = d.get("arn") or d.get("gatewayArn")
        print("  [create] gateway %s (%s)" % (name, gw_id))

    st = C.poll("gateway %s" % name,
                lambda: _gw_status(gw_id),
                timeout=600, interval=6,
                want={"ACTIVE", "AVAILABLE", "READY"})
    print("  gateway status: %s" % st)
    # get-gateway (unconditional) is the authoritative source for BOTH the
    # URL and the ARN -- list-gateways omits the ARN, so don't rely on the
    # value captured above (it may be empty on the reuse path).
    d = C.aws_json("bedrock-agentcore-control", "get-gateway",
                   "--gateway-identifier", gw_id)
    url = d.get("gatewayUrl") or d.get("url") or ""
    arn = d.get("gatewayArn") or d.get("arn") or arn or ""
    return gw_id, arn, url


def _gw_status(gw_id):
    try:
        d = C.aws_json("bedrock-agentcore-control", "get-gateway",
                       "--gateway-identifier", gw_id)
        return d.get("status", d.get("gatewayStatus", "?"))
    except Exception as e:
        return "ERR:" + str(e)[:80]


# --------------------------------------------------------------- target ----

TOOL_SCHEMA = [
    {
        # AgentCore gateway targets expect a FLAT MCP tool schema:
        # name / description / inputSchema / outputSchema  (NOT the
        # OpenAI {"type":"function","function":{...}} wrapper).
        "name": "transfer",
        "description": ("Execute a mock bank transfer of the given "
                        "amount (USD). Settles immediately and returns "
                        "a receipt (txId, amount, status)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {
                    "type": "integer",
                    "description": "Amount in USD to transfer (1..2000).",
                },
            },
            "required": ["amount"],
        },
    }
]


def _find_target(gw_id, tname):
    """Return the list item (dict) for target ``tname`` or None."""
    try:
        d = C.aws_json("bedrock-agentcore-control", "list-gateway-targets",
                       "--gateway-identifier", gw_id)
        for t in d.get("items", d.get("targets", [])):
            if t.get("name") == tname:
                return t
    except Exception:
        pass
    return None


def ensure_target(gw_id, lambda_arn):
    print("\n-- 5/5 Gateway target TransferTarget (MCP lambda tool)")
    tname = N["target"]
    t = _find_target(gw_id, tname)
    if t:
        tid = t.get("targetId", "")
        print("  [reuse] target %s (%s)" % (tname, tid))
    else:
        cfg = {
            "mcp": {
                "lambda": {
                    "lambdaArn": lambda_arn,
                    "toolSchema": {"inlinePayload": TOOL_SCHEMA},
                }
            }
        }
        # credentialProviderConfigurations IS required for a Lambda MCP
        # target, but must be GATEWAY_IAM_ROLE with NO credentialProvider
        # sub-object (an iamCredentialProvider is rejected on Lambda targets:
        # "IamCredentialProvider is not supported for this target type").
        # Semantics: the gateway uses its own role to invoke the Lambda.
        cred_providers = [
            {"credentialProviderType": "GATEWAY_IAM_ROLE"},
        ]
        resp = C.aws_json(
            "bedrock-agentcore-control", "create-gateway-target",
            "--gateway-identifier", gw_id,
            "--name", tname,
            "--target-configuration", json.dumps(cfg),
            "--credential-provider-configurations", json.dumps(cred_providers),
        )
        tid = resp.get("targetId", "")
        if not tid:  # fallback: look it up by name
            t2 = _find_target(gw_id, tname)
            tid = (t2 or {}).get("targetId", "")
        print("  [create] target %s (%s, tool: transfer)" % (tname, tid))

    st = C.poll("target %s" % tname,
                lambda: _tgt_status(gw_id, tid),
                timeout=300, interval=5,
                want={"ACTIVE", "AVAILABLE", "READY"})
    print("  target status: %s" % st)
    return tid


def _tgt_status(gw_id, target_id):
    try:
        d = C.aws_json("bedrock-agentcore-control", "get-gateway-target",
                       "--gateway-identifier", gw_id, "--target-id", target_id)
        return d.get("status", d.get("targetStatus", "?"))
    except Exception as e:
        return "ERR:" + str(e)[:80]


# ----------------------------------------------------------------- main ----

def main():
    print("=" * 68)
    print("10_setup -- gateway + policy engine + mock Lambda (region %s)"
          % REGION)
    print("=" * 68)
    try:
        grole_arn, lrole_arn = ensure_roles()
        pe_id, pe_arn = ensure_policy_engine()
        lambda_arn = ensure_lambda(lrole_arn)
        gw_id, gw_arn, gw_url = ensure_gateway(grole_arn, pe_id, pe_arn)
        target_id = ensure_target(gw_id, lambda_arn)
    except Exception as e:
        C.die("setup failed: %s" % e)

    st = C.save_state({
        "region": REGION,
        "account": account_id(),
        "names": N,
        "gatewayRoleArn": grole_arn,
        "lambdaRoleArn": lrole_arn,
        "lambdaArn": lambda_arn,
        "policyEngineId": pe_id,
        "policyEngineArn": pe_arn,
        "gatewayId": gw_id,
        "gatewayArn": gw_arn,
        "gatewayUrl": gw_url,
        "targetId": target_id,
        "toolSchema": TOOL_SCHEMA,
        "setup_done_utc": C.now_iso(),
    })
    print("\nstate -> out/state.json")
    print("  gateway      : %s" % gw_arn)
    print("  gateway url  : %s" % gw_url)
    print("  policy engine: %s" % pe_arn)
    print("  lambda       : %s" % lambda_arn)
    print("\nNext: python 20_deploy_policy.py")


if __name__ == "__main__":
    main()