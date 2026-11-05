# -*- coding: utf-8 -*-
"""00_preflight.py -- verify the local toolchain + AWS identity + permissions.

Prints a readiness report and exits 0 only when the environment is ready to
run the repro.  Safe to re-run; creates no AWS resources.

Checks
------
  1. Python (3.6+), AWS CLI v2, node, AgentCore CLI (@aws/agentcore)
  2. AWS credentials: sts get-caller-identity (account id + ARN, no secrets)
  3. Region chosen (AC_REPRO_REGION or the profile default)
  4. IAM permissions: list gateways / policy engines in the region
  5. Existing resources from a previous run (so we can resume or clean up)

Usage:  python 00_preflight.py
"""

import json
import sys

import common as C

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok, detail))
    mark = "OK  " if ok else "FAIL"
    print("  [%s] %-28s %s" % (mark, name, detail))
    return ok


def main():
    print("=" * 68)
    print("ROTN GAP-4 preflight -- real AgentCore Gateway repro")
    print("=" * 68)

    print("\n1. Local toolchain")
    import platform
    check("python", sys.version_info >= (3, 6),
          "%s (%s)" % (platform.python_version(), sys.executable))

    aws = None
    ac = None
    try:
        aws = C.aws_exe()
    except Exception as e:
        aws = None
        aws_err = str(e)
    check("aws cli v2", aws is not None, aws or getattr(globals(), "aws_err", ""))

    try:
        ac = C.ac_cmd()
    except Exception as e:
        ac = None
        ac_err = str(e)
    check("agentcore cli", ac is not None,
          " ".join(ac) if ac else getattr(globals(), "ac_err", ""))

    tool_ok = aws is not None and ac is not None

    print("\n2. AWS identity (no secrets shown)")
    identity = None
    if aws:
        try:
            identity = C.aws_json("sts", "get-caller-identity")
            check("credentials", True,
                  "account=%s arn=%s" % (
                      identity.get("Account"), identity.get("Arn")))
        except Exception as e:
            check("credentials", False, str(e)[:300])
    else:
        check("credentials", False, "aws cli missing")

    reg = C.region()
    check("region", True, reg + " (set AC_REPRO_REGION to override)")

    print("\n3. IAM permissions (read-only probes in %s)" % reg)
    if aws:
        try:
            gw = C.aws_json(
                "bedrock-agentcore-control", "list-gateways",
                "--region", reg)
            n = len(gw.get("items", gw.get("gateways", [])))
            check("list gateways", True, "%d existing" % n)
        except Exception as e:
            check("list gateways", False, str(e)[:300])
        try:
            pe = C.aws_json(
                "bedrock-agentcore-control", "list-policy-engines",
                "--region", reg)
            n = len(pe.get("items", pe.get("policyEngines", [])))
            check("list policy engines", True, "%d existing" % n)
        except Exception as e:
            check("list policy engines", False, str(e)[:300])
    else:
        check("iam probes", False, "skipped (no aws cli)")

    print("\n4. Existing resources (idempotency)")
    st = C.load_state()
    if st.get("gatewayArn"):
        print("  [resume] state.json has a prior gateway: %s"
              % st["gatewayArn"])
        print("           run 70_cleanup.py first, or delete state.json")
    else:
        print("  [clean]  no prior run recorded in out/state.json")

    ok = all(c[1] for c in CHECKS)
    print("\n" + "=" * 68)
    print("PREFLIGHT %s -- %d/%d checks passed"
          % ("READY" if ok else "NOT READY", sum(1 for c in CHECKS if c[1]),
             len(CHECKS)))
    if not ok:
        print("Fix the FAIL items above, then re-run 00_preflight.py")
    else:
        print("Next: python 10_setup.py")
    C.write_json("preflight.json", {
        "checks": [{"name": n, "ok": o, "detail": d} for n, o, d in CHECKS],
        "ready": ok, "identity": identity, "region": reg,
    })
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()