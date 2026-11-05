# -*- coding: utf-8 -*-
"""One-shot smoke fixture generator (temporary; deleted after the smoke)."""
import json
import os

D = os.path.dirname(os.path.abspath(__file__))
ARN = ("arn:aws:bedrock-agentcore:us-east-1:626756230713:"
       "gateway/rot-spendcap-gw-e0umswk6ss")

evs = [{"seq": i, "kind": "request", "amount": 100,
        "ts": "2026-11-05T00:00:0%dZ" % i, "live_verdict": "ADMITTED"}
       for i in range(1, 6)]
with open(os.path.join(D, "events.jsonl"), "w") as f:
    f.write("\n".join(json.dumps(e, sort_keys=True) for e in evs) + "\n")

meta = {
    "script": "smoke", "control": "E4-SMOKE", "phase": "test",
    "policy_which": "fixed",
    "policy_path": ("agentcore_repro/policies/"
                    "spendcap-correct-agentcore.dw"),
    "policy_path_abs": os.path.abspath(
        os.path.join(D, "..", "agentcore_repro", "policies",
                     "spendcap-correct-agentcore.dw")),
    "policy_sha256": "smoke",
    "gateway_arn": ARN,
    "session_id": "smoke-sess-1",
    "action": "TransferTarget___transfer",
    "action_cedar": 'AgentCore::Action::"TransferTarget___transfer"',
    "resource": ARN,
    "resource_cedar": 'AgentCore::Gateway::"%s"' % ARN,
    "amount": 100, "nfires": 5, "cap": 200,
    "policy_schema": os.path.join(D, "e4-schema.cedarschema"),
    "fired_at_utc": "2026-11-05T00:00:05Z",
}
with open(os.path.join(D, "events-meta.json"), "w") as f:
    json.dump(meta, f, indent=2, sort_keys=True)

# The schema artifact: reuse 64_replay_reference.SCHEMA (single source).
import importlib.util  # noqa: E402
import sys  # noqa: E402
_ac = os.path.abspath(os.path.join(D, "..", "agentcore_repro"))
if _ac not in sys.path:
    sys.path.insert(0, _ac)
_p = os.path.join(_ac, "64_replay_reference.py")
_spec = importlib.util.spec_from_file_location("e64", _p)
_m64 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m64)
with open(os.path.join(D, "e4-schema.cedarschema"), "w") as f:
    f.write(_m64.SCHEMA)
print("fixtures written in", D)
