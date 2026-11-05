# -*- coding: utf-8 -*-
"""_peprobe.py -- show raw responses of the policy-engine lookup APIs."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import common as C  # noqa: E402


def run(*args):
    try:
        out, err = subprocess.Popen(
            [C.aws_exe()] + list(args), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).communicate(timeout=60)
        return (out.decode("utf-8", "replace"),
                err.decode("utf-8", "replace"))
    except Exception as e:
        return "", "EXC:" + str(e)


print("=== get-policy-engine-summary --name rot_spendcap_engine ===")
out, err = run("bedrock-agentcore-control", "get-policy-engine-summary",
               "--name", "rot_spendcap_engine")
print("OUT:", out[:1500] or "(empty)")
print("ERR:", err[:1500] or "(empty)")

print()
print("=== list-policy-engines ===")
out, err = run("bedrock-agentcore-control", "list-policy-engines")
print("OUT:", out[:2000] or "(empty)")
print("ERR:", err[:1500] or "(empty)")

print()
print("=== get-policy-engine --policy-engine-id rot_spendcap_engine-rzhlj_2hg9 ===")
out, err = run("bedrock-agentcore-control", "get-policy-engine",
               "--policy-engine-id", "rot_spendcap_engine-rzhlj_2hg9")
print("OUT:", out[:2000] or "(empty)")
print("ERR:", err[:1500] or "(empty)")