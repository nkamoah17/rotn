# -*- coding: utf-8 -*-
"""Probe specific bedrock-agentcore-control operations and print the raw
AWS response (stdout + stderr) so we can map what's permitted vs denied.
Usage: python _probe_ops.py [op1 op2 ...]   (defaults to the repro's key ops)
"""
import json
import os
import sys
import common as C

DEFAULT_OPS = [
    "list-gateways",
    "list-policy-engines",
    "list-policy-summaries",
]

def probe(op):
    import subprocess
    print("=" * 60)
    print("OP:", op)
    cmd = [C.aws_exe(), "bedrock-agentcore-control", op,
           "--region", C.region(), "--output", "json"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(timeout=60)
        out = out.decode("utf-8", "replace").strip()
        err = err.decode("utf-8", "replace").strip()
        print("  rc   :", p.returncode)
        if out:
            try:
                d = json.loads(out)
                for k, v in d.items():
                    if isinstance(v, list):
                        print("  %s : %d item(s)" % (k, len(v)))
                    elif isinstance(v, dict):
                        print("  %s : dict(keys=%s)" % (k, list(v.keys())[:6]))
                    else:
                        print("  %s : %r" % (k, v))
            except ValueError:
                print("  body :", out[:400])
        else:
            print("  body : (empty stdout)")
        if err:
            print("  ERR  :", err[:400])
    except Exception as e:
        print("  EXC  :", str(e)[:400])

def main():
    ops = sys.argv[1:] or DEFAULT_OPS
    for op in ops:
        probe(op)

if __name__ == "__main__":
    main()