# -*- coding: utf-8 -*-
"""31_fire_sequential.py -- fire N transfers ONE AT A TIME in ONE fresh session.

E2 control + buggy-policy baseline.  This is the sequential twin of
30_fire_parallel.py: instead of starting all invokes back-to-back, each fire is
started, awaited, and classified BEFORE the next one begins.  Sequential firing
removes the concurrency effect, so whatever the engine does here is a statement
about its TEMPORAL WINDOW semantics, not about a TOCTOU race.

Why sequential (runbook docs/agentcore-repro.md, SS4 step 4 / SS5 control E2):
  * REFLEXIVE (spec-conformant) engine -- evaluation at position i reads
    positions j <= i (the current request included, spec SS6): fire#3 sees a
    running total of $300 and is DENIED, so exactly $200 is committed even
    sequentially.
  * NON-REFLEXIVE engine -- evaluation at i reads only j < i (current request
    excluded): fire#3 sees prior-sum $200, 200 <= 200 -> ADMITTED, so $300 is
    committed with no concurrency involved at all.
  * PREDICATE NEVER MATCHES -- the temporal clause never fires, so every
    transfer is admitted and $500 is committed.  This is hypothesis A in the
    runbook SS7: the live engine may not be matching the predicate to the
    gateway's events at all.

The THREE-WAY verdict below replaces the binary claim in 62_test_sequential.py
(which only distinguished "$200 = reflexive" from "else = non-reflexive" and
could not surface the never-matches case).

Reuses 30_fire_parallel's invoke / wait / classify helpers (loaded via
importlib, exactly as 62_test_sequential.py already does).  One fresh session
id (uuid4) is shared by all fires so their temporal histories count against
each other; the session id is printed on EVERY call and recorded in the JSON.

Outputs (all under out/):
  fire-seq-<N>.json         one per fire: the gateway response body (the CLI
                            --output-file target)
  sequential5-results.json  the run summary + the three-way verdict
  events.jsonl              one JSON object per event:
                            {seq, kind, amount, ts, live_verdict}
  events-meta.json          active policy path + sha256, gateway ARN, session,
                            action, resource (+ context)

The events.jsonl + events-meta.json pair is the recorded input for the E4
reference replay (``rot replay --oracle dogwood --events out/events.jsonl``);
the meta carries the policy identity so the replay uses the SAME policy text
that was live when the events were recorded.

Python 3.6 compatible (repo convention: stdlib only, %-formatting, no
f-strings).  Nothing opens a browser; every AWS call is via the local CLI with
the default credentials profile.

Usage:  python 31_fire_sequential.py [amount] [nfires]   (defaults 100 5)
Exit:   0 = fired + recorded (the verdict is data, not a pass/fail gate);
        3 = hard error (common.die).
"""

import hashlib
import importlib.util
import json
import os
import sys
import uuid

import common as C

CAP = 200            # the cap baked into the deployed spend-cap policy
DEFAULT_ACTION = "TransferTarget___transfer"


def load_fire():
    """Load 30_fire_parallel.py (digit-leading filename) as a module."""
    p = os.path.join(C.HERE, "30_fire_parallel.py")
    spec = importlib.util.spec_from_file_location("fire30", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path):
    """SHA-256 hex digest of a file's bytes (streamed, size-agnostic)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_active_policy(st):
    """Return (which, rel_path, abs_path, fname) for the ACTIVE policy.

    The state's ``phase`` is set by whichever deploy step ran last
    (20_deploy_policy.py -> "buggy-deployed", 60_redeploy_correct.py ->
    "fixed").  We record the template that was actually live so the E4 replay
    can be proven to use the same policy text.  Each returns None when no
    policy has been deployed yet.
    """
    phase = st.get("phase") or ""
    if phase == "fixed":
        fname = st.get("policyAcceptedFormFixed") or st.get("policyAcceptedForm")
        which = "fixed"
    else:
        # buggy-deployed / buggy / inconclusive / unknown -> the buggy twin
        fname = st.get("policyAcceptedForm") or st.get("policyAcceptedFormFixed")
        which = "buggy"
    if not fname:
        return None, None, None, None
    abs_path = os.path.join(C.HERE, "policies", fname)
    rel_path = os.path.join("policies", fname)
    return which, rel_path, abs_path, fname


def cedar_action_name(st):
    """The Cedar action identifier (prefers the discovered name)."""
    return st.get("cedarAction") or st.get("toolName") or DEFAULT_ACTION


def three_way_verdict(committed, amount, nfires):
    """E2 three-way verdict (replaces 62_test_sequential's binary claim).

    Maps the total committed to the runbook SS5 hypothesis for the canonical
    $100 fires (cap $200):
      * $200 -> REFLEXIVE / SPEC-CONFORMANT   (cap enforced sequentially)
      * $300 -> NON-REFLEXIVE ENGINE SUSPECTED (one transfer past the cap)
      * $500 -> PREDICATE MAY NEVER MATCH     (all admitted; check E1)
    Any other total is reported as UNEXPECTED for manual inspection.
    Returns (label, detail).
    """
    total = nfires * amount
    spec_val = CAP                 # $200
    nonref_val = CAP + amount      # $300 (one extra fire slipped through)
    never_val = total              # $500 (every fire admitted)

    # Never-match is the most distinctive signature: ALL fires admitted.
    if committed == never_val and committed != CAP:
        return ("PREDICATE MAY NEVER MATCH -- CHECK E1 FINDINGS",
                "All %d transfers admitted ($%d). The temporal predicate may "
                "never match this gateway's events (runbook SS7 hypothesis A). "
                "Inspect the E1 findings in out/validation-findings.json "
                "before reading this as an engine bug." % (nfires, committed))
    if committed == spec_val:
        return ("REFLEXIVE / SPEC-CONFORMANT",
                "Committed $%d == the $%d cap: the engine enforced the cap "
                "sequentially. This matches the documented Dogwood evaluation "
                "semantics (spec SS6: evaluation at position i reads positions "
                "j <= i, the current event included; SS6.1 observe-before-decide)."
                % (committed, CAP))
    if committed == nonref_val:
        return ("NON-REFLEXIVE ENGINE SUSPECTED",
                "Committed $%d exceeds the $%d cap by one transfer: the engine "
                "admitted a fire it should have denied, consistent with a "
                "NON-REFLEXIVE window (evaluation at i reads only j < i, "
                "excluding the current request)." % (committed, CAP))
    return ("UNEXPECTED -- $%d committed" % committed,
            "Committed $%d is not one of the three predicted outcomes "
            "($%d reflexive / $%d non-reflexive / $%d never-match). Inspect "
            "out/fire-seq-*.json for the per-fire detail."
            % (committed, spec_val, nonref_val, never_val))


def main():
    amount = 100
    nfires = 5
    if len(sys.argv) > 1:
        amount = int(sys.argv[1])
    if len(sys.argv) > 2:
        nfires = int(sys.argv[2])

    st = C.load_state()
    gw_id = st.get("gatewayId")
    if not gw_id or not st.get("gatewayArn"):
        C.die("run 10_setup.py first (missing gatewayId/gatewayArn in state)")

    fire = load_fire()
    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    session_id = str(uuid.uuid4())
    C.ensure_out()

    which, rel_path, abs_path, fname = resolve_active_policy(st)
    if abs_path and os.path.exists(abs_path):
        policy_sha = sha256_file(abs_path)
    else:
        policy_sha = None
        C.log("WARNING: no active policy file resolved from state "
              "(phase=%r); events-meta.json will carry no policy identity. "
              "Deploy a policy first (20_deploy_policy.py / "
              "60_redeploy_correct.py) for a meaningful E2 reading."
              % st.get("phase"))

    action = cedar_action_name(st)
    resource = st.get("gatewayArn")

    print("=" * 68)
    print("31_fire_sequential -- %d x $%d SEQUENTIAL, ONE fresh session"
          % (nfires, amount))
    print("  gateway : %s" % st.get("gatewayArn"))
    print("  session : %s" % session_id)
    print("  path    : %s   tool: %s" % (path, tool))
    if which:
        print("  policy  : %s  (%s twin, sha256 %s)"
              % (rel_path, which, (policy_sha or "?")[:16]))
    print("  cap     : %d (24h window)" % CAP)
    print("=" * 68)

    results = []
    events = []
    for i in range(1, nfires + 1):
        outfile = os.path.join(C.OUT_DIR, "fire-seq-%d.json" % i)
        ts = C.now_iso()
        # The E2 spec asks for the session id on EVERY call -- log it per fire
        # so a mixed-session run is impossible to misread.
        C.log("fire %d/%d  SEQUENTIAL  session=%s" % (i, nfires, session_id))
        p = fire.start_invoke(gw_id, session_id, i, path, amount, outfile, tool)
        rc, out, err, dt = fire.wait_invoke(p)
        verdict = fire.classify(rc, outfile, out, err)
        results.append({
            "fire": i, "session_id": session_id, "amount": amount,
            "path": path, "tool": tool,
            "exit_code": rc, "verdict": verdict, "elapsed_s": round(dt, 3),
            "stdout_tail": (out or "")[-800:],
            "stderr_tail": (err or "")[-800:],
            "response_file": outfile,
        })
        events.append({
            "seq": i, "kind": "request", "amount": amount,
            "ts": ts, "live_verdict": verdict,
        })
        print("  fire %d : %-9s rc=%s (%.2fs)  session=%s"
              % (i, verdict, rc, dt, session_id))

    admitted = [r for r in results if r["verdict"] == "ADMITTED"]
    denied = [r for r in results if r["verdict"] == "DENIED"]
    committed = sum(r["amount"] for r in admitted)

    label, detail = three_way_verdict(committed, amount, nfires)
    print("\n" + "-" * 68)
    print("  ADMITTED : %d fire(s), $%d committed" % (len(admitted), committed))
    print("  DENIED   : %d fire(s)" % len(denied))
    print("  VERDICT  : %s" % label)
    print("             %s" % detail)
    print("-" * 68)

    # --- run summary (sequential5-results.json) --------------------------
    C.write_json("sequential5-results.json", {
        "script": "31_fire_sequential.py",
        "control": "E2",
        "mode": "sequential",
        "phase": st.get("phase"),
        "session_id": session_id,
        "amount": amount, "nfires": nfires, "cap": CAP,
        "path": path, "tool": tool,
        "fired_at_utc": C.now_iso(),
        "active_policy": {
            "which": which,
            "path": rel_path,
            "sha256": policy_sha,
        },
        "results": results,
        "admitted_count": len(admitted),
        "denied_count": len(denied),
        "committed_usd": committed,
        "verdict": label,
        "verdict_detail": detail,
    })
    print("wrote out/sequential5-results.json")

    # --- events.jsonl (one JSON object per line; the E4 input) -----------
    events_text = "\n".join(json.dumps(ev, sort_keys=True) for ev in events)
    if events:
        events_text += "\n"
    C.write_text("events.jsonl", events_text)
    print("wrote out/events.jsonl (%d events)" % len(events))

    # --- events-meta.json (policy identity + gateway/session/action/res) --
    meta = {
        "script": "31_fire_sequential.py",
        "control": "E2",
        "phase": st.get("phase"),
        "policy_which": which,
        "policy_path": rel_path,
        "policy_path_abs": abs_path,
        "policy_sha256": policy_sha,
        "gateway_arn": resource,
        "session_id": session_id,
        "action": action,
        "action_cedar": 'AgentCore::Action::"%s"' % action,
        "resource": resource,
        "resource_cedar": 'AgentCore::Gateway::"%s"' % resource,
        "amount": amount,
        "nfires": nfires,
        "cap": CAP,
        "fired_at_utc": C.now_iso(),
        "note": ("events.jsonl = one line per event "
                 "(seq/kind/amount/ts/live_verdict); consumed by "
                 "'rot replay --oracle dogwood --events out/events.jsonl' "
                 "(E4). policy_path + policy_sha256 identify the exact "
                 "template that was live; gateway_arn renders {{GATEWAY_ARN}}."),
    }
    C.write_json("events-meta.json", meta)
    print("wrote out/events-meta.json")

    C.save_state({
        "lastSessionId": session_id,
        "seqResultsFile": "sequential5-results.json",
    })
    print("\nNext: python 30_fire_parallel.py   "
          "(buggy, parallel -- runbook SS4 step 5)")


if __name__ == "__main__":
    main()