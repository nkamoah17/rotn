# -*- coding: utf-8 -*-
"""65_divergence_e3.py -- ENGINE DIVERGENCE test (corrected policy).

Reuses the EXISTING E3 session (the one where a lone $300 fire was DENIED)
and fires ONE more $100 transfer into it.  This discriminates how the live
AgentCore engine records a DENIED request versus how the Dogwood reference
records one:

  * AgentCore event semantics (see the buggy-twin policy comment): a denied
    action records an `::error`, NOT a `::request`.  So the corrected
    (request-sum) policy's 24h sum, for the new $100 fire, sees ONLY the $100
    (the denied $300 became an error, not a request):  100 <= 200 -> ADMIT.
  * Dogwood reference semantics (spec SS6): "every event is observed before
    it is decided; a recorded request stays in history even if evaluation
    then denies it."  So the denied $300 request STAYS in history and the
    corrected policy's sum for the $100 fire is  300 + 100 = 400 > 200 -> DENY.

If the live ADMITs the $100 while the reference DENYs it, that is a live-vs-
reference divergence in how a denied request is treated -- independent of the
window-semantics (reflexive/non-reflexive) question.

Outputs (out/):
  divergence-e3.json            live verdict + reference decisions + reading
  divergence-e3-events.jsonl    the 2-event trace fed to the reference
  divergence-e3/                the reference replay raw artifacts

Usage:  python 65_divergence_e3.py [session_id]
        (default: the E3 session recorded in out/single300.json)
Exit:   0 = fired + replayed + recorded (the reading is data, not a gate);
        3 = hard error (common.die).
"""

import importlib.util
import json
import os
import sys

import common as C

E3_SESSION_DEFAULT = "b89d9c56-e8b9-49c2-95cd-74789b121de5"
AMOUNT = 100
CAP = 200
CORRECT_POLICY = os.path.join(C.HERE, "policies",
                              "spendcap-correct-agentcore.dw")


def load_sibling(name):
    p = os.path.join(C.HERE, name)
    spec = importlib.util.spec_from_file_location(name.split(".")[0], p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def e3_session_id():
    """The E3 session (where the lone $300 was denied)."""
    for a in sys.argv[1:]:
        if not a.startswith("--"):
            return a.strip()
    try:
        with open(os.path.join(C.OUT_DIR, "single300.json")) as f:
            sid = json.load(f).get("session_id")
            if sid:
                return sid
    except Exception:
        pass
    return E3_SESSION_DEFAULT


def render_correct_policy(st):
    """Render the corrected policy with the real ARN, then adapt the one
    event-field this reference build names differently (eventResource ->
    callerResource) so `dogwood validate` passes (mirrors 64_replay)."""
    with open(CORRECT_POLICY, "r") as f:
        text = f.read()
    arn = st.get("gatewayArn") or ""
    text = text.replace("{{GATEWAY_ARN}}", arn)
    if "eventResource" in text:
        text = text.replace("eventResource", "callerResource")
    return C.write_text("divergence-e3-policy.dw", text)


def replay_reference(events_path, policy_path, schema_path, out_dir):
    """Run `rot replay --oracle dogwood` into out_dir; return (rc, out, decs)."""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    rc, out = C.run([sys.executable, "-m", "rot", "replay",
                     "--oracle", "dogwood",
                     "--events", events_path,
                     "--policy", policy_path,
                     "--policy-schema", schema_path,
                     "--out", out_dir], check=False)
    decs = []
    rp = os.path.join(out_dir, "reference-replay.json")
    if os.path.isfile(rp):
        try:
            with open(rp, "r") as f:
                reports = json.load(f)
            if isinstance(reports, dict):
                reports = [reports]
            for r in reports:
                # decisions live under the dogwood reference key, with a
                # top-level fallback for other replay report shapes.
                blob = r.get("dogwood_reference_buggy", r)
                for d in (blob.get("decisions") or r.get("decisions") or []):
                    decs.append(d)
        except Exception:
            decs = []
    return rc, out, decs


def main():
    st = C.load_state()
    gw_id = st.get("gatewayId")
    if not gw_id or not st.get("gatewayArn"):
        C.die("run 10_setup.py first (missing gateway in state)")

    fire = load_sibling("30_fire_parallel.py")
    rep = load_sibling("64_replay_reference.py")  # SCHEMA + dogwood finder

    session_id = e3_session_id()
    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    C.ensure_out()

    print("=" * 68)
    print("65_divergence_e3 -- engine divergence (corrected policy)")
    print("  gateway : %s" % st.get("gatewayArn"))
    print("  session : %s  (E3: the lone $300 was DENIED here)" % session_id)
    print("  probe   : ONE $%d fire into that same session" % AMOUNT)
    print("  cap     : %d (24h window)" % CAP)
    print("=" * 68)

    # 1) fire $100 into the EXISTING E3 session ----------------------------
    outfile = os.path.join(C.OUT_DIR, "divergence-e3-response.json")
    reuse_live = ("--reuse-live" in sys.argv)
    if reuse_live and os.path.exists(outfile):
        rc, out, err, dt = 0, "", "", 0.0
        verdict = fire.classify(0, outfile, "", "")
        detail = fire.response_detail(outfile)
        C.log("reusing prior live response %s (no new fire)" % outfile)
    else:
        C.log("firing $%d into E3 session %s" % (AMOUNT, session_id))
        p = fire.start_invoke(gw_id, session_id, 2, path, AMOUNT, outfile, tool)
        rc, out, err, dt = fire.wait_invoke(p)
        verdict = fire.classify(rc, outfile, out, err)
        detail = fire.response_detail(outfile)
    print("  LIVE  : %-9s rc=%s (%.2fs)" % (verdict, rc, dt))
    if detail.get("denial"):
        print("           DENIAL: %s" % detail["denial"][:200])
    elif detail.get("receipt"):
        print("           receipt txId=%s" % detail["receipt"])
    live_admitted = (verdict == "ADMITTED")

    # 2) build the 2-event trace (the E3 $300 denial + this $100 fire) ------
    e3_ts = "2026-11-06T08:58:38Z"
    try:
        with open(os.path.join(C.OUT_DIR, "single300.json")) as f:
            e3_ts = json.load(f).get("fired_at_utc", e3_ts)
    except Exception:
        pass
    events = [
        {"seq": 1, "kind": "request", "amount": 300,
         "ts": e3_ts, "live_verdict": "DENIED"},
        {"seq": 2, "kind": "request", "amount": AMOUNT,
         "ts": C.now_iso(), "live_verdict": verdict},
    ]
    C.write_text("divergence-e3-events.jsonl",
                 "\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n")

    # 3) reference replay of the SAME trace --------------------------------
    policy_path = render_correct_policy(st)
    schema_path = C.write_text("divergence-e3-schema.cedarschema", rep.SCHEMA)
    out_dir = os.path.join(C.OUT_DIR, "divergence-e3")
    binary = rep.find_dogwood()
    if binary is None:
        C.die("dogwood binary not found (set DOGWOOD_BIN or build it)")
    C.log("reference replay: %s" % binary)
    events_path = os.path.join(C.OUT_DIR, "divergence-e3-events.jsonl")
    r_rc, r_out, decs = replay_reference(events_path, policy_path,
                                         schema_path, out_dir)
    ref = {}
    for d in decs:
        n = d.get("seq")
        if isinstance(n, int):
            ref[n // 2 + 1] = d.get("decision", "?")
    ref_e1 = ref.get(1, "?")   # the $300 (denied live)
    ref_e2 = ref.get(2, "?")   # the $100 (this probe)
    C.log("reference: E1($300)=%s  E2($100)=%s  (replay_rc=%s)"
          % (ref_e1, ref_e2, r_rc))
    finish(st, session_id, verdict, rc, dt, detail, live_admitted,
           binary, decs, ref_e1, ref_e2, r_rc)


def finish(st, session_id, verdict, rc, dt, detail, live_admitted,
           binary, decs, ref_e1, ref_e2, r_rc):
    rep = load_sibling("64_replay_reference.py")
    # 4) the divergence reading --------------------------------------------
    if live_admitted and ref_e2 == "DENY":
        reading = "LIVE/REFERENCE DIVERGENCE (denied-request handling)"
        detail_read = (
            "Live AgentCore ADMITted the follow-on $%d in the E3 session "
            "where a $300 fire had just been DENIED: the denied action was "
            "recorded as an `::error`, so the corrected (request-sum) policy "
            "saw only the $%d (100 <= 200). The reference, per spec SS6 "
            "('a recorded request stays in history even if evaluation then "
            "denies it'), kept the $300 request in history and DENIED the "
            "$%d (300 + 100 = 400 > 200). Same policy text, same trace, "
            "opposite decisions -- a divergence in how a DENIED request is "
            "treated (live: error, not counted; reference: request, counted)."
            % (AMOUNT, AMOUNT, AMOUNT))
    elif (not live_admitted) and ref_e2 == "ALLOW":
        reading = "LIVE/REFERENCE DIVERGENCE (denied-request handling)"
        detail_read = (
            "Live DENIED the $%d while the reference ADMITted it -- the "
            "opposite signature (live is counting the denied $300, the "
            "reference is not)." % AMOUNT)
    elif (not live_admitted) and ref_e2 == "DENY":
        reading = "NO DIVERGENCE -- live and reference AGREE (both count a denied request)"
        detail_read = (
            "Hypothesis was that the live engine records a DENIED action as an "
            "`::error` (not a request), so it would ADMIT the follow-on $%d "
            "(100 <= 200) while the reference DENYs it (300 + 100 = 400 > 200). "
            "That did NOT materialize: the live engine DENIED the $%d follow-on "
            "-- a $100 in a fresh session is admitted (E2 cf467d76), so the "
            "denial here is attributable to the denied $300 being COUNTED in the "
            "24h aggregate. The reference makes the same call (DENY, 400 > 200). "
            "So for this trace the live engine and the Dogwood reference are "
            "CONSISTENT: both treat a denied request as still-counting in the "
            "temporal sum. The 'denied -> error, not counted' hypothesis is not "
            "supported by this live probe."
            % (AMOUNT, AMOUNT))
    else:
        reading = "NO DIVERGENCE (live and reference agree)"
        detail_read = (
            "Live %s the $%d and the reference %s it -- they agree on this "
            "trace, so this probe did not surface a denied-request-handling "
            "gap (inspect out/divergence-e3/ and the reference decisions)."
            % (verdict, AMOUNT, ref_e2))

    C.write_json("divergence-e3.json", {
        "script": "65_divergence_e3.py",
        "control": "divergence-e3",
        "phase": st.get("phase"),
        "session_id": session_id,
        "amount": AMOUNT,
        "cap": CAP,
        "live": {
            "verdict": verdict,
            "exit_code": rc,
            "elapsed_s": round(dt, 3),
            "denial": detail.get("denial"),
            "receipt": detail.get("receipt"),
            "response_file": "divergence-e3-response.json",
        },
        "reference": {
            "binary": binary,
            "version": rep.dogwood_version(binary),
            "decisions": decs,
            "e1_300": ref_e1,
            "e2_100": ref_e2,
            "replay_rc": r_rc,
            "out_dir": "divergence-e3",
        },
        "divergence": bool((live_admitted and ref_e2 == "DENY")
                           or ((not live_admitted) and ref_e2 == "ALLOW")),
        "reading": reading,
        "reading_detail": detail_read,
        "fired_at_utc": C.now_iso(),
    })

    print("")
    print("-" * 68)
    print("  LIVE      : %s (the $%d follow-on in the E3 session)"
          % (verdict, AMOUNT))
    print("  REFERENCE : E1($300)=%s  E2($%d)=%s" % (ref_e1, AMOUNT, ref_e2))
    print("  READING   : %s" % reading)
    print("             %s" % detail_read)
    print("-" * 68)
    print("wrote out/divergence-e3.json")
    print("")
    print("NOTE: a live ADMIT vs reference DENY is a live-vs-reference "
          "finding on denied-request handling. Per the runbook, a genuine "
          "engine finding goes to AWS privately before publication.")


if __name__ == "__main__":
    main()