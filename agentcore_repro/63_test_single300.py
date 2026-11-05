# -*- coding: utf-8 -*-
"""63_test_single300.py -- E3 control: ONE $300 transfer, ONE fresh session.

A single $300 fire cannot be explained by window semantics alone, so it
discriminates the hypothesis space differently from E2 (sequential 5 x $100):

  * Under the CORRECT (request-sum) policy the lone fire sees only itself:
      - reflexive engine        -> sum $300 > $200 cap -> DENIED
      - non-reflexive engine    -> prior sum $0        -> ADMITTED
      - predicate never matches -> empty sum, $0 <= $200 -> ADMITTED
    so a single-fire ADMIT leaves hypotheses A (predicate mismatch) and
    B (non-reflexive) open -- E4 (64_replay_reference.py) discriminates
    them by replaying the same shape against the reference.
  * Under the BUGGY (response-sum) policy the lone fire sees no settled
    responses either way (the template has no current-amount term), so an
    ADMIT is simply CONSISTENT with the deployed template and is not a
    window-semantics signal; a DENY would be unexpected and points at the
    live policy identity / E1 findings.

The session is fresh (uuid4) so the 24h window starts empty, and the run
writes out/single300.json only -- it does NOT touch out/events.jsonl or
out/events-meta.json, so the E2 recording consumed by E4 stays intact.

Reuses 30_fire_parallel's invoke / wait / classify helpers (importlib, as
62_test_sequential.py does) and 31_fire_sequential's active-policy
resolution + SHA-256 so the verdict is attributed to the template that was
actually live.

Usage:  python 63_test_single300.py
Exit:   0 = fired + recorded (the verdict is data, not a pass/fail gate);
        3 = hard error (common.die).
"""

import importlib.util
import os
import uuid

import common as C

AMOUNT = 300          # the E3 probe amount (above the $200 cap, one fire)
CAP = 200             # the cap baked into the deployed spend-cap policy


def load_sibling(name):
    """Load a sibling script (digit-leading filename) as a module."""
    p = os.path.join(C.HERE, name)
    spec = importlib.util.spec_from_file_location(name.split(".")[0], p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    st = C.load_state()
    gw_id = st.get("gatewayId")
    if not gw_id or not st.get("gatewayArn"):
        C.die("run 10_setup.py first (missing gatewayId/gatewayArn in state)")

    fire = load_sibling("30_fire_parallel.py")
    seq = load_sibling("31_fire_sequential.py")

    tool = fire.tool_name(st)
    path = fire.mcp_path(st)
    session_id = str(uuid.uuid4())
    C.ensure_out()

    which, rel_path, abs_path, fname = seq.resolve_active_policy(st)
    if abs_path and os.path.exists(abs_path):
        policy_sha = seq.sha256_file(abs_path)
    else:
        policy_sha = None

    print("=" * 68)
    print("63_test_single300 -- E3: ONE $%d transfer, ONE fresh session"
          % AMOUNT)
    print("  gateway : %s" % st.get("gatewayArn"))
    print("  session : %s" % session_id)
    print("  path    : %s   tool: %s" % (path, tool))
    if which:
        print("  policy  : %s  (%s twin, sha256 %s)"
              % (rel_path, which, (policy_sha or "?")[:16]))
    print("  cap     : %d (24h window)" % CAP)
    print("=" * 68)

    outfile = os.path.join(C.OUT_DIR, "single300-response.json")
    C.log("E3 fire  SEQUENTIAL (single)  session=%s" % session_id)
    p = fire.start_invoke(gw_id, session_id, 1, path, AMOUNT, outfile, tool)
    rc, out, err, dt = fire.wait_invoke(p)
    verdict = fire.classify(rc, outfile, out, err)
    print("  fire   : %-9s rc=%s (%.2fs)  session=%s"
          % (verdict, rc, dt, session_id))

    admitted = (verdict == "ADMITTED")
    label, detail = read_e3(which, admitted, st.get("phase"))

    print("\n" + "-" * 68)
    print("  LIVE    : %s (one $%d transfer, fresh session)" % (verdict, AMOUNT))
    print("  READING : %s" % label)
    print("           %s" % detail)
    print("-" * 68)

    C.write_json("single300.json", {
        "script": "63_test_single300.py",
        "control": "E3",
        "phase": st.get("phase"),
        "session_id": session_id,
        "amount": AMOUNT,
        "cap": CAP,
        "gateway_arn": st.get("gatewayArn"),
        "path": path,
        "tool": tool,
        "active_policy": {
            "which": which,
            "path": rel_path,
            "sha256": policy_sha,
        },
        "fired_at_utc": C.now_iso(),
        "exit_code": rc,
        "elapsed_s": round(dt, 3),
        "verdict": verdict,
        "admitted": admitted,
        "reading": label,
        "reading_detail": detail,
        "response_file": "single300-response.json",
        "stdout_tail": (out or "")[-800:],
        "stderr_tail": (err or "")[-800:],
        "note": ("E3 control: a single over-cap fire cannot be explained "
                 "by concurrency; the reading above maps the live verdict "
                 "to the runbook SS7 hypotheses under the policy that was "
                 "active. This run does NOT touch events.jsonl, so the E2 "
                 "recording consumed by E4 stays intact."),
    })
    print("wrote out/single300.json")
    print("\nNext: python 64_replay_reference.py   (E4 -- reference replay of E2)")


def read_e3(which, admitted, phase=None):
    """Map the single-fire live verdict to the runbook hypothesis, given
    which policy template was active.  Returns (label, detail)."""
    if which == "fixed":
        if admitted:
            return ("NON-REFLEXIVE WINDOW OR PREDICATE MISMATCH "
                    "(hypotheses B/A)",
                    "A lone $%d fire was admitted under the request-sum "
                    "policy. A reflexive engine would deny it ($%d > the "
                    "$%d cap: the current request is already in the sum); "
                    "a non-reflexive engine admits it (prior sum $0); and a "
                    "predicate that never matches also admits it (empty sum "
                    "= 0 <= cap). E4 (64_replay_reference.py) discriminates: "
                    "it replays the same shape against the reference and "
                    "reads the per-fire decisions."
                    % (AMOUNT, AMOUNT, CAP))
        return ("REFLEXIVE / SPEC-CONFORMANT FOR THE SINGLE-FIRE CASE",
                "A lone over-cap fire was DENIED: the predicate matches this "
                "gateway's events (hypothesis A ruled out) and the window "
                "includes the current request (spec SS6: evaluation at "
                "position i reads positions j <= i). The unexplained $300 "
                "from the parallel runs is now isolated to the "
                "concurrent/in-flight regime -- see the E2/E4 read.")
    if which == "buggy":
        if admitted:
            return ("CONSISTENT WITH THE BUGGY TEMPLATE (response-sum)",
                    "The deployed template sums SETTLED responses only and "
                    "has no current-amount term, so a lone fire sees $0 "
                    "settled under ANY window semantics ($0 <= $%d). An "
                    "admission here is expected and is NOT a window- or "
                    "predicate-mismatch signal; the discrimination comes "
                    "from E2/E4 under the corrected policy."
                    % CAP)
        return ("UNEXPECTED UNDER THE BUGGY TEMPLATE",
                "A lone fire sees no settled responses, so the buggy "
                "template's sum is $0 <= $%d and the fire should be "
                "admitted. A DENY suggests the live policy is not the "
                "buggy twin (check state.json phase + "
                "out/validation-findings.json, E1) or the policy never "
                "applies at all (Cedar default-deny) -- inspect the E1 "
                "findings before reading this as an engine decision."
                % CAP)
    return ("NO POLICY RESOLVED FROM STATE",
            "state.json names no accepted policy form (phase=%r); the "
            "live verdict cannot be attributed to a template. Deploy "
            "first (20_deploy_policy.py / 60_redeploy_correct.py)."
            % (phase,))


if __name__ == "__main__":
    main()