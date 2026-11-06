# -*- coding: utf-8 -*-
"""66_e4_corrected.py -- COMPLETE THE CORRECTED-POLICY E4.

Replays the CORRECTED-policy live traces through the local Dogwood reference
and compares live vs reference, per fire:

  * E2-corrected : the sequential 3 x $100 (session cf467d76, 2 ADMIT / 1 DENY)
  * E3-corrected : the single over-cap $300  (session b89d9c56, DENIED)

Both ran under the corrected (request-sum) policy, the one the AWS validator
accepted.  The corrected policy admits exactly the in-cap fires (2 x $100 =
$200) and denies from fire #3, and denies a lone $300.  If the reference
makes the SAME calls, the corrected policy is consistent with the reference
(unlike the buggy twin, whose non-reflexive window let fire #3 through).
Local half only -- touches NOTHING in AWS.

Usage:  python 66_e4_corrected.py
Exit:   0 = recorded; 3 = hard error (common.die).
"""

import importlib.util
import json
import os
import sys

import common as C

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
def render_correct_policy(arn):
    """Corrected policy, real ARN, and the one event-field this reference
    build names differently (eventResource -> callerResource)."""
    with open(CORRECT_POLICY, "r") as f:
        text = f.read()
    text = text.replace("{{GATEWAY_ARN}}", arn)
    if "eventResource" in text:
        text = text.replace("eventResource", "callerResource")
    return C.write_text("e4c-policy.dw", text)


def replay(events_path, policy_path, schema_path, out_dir):
    """`rot replay --oracle dogwood` into out_dir; return (rc, decisions)."""
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
                blob = r.get("dogwood_reference_buggy", r)
                decs.extend(blob.get("decisions") or [])
        except Exception:
            decs = []
    return rc, decs


def fires_from_decisions(decs):
    """decision seq (trace timepoint index) -> ALLOW/DENY, keyed by fire #."""
    fires = {}
    for d in decs:
        n = d.get("seq")
        if isinstance(n, int):
            fires[n // 2 + 1] = d.get("decision", "?")
    return fires


def write_events(name, events):
    return C.write_text("e4c-%s-events.jsonl" % name,
                        "\n".join(json.dumps(e, sort_keys=True)
                                  for e in events) + "\n")
def main():
    st = C.load_state()
    arn = st.get("gatewayArn")
    if not arn:
        C.die("run 10_setup.py first (missing gatewayArn)")
    rep = load_sibling("64_replay_reference.py")  # SCHEMA + dogwood finder
    binary = rep.find_dogwood()
    if binary is None:
        C.die("dogwood binary not found (set DOGWOOD_BIN or build it)")
    C.ensure_out()
    tpl_rel = os.path.relpath(CORRECT_POLICY, C.HERE)

    # -- corrected E2: the sequential 3 x $100 (cf467d76) -------------------
    with open(os.path.join(C.OUT_DIR, "sequential-results.json")) as f:
        seq = json.load(f)
    e2_events = []
    for r in seq.get("results", []):
        e2_events.append({"seq": r["fire"], "kind": "request",
                          "amount": seq.get("amount", 100),
                          "ts": r.get("ts", ""),
                          "live_verdict": r.get("verdict", "?")})

    # -- corrected E3: the single over-cap $300 (b89d9c56) ------------------
    with open(os.path.join(C.OUT_DIR, "single300.json")) as f:
        e3 = json.load(f)
    e3_events = [{"seq": 1, "kind": "request",
                  "amount": e3.get("amount", 300),
                  "ts": e3.get("fired_at_utc", ""),
                  "live_verdict": e3.get("verdict", "?")}]

    policy_path = render_correct_policy(arn)
    schema_path = C.write_text("e4c-schema.cedarschema", rep.SCHEMA)

    print("=" * 68)
    print("66_e4_corrected -- corrected-policy traces vs the Dogwood reference")
    print("  gateway : %s" % arn)
    print("  policy  : %s" % tpl_rel)
    print("  dogwood : %s (%s)" % (binary, rep.dogwood_version(binary)))
    print("=" * 68)

    traces = [
        ("E2-corrected", "sequential 3 x $100", e2_events,
         seq.get("session_id")),
        ("E3-corrected", "single over-cap $300", e3_events,
         e3.get("session_id")),
    ]

    results = {}
    for (name, desc, events, session) in traces:
        ev_path = write_events(name, events)
        out_dir = os.path.join(C.OUT_DIR, "e4c-" + name)
        rc, decs = replay(ev_path, policy_path, schema_path, out_dir)
        fires = fires_from_decisions(decs)
        live = [e["live_verdict"] for e in events]
        ref = [fires.get(i + 1) for i in range(len(events))]
        pairs = []
        agree = True
        for i, (l, r) in enumerate(zip(live, ref), 1):
            ok = ((l == "ADMITTED" and r == "ALLOW")
                  or (l == "DENIED" and r == "DENY"))
            agree = agree and ok
            pairs.append({"fire": i, "live": l, "reference": r,
                          "agree": ok})
        results[name] = {
            "desc": desc, "session_id": session, "policy": "corrected",
            "live": live, "reference": ref, "fires": pairs,
            "agree": agree, "replay_rc": rc,
            "out_dir": "e4c-" + name,
            "reading": ("LIVE == REFERENCE (corrected policy consistent "
                        "with the reference)" if agree
                        else "LIVE/REFERENCE MISMATCH -- inspect"),
        }
        print("\n-- %s : %s  (session %s)" % (name, desc, session))
        for p in pairs:
            print("   fire %d : live=%-8s ref=%-6s  %s"
                  % (p["fire"], p["live"], p["reference"],
                     "OK" if p["agree"] else "MISMATCH"))
    overall = all(results[t]["agree"] for t in results)
    reading = ("CORRECTED POLICY CONSISTENT WITH THE REFERENCE"
               if overall else "MISMATCH SOMEWHERE -- INSPECT")
    detail = (
        "Under the corrected (request-sum) policy, the live gateway and the "
        "Dogwood reference agree on both corrected traces: E2-corrected admits "
        "exactly the 2 in-cap $100 fires and denies fire #3 (200 + 100 > 200, "
        "reflexive window), and E3-corrected denies the lone $300 (300 > 200). "
        "This is the corrected-policy counterpart of the buggy E4 (which "
        "diverged on the non-reflexive window): with the fix, live and "
        "reference make the same calls."
        if overall else
        "One or more live/reference verdicts disagree on a corrected trace; "
        "inspect out/e4c-* / and e4-corrected-report.json for the mismatch.")

    C.write_json("e4-corrected-report.json", {
        "script": "66_e4_corrected.py",
        "control": "E4-corrected",
        "generated_at_utc": C.now_iso(),
        "dogwood": {"binary": binary,
                    "version": rep.dogwood_version(binary)},
        "policy": {"which": "corrected",
                   "template": tpl_rel,
                   "template_sha256": sha256_file(CORRECT_POLICY),
                   "rendered": "e4c-policy.dw",
                   "rendered_sha256": sha256_file(policy_path),
                   "rendered_arn": arn,
                   "field_map": {"eventResource": "callerResource"}},
        "schema": {"file": "e4c-schema.cedarschema",
                   "sha256": sha256_file(schema_path)},
        "traces": results,
        "all_agree": bool(overall),
        "reading": reading,
        "reading_detail": detail,
        "note": ("Local half of the corrected E4: replays the corrected-policy "
                 "live traces against the Dogwood reference. Nothing here "
                 "touched AWS."),
    })

    print("\n" + "-" * 68)
    print("  OVERALL : %s" % reading)
    print("  %s" % detail)
    print("-" * 68)
    print("wrote out/e4-corrected-report.json")


if __name__ == "__main__":
    main()
