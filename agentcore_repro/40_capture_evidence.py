# -*- coding: utf-8 -*-
"""40_capture_evidence.py -- collect AWS-side evidence for the run.

Gathers (best-effort, each section independent):
  1. CloudWatch metrics for the AgentCore gateway (decision counters) over
     the last 15 minutes, namespace AWS/Bedrock-AgentCore.
  2. CloudWatch Logs for the mock Lambda: every SETTLE line = one transfer
     that actually executed (the "money moved" proof).
  3. The saved gateway responses (out/fire-*.json) from step 30/60.

Writes out/evidence.json (machine) and out/evidence.md (human) -- the raw
material for the demo's "AWS's own logs show $300 admitted" claim.

Usage:  python 40_capture_evidence.py
"""

import datetime
import json
import os
import re

import common as C

SETTLE_RE = re.compile(r"SETTLE txId=(\S+) amount=(\d+) status=(\S+)")


def ts_min_ago(minutes):
    # Windows Python 3.6 has no strftime("%s"); use an aware-UTC datetime +
    # .timestamp() instead (correct epoch seconds, no local-tz drift).
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)
    return int(t.timestamp())


def collect_cw_metrics(st):
    """Collect CloudWatch metrics for the repro gateway + policy engine.

    AgentCore metrics are dimensioned, and the dimension SET differs per
    metric (e.g. AllowDecisions uses OperationName=AuthorizeAction while
    DenyDecisions uses PartiallyAuthorizeActions; Invocations carry
    Resource/Method/Name).  So we discover, from list-metrics, the dimension
    sets that reference OUR gateway/engine, then query each with its exact
    dimensions.  Nothing is hardcoded, so it survives dimension renames.
    """
    ns = "AWS/Bedrock-AgentCore"
    markers = [m for m in (st.get("gatewayId"), st.get("policyEngineId"),
                           st.get("gatewayArn")) if m]
    out = {"namespace": ns, "metrics": []}
    try:
        d = C.aws_json("cloudwatch", "list-metrics", "--namespace", ns)
        all_names = [m.get("MetricName") for m in d.get("Metrics", [])
                     if m.get("MetricName")]
        # (name, dims) pairs whose dimension values reference this repro.
        series = []
        for m in d.get("Metrics", []):
            name = m.get("MetricName")
            dims = m.get("Dimensions") or []
            if not name or not dims:
                continue
            values = " ".join(str(x.get("Value", "")) for x in dims)
            if not any(mk in values for mk in markers):
                continue
            series.append((name, dims))
        want = ("ecision", "nvoke", "hrottl", "rror", "atency")
        seen = set()
        picked = []
        for name, dims in series:
            if not any(w in name for w in want):
                continue
            key = (name, tuple(sorted((x["Name"], x["Value"]) for x in dims)))
            if key in seen:
                continue
            seen.add(key)
            picked.append((name, dims))
        start = ts_min_ago(60)
        end = ts_min_ago(0)
        for name, dims in picked[:25]:
            # Multi-dimension metrics can't be expressed via the --dimensions
            # shorthand (the CLI parses it as a flat Name/Value map and rejects
            # a second "Value" key).  --cli-input-json is the reliable form.
            body = {
                "Namespace": ns,
                "MetricName": name,
                "Dimensions": [{"Name": x["Name"], "Value": x["Value"]}
                               for x in dims],
                "StartTime": start,
                "EndTime": end,
                "Period": 60,
                "Statistics": ["Sum", "SampleCount"],
            }
            try:
                dd = C.aws_json("cloudwatch", "get-metric-statistics",
                                "--cli-input-json", json.dumps(body))
                dps = dd.get("Datapoints", [])
                if dps:
                    out["metrics"].append({
                        "name": name, "dimensions": dims, "datapoints": dps,
                    })
            except Exception:
                continue
        out["all_metric_names"] = sorted(set(all_names))
    except Exception as e:
        out["error"] = str(e)[:500]
    return out


def collect_lambda_logs(region, fn_name):
    """Fetch recent log events from the Lambda log group; keep SETTLE lines.

    NOTE: a Lambda log group SURVIVES function deletion/re-creation, so the
    group can carry SETTLE lines from EARLIER runs of the repro.  Every line
    therefore carries its timestamp (epoch_s + ISO), and the cross-check in
    main() scopes per burst by matching txIds against the saved response
    bodies rather than by raw counts.
    """
    out = {"function": fn_name, "settle_lines": [], "raw_tail": ""}
    try:
        d = C.aws_json("logs", "describe-log-groups",
                       "--log-group-name-prefix", "/aws/lambda/" + fn_name)
        groups = [g["logGroupName"] for g in d.get("logGroups", [])
                  if g.get("logGroupName", "").startswith("/aws/lambda/" + fn_name)]
        if not groups:
            out["error"] = "no log group found"
            return out
        lg = groups[0]
        ds = C.aws_json("logs", "describe-log-streams",
                        "--log-group-name", lg,
                        "--order", "LastEventTime",
                        "--descending")
        streams = [s["logStreamName"] for s in ds.get("logStreams", [])]
        events = []
        for s in streams[:3]:
            ev = C.aws_json("logs", "get-log-events",
                            "--log-group-name", lg, "--log-stream-name", s,
                            "--limit", "500")
            events += ev.get("events", [])
        text = "\n".join(e.get("message", "") for e in events)
        out["raw_tail"] = text[-4000:]
        for e in events:
            m = SETTLE_RE.search(e.get("message", ""))
            if not m:
                continue
            ms = e.get("timestamp") or 0
            try:
                iso = datetime.datetime.fromtimestamp(
                    int(ms) / 1000.0,
                    datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                iso = None
            out["settle_lines"].append({
                "txId": m.group(1), "amount": int(m.group(2)),
                "status": m.group(3), "epoch_s": int(ms) // 1000,
                "timestamp_utc": iso,
            })
    except Exception as e:
        out["error"] = str(e)[:500]
    return out


def collect_responses():
    out = {"responses": []}
    if not os.path.isdir(C.OUT_DIR):
        return out
    for fn in sorted(os.listdir(C.OUT_DIR)):
        if fn.startswith("fire-") and fn.endswith(".json"):
            try:
                with open(os.path.join(C.OUT_DIR, fn), "r") as f:
                    out["responses"].append(
                        {"file": fn, "body": f.read()[:2000]})
            except Exception:
                continue
    return out


def iso_to_epoch(s):
    """'2026-11-06T06:42:02Z' -> epoch seconds (naive-UTC, 3.6-safe)."""
    if not s:
        return None
    try:
        dt = datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception:
        return None


def load_json_maybe(fname):
    p = os.path.join(C.OUT_DIR, fname)
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def parse_saved_responses():
    """Parse the saved out/fire-*.json bodies into admissions + denials.

    The BODY is authoritative (the agentcore CLI exits 0 even on denial):
      top-level "result" -> admitted; receipt txId from result.content
      top-level "error"  -> denied;  message from error.message
    """
    out = {"admitted": [], "denied": []}
    if not os.path.isdir(C.OUT_DIR):
        return out
    for fn in sorted(os.listdir(C.OUT_DIR)):
        if not (fn.startswith("fire-") and fn.endswith(".json")):
            continue
        try:
            with open(os.path.join(C.OUT_DIR, fn), "r", errors="replace") as f:
                d = json.loads(f.read())
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        if "error" in d:
            err = d["error"]
            out["denied"].append({
                "file": fn,
                "message": (str(err.get("message", err))[:400]
                            if isinstance(err, dict) else str(err)[:400]),
            })
            continue
        txid = None
        r = d.get("result")
        if isinstance(r, dict):
            for c in (r.get("content") or []):
                try:
                    inner = json.loads((c or {}).get("text", ""))
                except Exception:
                    inner = None
                if isinstance(inner, dict) and inner.get("txId"):
                    txid = inner["txId"]
                    break
        out["admitted"].append({"file": fn, "txId": txid})
    return out


def cross_check(settle_lines, responses, run_since_epoch):
    """Per-burst cross-check: admitted receipts (response bodies) vs SETTLE
    lines (AWS CloudWatch Logs), matched by txId.

    The log group outlives the lambda, so raw counts are meaningless; txId
    identity is the proof that "AWS admitted it" == "the tool executed".
    A burst is consistent when every admitted receipt has a SETTLE line and
    no SETTLE line (this run) is unaccounted for by any admitted receipt.
    """
    all_adm = set(a["txId"] for a in responses["admitted"] if a.get("txId"))
    this_run = [s for s in settle_lines
                if not run_since_epoch
                or s.get("epoch_s", 0) >= run_since_epoch]
    this_run_tx = set(s["txId"] for s in this_run)

    def burst(label, result_file, pred):
        files = [a["file"] for a in responses["admitted"] if pred(a["file"])]
        tx = set(a["txId"] for a in responses["admitted"]
                 if pred(a["file"]) and a.get("txId"))
        matched = tx & this_run_tx
        par = load_json_maybe(result_file) or {}
        amt = par.get("amount") or 0
        return {
            "burst": label,
            "result_file": result_file,
            "admitted_files": sorted(files),
            "denied_files": sorted(dd["file"] for dd in responses["denied"]
                                   if pred(dd["file"])),
            "admitted_txids": sorted(tx),
            "settled_txids": sorted(matched),
            "admitted_usd": amt * len(tx),
            "settled_usd": sum(s["amount"] for s in this_run
                               if s["txId"] in matched),
            "consistent": (matched == tx),
        }

    per_burst = [
        burst("sequential (E2 control, 31_fire_sequential)",
              "sequential5-results.json",
              lambda f: f.startswith("fire-seq-")),
        burst("parallel (the exploit, 30_fire_parallel)",
              "fire-results.json",
              lambda f: (not f.startswith("fire-seq-")
                         and f[5:].split(".", 1)[0].isdigit())),
    ]
    unassigned = sorted(this_run_tx - all_adm)
    return {
        "consistent": (all(b["consistent"] for b in per_burst)
                       and not unassigned),
        "note": ("txId-matched per burst. The log group outlives the lambda, "
                 "so SETTLE lines are scoped to this run (since setup) and "
                 "matched to the saved response bodies by txId identity -- "
                 "raw counts are NOT the evidence."),
        "settled_this_run": len(this_run),
        "settled_usd_this_run": sum(s["amount"] for s in this_run),
        "unassigned_settled_txids": unassigned,
        "per_burst": per_burst,
    }


def main():
    st = C.load_state()
    region = st.get("region", C.region())
    gw_arn = st.get("gatewayArn", "")
    fn = st.get("names", {}).get("lambda", C.names()["lambda"])

    print("=" * 68)
    print("40_capture_evidence -- AWS-side evidence for the run")
    print("=" * 68)

    fire_results = {}
    fr = os.path.join(C.OUT_DIR, "fire-results.json")
    if os.path.exists(fr):
        with open(fr, "r") as f:
            fire_results = json.load(f)

    print("\n-- cloudwatch metrics (last 60m)")
    cw = collect_cw_metrics(st)
    print("   %d decision/invoke metric(s) with datapoints"
          % len(cw.get("metrics", [])))
    for m in cw.get("metrics", [])[:10]:
        print("     %-30s %s" % (m["name"], m["datapoints"][:3]))
    if cw.get("error"):
        print("   (note: %s)" % cw["error"])

    print("\n-- lambda settle lines (CloudWatch Logs)")
    logs = collect_lambda_logs(region, fn)
    total_settled = sum(s["amount"] for s in logs.get("settle_lines", []))
    print("   %d SETTLE line(s), $%d settled"
          % (len(logs.get("settle_lines", [])), total_settled))
    for s in logs.get("settle_lines", [])[:10]:
        print("     %s  $%d  %s" % (s["txId"], s["amount"], s["status"]))
    if logs.get("error"):
        print("   (note: %s)" % logs["error"])

    print("\n-- gateway responses")
    resp = collect_responses()
    print("   %d saved response(s)" % len(resp.get("responses", [])))

    # --- cross-check (txId-matched, scoped to this run) ------------------
    run_since = iso_to_epoch(st.get("setup_done_utc"))
    bodies = parse_saved_responses()
    cc = cross_check(logs.get("settle_lines", []), bodies, run_since)
    print("\n-- cross-check (admitted receipts vs SETTLE lines, by txId)")
    for b in cc["per_burst"]:
        print("   %-46s admitted %-3d settled %-3d -> %s"
              % (b["burst"][:46], len(b["admitted_txids"]),
                 len(b["settled_txids"]),
                 "CONSISTENT" if b["consistent"] else "MISMATCH"))
        for df in b.get("denied_files", []):
            print("      denied: %s" % df)
    print("   settled this run: %d line(s), $%s"
          % (cc.get("settled_this_run"), cc.get("settled_usd_this_run")))
    if cc["unassigned_settled_txids"]:
        print("   UNASSIGNED settled txIds: %s"
              % ", ".join(cc["unassigned_settled_txids"]))
    print("   OVERALL: %s"
          % ("CONSISTENT" if cc["consistent"] else "MISMATCH"))

    evidence = {
        "captured_at_utc": C.now_iso(),
        "region": region,
        "gatewayArn": gw_arn,
        "fire_results": fire_results,
        "bodies_parsed": bodies,
        "cloudwatch": cw,
        "lambda_logs": logs,
        "responses": resp,
        "cross_check": cc,
    }
    C.write_json("evidence.json", evidence)
    C.write_text("evidence.md", render_md(evidence))
    print("\nwrote out/evidence.json + out/evidence.md")
    print("\nNext: python 50_rot_catch_fix_prove.py")


def render_md(ev):
    L = []
    L.append("# GAP-4 live evidence")
    L.append("")
    L.append("- captured: %s" % ev.get("captured_at_utc"))
    L.append("- region: %s" % ev.get("region"))
    L.append("- gateway: %s" % ev.get("gatewayArn"))
    fr = ev.get("fire_results") or {}
    seq = load_json_maybe("sequential5-results.json") or {}
    L.append("- parallel burst: %s x $%s, session %s"
             % (fr.get("nfires"), fr.get("amount"), fr.get("session_id")))
    L.append("- parallel: admitted %s, denied %s, committed $%s"
             % (fr.get("admitted_count"), fr.get("denied_count"),
                fr.get("committed_usd")))
    L.append("- sequential burst (E2): %s x $%s, session %s"
             % (seq.get("nfires"), seq.get("amount"), seq.get("session_id")))
    L.append("- sequential: admitted %s, denied %s, committed $%s"
             % (seq.get("admitted_count"), seq.get("denied_count"),
                seq.get("committed_usd")))
    if seq.get("verdict"):
        L.append("- sequential verdict: %s" % seq.get("verdict"))
    cc = ev.get("cross_check") or {}
    L.append("")
    L.append("## Cross-check (admitted receipts vs SETTLE lines, by txId)")
    for b in cc.get("per_burst", []):
        L.append("- %s: admitted $%s / settled $%s -> %s"
                 % (b["burst"], b.get("admitted_usd"), b.get("settled_usd"),
                    "CONSISTENT" if b.get("consistent") else "MISMATCH"))
        for t in b.get("admitted_txids", []):
            L.append("    admitted receipt  %s" % t)
        for df in b.get("denied_files", []):
            L.append("    denied (policy)   %s" % df)
    L.append("- settled this run: %s line(s), $%s"
             % (cc.get("settled_this_run"), cc.get("settled_usd_this_run")))
    if cc.get("unassigned_settled_txids"):
        L.append("- UNASSIGNED settled txIds: %s"
                 % ", ".join(cc["unassigned_settled_txids"]))
    L.append("- **overall: %s**"
             % ("CONSISTENT" if cc.get("consistent") else "MISMATCH"))
    L.append("")
    L.append("## Lambda settle lines (log-group history, oldest last-stream first)")
    for s in (ev.get("lambda_logs") or {}).get("settle_lines", []):
        L.append("- %s  %s  $%d  %s"
                 % (s.get("timestamp_utc") or "?", s["txId"],
                    s["amount"], s["status"]))
    L.append("")
    L.append("## CloudWatch metrics (last 60m)")
    for m in (ev.get("cloudwatch") or {}).get("metrics", []):
        dims = m.get("dimensions") or []
        dimstr = ", ".join("%s=%s" % (x["Name"], x["Value"]) for x in dims)
        L.append("- %s [%s]: %s" % (m["name"], dimstr, m["datapoints"]))
    L.append("")
    L.append("## Gateway responses (truncated)")
    for r in (ev.get("responses") or {}).get("responses", []):
        L.append("### %s\n\n```\n%s\n```\n" % (r["file"], r["body"]))
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()