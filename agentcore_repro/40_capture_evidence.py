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
    """Fetch recent log events from the Lambda log group; keep SETTLE lines."""
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
        for m in SETTLE_RE.finditer(text):
            out["settle_lines"].append({
                "txId": m.group(1), "amount": int(m.group(2)),
                "status": m.group(3),
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

    evidence = {
        "captured_at_utc": C.now_iso(),
        "region": region,
        "gatewayArn": gw_arn,
        "fire_results": fire_results,
        "cloudwatch": cw,
        "lambda_logs": logs,
        "responses": resp,
        "cross_check": {
            "settled_usd_per_logs": total_settled,
            "admitted_usd_per_responses": fire_results.get("committed_usd"),
            "consistent": (total_settled == fire_results.get("committed_usd")),
        },
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
    L.append("- fires: %s x $%s, session %s"
             % (fr.get("nfires"), fr.get("amount"), fr.get("session_id")))
    L.append("- admitted: %s, denied: %s, committed: $%s"
             % (fr.get("admitted_count"), fr.get("denied_count"),
                fr.get("committed_usd")))
    cc = ev.get("cross_check") or {}
    L.append("- lambda SETTLED total: $%s (consistent: %s)"
             % (cc.get("settled_usd_per_logs"), cc.get("consistent")))
    L.append("")
    L.append("## Lambda settle lines")
    for s in (ev.get("lambda_logs") or {}).get("settle_lines", []):
        L.append("- %s  $%d  %s" % (s["txId"], s["amount"], s["status"]))
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