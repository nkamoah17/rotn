# -*- coding: utf-8 -*-
"""tmp_reclassify.py -- reclassify the SAVED gateway response bodies and
rewrite the derived summaries.

The fire scripts' original classify() trusted the CLI exit code, but the
agentcore CLI exits 0 even when the gateway DENIES the tool call (the denial
is a JSON-RPC error object in the body).  The saved bodies (out/fire-*.json)
are immutable evidence; this script only re-derives the verdicts in:

  * out/fire-results.json          (parallel burst summary)
  * out/sequential5-results.json   (sequential burst summary + verdict)
  * out/events.jsonl               (E4 replay input: live_verdict per event)

Usage:  python tmp_reclassify.py
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPRO = os.path.join(HERE, "agentcore_repro")
OUT = os.path.join(REPRO, "out")


def body_verdict(path):
    """(verdict, txid, denial) from one saved response body."""
    try:
        with open(path, "r", errors="replace") as f:
            d = json.load(f)
    except Exception:
        return "UNKNOWN", None, None
    if not isinstance(d, dict):
        return "UNKNOWN", None, None
    if "error" in d:
        err = d["error"]
        msg = err.get("message") if isinstance(err, dict) else str(err)
        return "DENIED", None, (str(msg)[:400] if msg else None)
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
    return "ADMITTED", txid, None


def dump(p, d):
    with open(p, "w") as f:
        json.dump(d, f, indent=2, sort_keys=True)
        f.write("\n")


def rewrite_summary(fname, file_pred):
    p = os.path.join(OUT, fname)
    if not os.path.exists(p):
        return
    with open(p, "r") as f:
        d = json.load(f)
    changed = 0
    for r in d.get("results", []):
        base = os.path.basename(r.get("response_file", ""))
        if not file_pred(base):
            continue
        v, txid, denial = body_verdict(os.path.join(OUT, base))
        if (r.get("verdict") != v or r.get("receipt") != txid
                or r.get("denial") != denial):
            changed += 1
        r["verdict"] = v
        r["receipt"] = txid
        r["denial"] = denial
    results = d.get("results", [])
    adm = [r for r in results if r.get("verdict") == "ADMITTED"]
    den = [r for r in results if r.get("verdict") == "DENIED"]
    d["admitted_count"] = len(adm)
    d["denied_count"] = len(den)
    d["committed_usd"] = sum(r.get("amount", 0) for r in adm)
    dump(p, d)
    print("%s: %d verdict(s) reclassified; admitted=%s denied=%s "
          "committed=$%s" % (fname, changed, len(adm), len(den),
                             d["committed_usd"]))


def main():
    rewrite_summary(
        "fire-results.json",
        lambda b: re.match(r"fire-\d+\.json$", b) is not None)
    rewrite_summary("sequential5-results.json",
                    lambda b: b.startswith("fire-seq-"))

    # events.jsonl (E4 input): refresh live_verdict, keep the schema stable.
    p = os.path.join(OUT, "events.jsonl")
    if os.path.exists(p):
        with open(p, "r") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        for ev in lines:
            base = "fire-seq-%s.json" % ev.get("seq")
            v, _txid, _den = body_verdict(os.path.join(OUT, base))
            ev["live_verdict"] = v
        with open(p, "w") as f:
            for ev in lines:
                f.write(json.dumps(ev, sort_keys=True) + "\n")
        print("events.jsonl: live_verdict refreshed -> %s"
              % [e.get("live_verdict") for e in lines])

    # sequential5 verdict label (three-way, from 31_fire_sequential).
    sys.path.insert(0, REPRO)
    spec = importlib.util.spec_from_file_location(
        "fire31", os.path.join(REPRO, "31_fire_sequential.py"))
    m31 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m31)
    p = os.path.join(OUT, "sequential5-results.json")
    if os.path.exists(p):
        with open(p, "r") as f:
            d = json.load(f)
        label, detail = m31.three_way_verdict(
            d.get("committed_usd", 0), d.get("amount", 100),
            d.get("nfires", 5))
        d["verdict"] = label
        d["verdict_detail"] = detail
        dump(p, d)
        print("sequential5 verdict: %s" % label)


if __name__ == "__main__":
    main()
